// http.cpp - minimal HTTP/1.1 over TCP sockets: URL parse, chunked bodies,
// per-op timeouts, no redirects, no TLS (the portal protocol is plain http).
#include "http.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <fcntl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
static const sock_t kInvalidSock = INVALID_SOCKET;
static void sockClose(sock_t s) { closesocket(s); }
static std::string sockErrStr() {
    return "WSA error " + std::to_string(WSAGetLastError());
}
static bool waitSock(sock_t fd, bool readable, int ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv{ms / 1000, (ms % 1000) * 1000};
    int r = select((int)fd + 1, readable ? &fds : nullptr, readable ? nullptr : &fds,
                   nullptr, &tv);
    return r > 0;
}
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
static const sock_t kInvalidSock = -1;
static void sockClose(sock_t s) { ::close(s); }
static std::string sockErrStr() { return strerror(errno); }
static bool waitSock(sock_t fd, bool readable, int ms) {
    struct pollfd p{fd, readable ? (short)POLLIN : (short)POLLOUT, 0};
    int r = poll(&p, 1, ms);
    return r > 0 && (p.revents & (readable ? (POLLIN | POLLHUP | POLLERR)
                                           : (POLLOUT | POLLHUP | POLLERR)));
}
#endif

namespace ty {

namespace {

struct Url {
    std::string host;
    std::string port;
    std::string path;
};

Url parseUrl(const std::string& url) {
    Url u;
    std::string rest = url;
    if (rest.rfind("http://", 0) == 0) {
        rest = rest.substr(7);
    } else if (rest.rfind("https://", 0) == 0) {
        throw std::runtime_error("https is not supported by the portal client");
    }
    // authority ends at the first '/', '?' or '#'; the BAS redirect uses the
    // path-less form "http://202.102.13.97?wlanuserip=…"
    size_t slash = rest.find('/');
    size_t qmark = rest.find('?');
    size_t hash = rest.find('#');
    size_t end = rest.size();
    if (slash != std::string::npos && slash < end) end = slash;
    if (qmark != std::string::npos && qmark < end) end = qmark;
    if (hash != std::string::npos && hash < end) end = hash;
    std::string hostport = rest.substr(0, end);
    u.path = end < rest.size() ? rest.substr(end) : "/";
    if (u.path[0] != '/') u.path = "/" + u.path;
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(']') == std::string::npos) {
        u.host = hostport.substr(0, colon);
        u.port = hostport.substr(colon + 1);
    } else {
        u.host = hostport;
        u.port = "80";
    }
    return u;
}

struct Conn {
    sock_t fd = kInvalidSock;
    std::string rbuf;

    ~Conn() {
        if (fd != kInvalidSock) sockClose(fd);
    }

    bool waitReadable(int ms) { return waitSock(fd, true, ms); }

    // read more data into rbuf; returns false on EOF/error
    bool fill(int timeoutMs) {
        if (!waitReadable(timeoutMs)) return false;
        char tmp[16384];
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        rbuf.append(tmp, n);
        return true;
    }

    // read until header terminator
    bool readHead(int timeoutMs) {
        size_t pos;
        while ((pos = rbuf.find("\r\n\r\n")) == std::string::npos) {
            if (!fill(timeoutMs)) return false;
        }
        return true;
    }
};

}  // namespace

HttpResp httpOnce(const HttpRequest& req) {
#ifdef _WIN32
    static bool wsaInit = [] {
        WSADATA d;
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    if (!wsaInit) throw std::runtime_error("WSAStartup failed");
#endif
    Url u = parseUrl(req.url);

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(u.host.c_str(), u.port.c_str(), &hints, &res);
    if (rc != 0 || !res)
        throw std::runtime_error("DNS 解析失败: " + u.host + " (" + gai_strerror(rc) + ")");

    sock_t fd = kInvalidSock;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == kInvalidSock) continue;
#ifdef _WIN32
        u_long nonblock = 1, block = 0;
        ioctlsocket(fd, FIONBIO, &nonblock);
#else
        // connect timeout via non-blocking connect + poll
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
#ifdef _WIN32
            ioctlsocket(fd, FIONBIO, &block);
#else
            fcntl(fd, F_SETFL, flags);
#endif
            break;
        }
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            if (waitSock(fd, false, req.connectTimeoutMs)) {
                int soerr = 0;
                socklen_t len = sizeof(soerr);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len);
                if (soerr == 0) {
                    ioctlsocket(fd, FIONBIO, &block);
                    break;
                }
            }
        }
#else
        if (errno == EINPROGRESS) {
            if (waitSock(fd, false, req.connectTimeoutMs)) {
                int soerr = 0;
                socklen_t len = sizeof(soerr);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len);
                if (soerr == 0) {
                    fcntl(fd, F_SETFL, flags);
                    break;
                }
            }
        }
#endif
        sockClose(fd);
        fd = kInvalidSock;
    }
    freeaddrinfo(res);
    if (fd == kInvalidSock)
        throw std::runtime_error("连接失败: " + u.host + ":" + u.port + " (" +
                                 sockErrStr() + ")");

    Conn c;
    c.fd = fd;

    // ---- build request ----
    std::string head = req.method + " " + u.path + " HTTP/1.1\r\n";
    bool hasHost = false, hasUA = false, hasConn = false, hasAccept = false;
    for (auto& h : req.headers) {
        std::string n = h.first;
        for (auto& ch : n)
            if (ch >= 'A' && ch <= 'Z') ch += 32;
        if (n == "host") hasHost = true;
        if (n == "user-agent") hasUA = true;
        if (n == "connection") hasConn = true;
        if (n == "accept") hasAccept = true;
        head += h.first + ": " + h.second + "\r\n";
    }
    if (!hasHost) head += "Host: " + u.host + (u.port == "80" ? "" : ":" + u.port) + "\r\n";
    if (!hasUA) head += "User-Agent: tylogin-native\r\n";
    if (!hasAccept) head += "Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*\r\n";
    if (!hasConn) head += "Connection: close\r\n";
    if (!req.body.empty() || req.method == "POST")
        head += "Content-Length: " + std::to_string(req.body.size()) + "\r\n";
    head += "\r\n";

    std::string out = head;
    out.append((const char*)req.body.data(), req.body.size());
    size_t sent = 0;
    while (sent < out.size()) {
        if (!waitSock(fd, false, req.readTimeoutMs)) {
            throw std::runtime_error("发送超时: " + u.host);
        }
#ifdef _WIN32
        ssize_t n = (ssize_t)send(fd, out.data() + sent, (int)(out.size() - sent), 0);
#else
        ssize_t n = send(fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
#endif
        if (n <= 0) throw std::runtime_error("发送失败: " + sockErrStr());
        sent += n;
    }

    // ---- read response head ----
    if (!c.readHead(req.readTimeoutMs))
        throw std::runtime_error("响应头读取超时: " + u.host);

    size_t headEnd = c.rbuf.find("\r\n\r\n");
    std::string headBlock = c.rbuf.substr(0, headEnd);
    size_t bodyStart = headEnd + 4;

    HttpResp resp;
    size_t lineEnd = headBlock.find("\r\n");
    std::string statusLine = headBlock.substr(0, lineEnd == std::string::npos ? headBlock.size() : lineEnd);
    if (statusLine.rfind("HTTP/1.", 0) != 0)
        throw std::runtime_error("无效的 HTTP 响应: " + statusLine.substr(0, 32));
    resp.code = atoi(statusLine.c_str() + 9);

    size_t pos = lineEnd == std::string::npos ? headBlock.size() : lineEnd + 2;
    while (pos < headBlock.size()) {
        size_t e = headBlock.find("\r\n", pos);
        if (e == std::string::npos) e = headBlock.size();
        std::string line = headBlock.substr(pos, e - pos);
        pos = e + 2;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        size_t vs = colon + 1;
        while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) vs++;
        resp.headers.emplace_back(name, line.substr(vs));
    }

    std::string body = c.rbuf.substr(bodyStart);

    // ---- read body: chunked / content-length / to-close ----
    std::string teLower;
    std::string clLower;
    for (auto& h : resp.headers) {
        std::string n = h.first;
        for (auto& ch : n)
            if (ch >= 'A' && ch <= 'Z') ch += 32;
        if (n == "transfer-encoding") teLower = h.second;
        if (n == "content-length") clLower = h.second;
    }
    if (teLower.find("chunked") != std::string::npos) {
        // parse chunks from body, refilling as needed
        std::string out_;
        size_t p = 0;
        for (;;) {
            size_t e;
            while ((e = body.find("\r\n", p)) == std::string::npos) {
                size_t before = body.size();
                if (!c.fill(req.readTimeoutMs))
                    throw std::runtime_error("chunked body 读取超时");
                body = c.rbuf.substr(bodyStart);
                if (body.size() == before) throw std::runtime_error("chunked body 中断");
            }
            std::string szs = body.substr(p, e - p);
            size_t semi = szs.find(';');
            if (semi != std::string::npos) szs = szs.substr(0, semi);
            unsigned long long sz = strtoull(szs.c_str(), nullptr, 16);
            p = e + 2;
            if (sz == 0) break;
            while (body.size() < p + sz + 2) {
                if (!c.fill(req.readTimeoutMs)) throw std::runtime_error("chunked body 中断");
                body = c.rbuf.substr(bodyStart);
            }
            out_.append(body, p, sz);
            p += sz + 2;
        }
        resp.body.assign(out_.begin(), out_.end());
    } else if (!clLower.empty()) {
        size_t want = (size_t)strtoull(clLower.c_str(), nullptr, 10);
        if (want > 64ull * 1024 * 1024) throw std::runtime_error("响应体过大");
        while (body.size() < want) {
            if (!c.fill(req.readTimeoutMs)) break;
            body = c.rbuf.substr(bodyStart);
        }
        size_t n = body.size() < want ? body.size() : want;
        resp.body.assign(body.begin(), body.begin() + n);
    } else {
        while (c.fill(req.readTimeoutMs)) body = c.rbuf.substr(bodyStart);
        resp.body.assign(body.begin(), body.end());
    }
    return resp;
}

}  // namespace ty
