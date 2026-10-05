// dialer.cpp - portal probing / authentication / heartbeat / term state machine.
// Byte-exact port of tylogin/JSDialer.kt (XML templates, header order, parsing).
#include "dialer.h"

#include "http.h"
#include "md5.h"
#include "util.h"
#include "zsm/damod.h"

#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define TY_MKDIR(p) _mkdir(p)
#define TY_SLEEP_1S() Sleep(1000)
#else
#include <unistd.h>
#define TY_MKDIR(p) mkdir((p), 0755)
#define TY_SLEEP_1S() sleep(1)
#endif

#include <atomic>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace ty {

volatile sig_atomic_t gStop = 0;

static const char* kUA = "CCTP/android64/3001";
static const char* kZeroAlgo = "00000000-0000-0000-0000-000000000000";
// reliability tuning for -l mode (port of JSDialer constants)
static constexpr int KEEP_MAX_ATTEMPTS = 3;
static constexpr long KEEP_RETRY_DELAY_MS = 3000;
static constexpr long PROBE_SLICE_SEC = 5;
static constexpr long PROBE_EVERY_SEC = 15;
static constexpr int PROBE_TIMEOUT_MS = 5000;
static const char* kNet204Url = "http://connectivitycheck.gstatic.com/generate_204";
// TY_PORTAL_BASE overrides detect/check URLs (mock-portal testing only)
static std::string detectUrl() {
    const char* base = getenv("TY_PORTAL_BASE");
    return base ? std::string(base) + "/detect.html" : "http://202.111.54.132/detect.html";
}
static std::string checkUrl() {
    const char* base = getenv("TY_PORTAL_BASE");
    return base ? std::string(base) + "/check" : "http://check.go189.cn";
}

static std::unique_ptr<ZsmRuntime> g_zsm;

std::string errCodeText(const std::string& code) {
    if (code == "100") return "账号或密码错误";
    if (code == "101") return "challenge 无效";
    if (code == "102") return "认证被拒绝";
    if (code == "103") return "在线终端数超限（请先在其他设备下线）";
    if (code == "104") return "未知用户";
    if (code == "10") return "IP 无效";
    if (code == "11") return "MAC 无效";
    if (code == "12") return "Client-ID 无效";
    if (code == "13") return "Algo-ID 无效";
    if (code == "14") return "ticket 无效";
    if (code == "15") return "校验和错误";
    if (code == "200") return "算法模块过期";
    if (code == "300" || code == "301") return "需要二次认证";
    return "服务器错误 " + code;
}

// ---------------- small helpers ----------------

static std::string regexFind1(const std::string& text, const std::string& open,
                              const std::string& close) {
    size_t p = text.find(open);
    if (p == std::string::npos) return "";
    p += open.size();
    size_t e = text.find(close, p);
    if (e == std::string::npos) return "";
    return text.substr(p, e - p);
}

// <tag>\s*<![CDATA[value]]>\s*</tag> with fallback to <tag>value</tag>
static std::string cdataTag(const std::string& html, const std::string& tag) {
    std::string open = "<" + tag + ">";
    std::string closeTag = "</" + tag + ">";
    size_t p = html.find(open);
    if (p == std::string::npos) return "";
    p += open.size();
    while (p < html.size() && isspace((unsigned char)html[p])) p++;
    if (html.compare(p, 9, "<![CDATA[") == 0) {
        p += 9;
        size_t e = html.find("]]>", p);
        if (e == std::string::npos) return "";
        size_t after = e + 3;
        while (after < html.size() && isspace((unsigned char)html[after])) after++;
        if (html.compare(after, closeTag.size(), closeTag) == 0)
            return html.substr(p, e - p);
        return "";
    }
    size_t e = html.find(closeTag, p);
    if (e == std::string::npos || e == p) return "";
    std::string v = html.substr(p, e - p);
    if (v.find('<') != std::string::npos) return "";
    return v;
}

static std::string queryParam(const std::string& query, const std::string& name) {
    std::string needle = name + "=";
    size_t p = query.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    size_t e = query.find('&', p);
    if (e == std::string::npos) e = query.size();
    return query.substr(p, e - p);
}

static void mkdirs(const std::string& path) {
    std::string cur;
    for (size_t i = 0; i <= path.size(); i++) {
        if (i == path.size() || path[i] == '/') {
            cur = path.substr(0, i);
            if (!cur.empty()) TY_MKDIR(cur.c_str());
        }
    }
}

// sleep in 1s steps so signals interrupt promptly
static void sleepInterruptible(long seconds) {
    for (long i = 0; i < seconds && !gStop; i++) TY_SLEEP_1S();
}

// ---------------- construction ----------------

Dialer::Dialer(const DialerOptions& opt) : opt_(opt) {
    clientId_ = uuid4();
    algoId_ = kZeroAlgo;
    if (!g_zsm) {
        const char* envHome = getenv("TYLOGIN_HOME");
        std::string home = envHome ? envHome
                                   : std::string(getenv("HOME") ? getenv("HOME") : ".") +
                                         "/.tylogin";
        mkdirs(home);
        g_zsm.reset(new ZsmRuntime("com.cndatacom.campus.cdccportaljs", home));
    }
}

HttpResp Dialer::post(const std::string& url, const std::string& body) {
    HttpRequest req;
    req.method = "POST";
    req.url = url;
    req.body.assign(body.begin(), body.end());
    req.headers = {
        {"User-Agent", kUA},
        {"Accept",
         "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"},
        {"Content-Type", "text/plain; charset=utf-8"},
        {"Algo-ID", algoId_},
        {"Client-ID", clientId_},
        {"CDC-Checksum", md5hex(body)},
        {"Connection", "close"},
    };
    return httpOnce(req);
}

// ---------------- protocol ----------------

Dialer::PortalState Dialer::discoverPortal() {
    portalError_.clear();
    HttpResp det;
    try {
        HttpRequest r;
        r.url = detectUrl();
        r.headers = {{"User-Agent", kUA}};
        det = httpOnce(r);
    } catch (const std::exception& e) {
        dlog(std::string("detect error: ") + e.what());
        portalError_ = std::string("detect: ") + e.what();
        return UNREACHABLE;
    }
    dlog("detect: HTTP " + std::to_string(det.code));
    if (det.code != 200) {
        portalError_ = "detect: HTTP " + std::to_string(det.code);
        return UNREACHABLE;
    }

    HttpResp chk;
    try {
        HttpRequest r;
        r.url = checkUrl();
        r.headers = {{"User-Agent", kUA}};
        chk = httpOnce(r);
    } catch (const std::exception& e) {
        dlog(std::string("check error: ") + e.what());
        portalError_ = std::string("check: ") + e.what();
        return UNREACHABLE;
    }
    dlog("check: HTTP " + std::to_string(chk.code) + " -> " + chk.header("Location"));
    std::string basUrl = chk.header("Location");
    if (basUrl.empty()) return ONLINE;
    while (!basUrl.empty() && (basUrl.back() == ' ' || basUrl.back() == '\r')) basUrl.pop_back();

    HttpResp bas;
    try {
        HttpRequest r;
        r.url = basUrl;
        r.headers = {{"User-Agent", kUA}};
        bas = httpOnce(r);
    } catch (const std::exception& e) {
        dlog(std::string("bas error: ") + e.what());
        portalError_ = "bas(" + basUrl.substr(0, 60) + "): " + e.what();
        return UNREACHABLE;
    }
    std::string idxUrl = bas.header("Location");
    dlog("bas: HTTP " + std::to_string(bas.code) + " -> " + idxUrl.substr(0, 120));
    if (idxUrl.empty()) {
        portalError_ = "bas: no redirect (HTTP " + std::to_string(bas.code) + ")";
        return UNREACHABLE;
    }

    // identity from the index.cgi query string
    size_t q = idxUrl.find('?');
    std::string query = q == std::string::npos ? "" : idxUrl.substr(q + 1);
    wlanUserIp_ = queryParam(query, "wlanuserip");
    mscgIp_ = queryParam(query, "mscgip");
    wlanUserMac_ = queryParam(query, "wlanusermac");
    userLocation_ = queryParam(query, "userlocation");
    dlog("identity: ip=" + wlanUserIp_ + " mac=" + wlanUserMac_ + " mscg=" + mscgIp_ +
         " loc=" + userLocation_);

    HttpResp idx;
    try {
        HttpRequest r;
        r.url = idxUrl;
        r.headers = {{"User-Agent", kUA}};
        idx = httpOnce(r);
    } catch (const std::exception& e) {
        dlog(std::string("index error: ") + e.what());
        portalError_ = std::string("index: ") + e.what();
        return UNREACHABLE;
    }
    std::string html = idx.text();
    dlog("index.cgi: HTTP " + std::to_string(idx.code) + " " +
         std::to_string(html.size()) + " bytes");
    ticketUrl_ = cdataTag(html, "ticket-url");
    authUrl_ = cdataTag(html, "auth-url");
    hasDelDomain_ = false;
    delDomainVal_.clear();
    {
        std::string marker = "<type>del-domain</type>";
        size_t p = html.find(marker);
        if (p != std::string::npos) {
            size_t v = html.find("<value>", p + marker.size());
            if (v != std::string::npos) {
                v += 7;
                size_t e = html.find("</value>", v);
                if (e != std::string::npos) {
                    delDomainVal_ = html.substr(v, e - v);
                    hasDelDomain_ = true;
                }
            }
        }
    }
    dlog("ticketUrl=" + ticketUrl_);
    dlog("authUrl=" + authUrl_);
    return (!ticketUrl_.empty() && !authUrl_.empty()) ? PORTAL : UNREACHABLE;
}

bool Dialer::initCrypto() {
    HttpResp r_ = post(ticketUrl_, kZeroAlgo);
    std::string errCode = r_.header("Error-Code");
    dlog("zsm-download: HTTP " + std::to_string(r_.code) + " Error-Code=" + errCode +
         " body=" + std::to_string(r_.body.size()) + "B");
    if (errCode != "200" || r_.body.empty()) {
        dlog("unexpected ZSM download response");
        return false;
    }
    int64_t h = g_zsm->load(r_.body);
    if (h == 0) {
        dlog("ZSM module load failed");
        return false;
    }
    session_ = (void*)h;
    algoId_ = g_zsm->algoId(h);
    dlog("algoId=" + algoId_);
    return true;
}

bool Dialer::ticketRequest() {
    std::string xml =
        std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?><request><user-agent>") +
        kUA + "</user-agent><client-id>" + clientId_ + "</client-id><local-time>" +
        nowTime() + "</local-time><host-name>linux</host-name><ipv4>" + wlanUserIp_ +
        "</ipv4><ipv6></ipv6><mac>" + wlanUserMac_ +
        "</mac><ostag>linux</ostag><gwip></gwip></request>";
    HttpResp r_ = post(ticketUrl_, g_zsm->encrypt((int64_t)session_, xml));
    std::string errCode = r_.header("Error-Code");
    if (errCode != "0") {
        dlog("ticket failed: Error-Code=" + errCode + " " + r_.text().substr(0, 200));
        return false;
    }
    std::string plain = g_zsm->decrypt((int64_t)session_, r_.text());
    dlog("ticket resp: " + plain);
    ticket_ = regexFind1(plain, "<ticket>", "</ticket>");
    dlog("ticket=" + ticket_);
    return !ticket_.empty();
}

const char* Dialer::auth(const std::string& user, const std::string& pass) {
    std::string userid = user;
    if (hasDelDomain_) {
        if (delDomainVal_.empty() || user.find(delDomainVal_) != std::string::npos) {
            size_t at = user.find('@');
            if (at != std::string::npos) userid = user.substr(0, at);
        }
    }
    std::string xml =
        std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?><request><user-agent>") +
        kUA + "</user-agent><client-id>" + clientId_ + "</client-id><local-time>" +
        nowTime() + "</local-time><ticket>" + ticket_ + "</ticket><userid>" + userid +
        "</userid><passwd>" + pass + "</passwd></request>";
    HttpResp r_ = post(authUrl_, g_zsm->encrypt((int64_t)session_, xml));
    std::string errCode = r_.header("Error-Code");
    if (errCode != "0") {
        dlog("auth failed: Error-Code=" + errCode + " sub=" + r_.header("Sub-Error"));
        std::string msg = errCodeText(errCode) + " (" + errCode + ")";
        return strdup(msg.c_str());  // process-lifetime leak, matches one-shot usage
    }
    std::string plain = g_zsm->decrypt((int64_t)session_, r_.text());
    dlog("auth resp: " + plain);
    keepUrl_ = cdataTag(plain, "keep-url");
    termUrl_ = cdataTag(plain, "term-url");
    {
        std::string kr = regexFind1(plain, "<keep-retry>", "</keep-retry>");
        keepInterval_ =
            (!kr.empty() && kr.find_first_not_of("0123456789") == std::string::npos)
                ? atol(kr.c_str())
                : 60;
    }
    dlog("keepUrl=" + keepUrl_ + " interval=" + std::to_string(keepInterval_));
    if (keepUrl_.empty()) return "认证响应异常（缺少 keep-url）";
    return nullptr;
}

// ---------------- keep-alive ----------------

Dialer::KeepOutcome Dialer::keepOnce() {
    if (!session_ || keepUrl_.empty())
        return {KeepOutcome::NET_FAIL, "", "", "无心跳会话"};
    try {
        std::string xml =
            std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?><request><user-agent>") +
            kUA + "</user-agent><client-id>" + clientId_ + "</client-id><local-time>" +
            nowTime() + "</local-time><host-name>linux</host-name><ipv4>" + wlanUserIp_ +
            "</ipv4><ticket>" + ticket_ + "</ticket><ipv6></ipv6><mac>" + wlanUserMac_ +
            "</mac><ostag>linux</ostag></request>";
        HttpResp r_ = post(keepUrl_, g_zsm->encrypt((int64_t)session_, xml));
        std::string errCode = r_.header("Error-Code");
        if (errCode != "0") {
            dlog("keep failed: Error-Code=" + errCode + " sub=" + r_.header("Sub-Error"));
            return {KeepOutcome::PROTO_FAIL, errCode, r_.header("Sub-Error"), ""};
        }
        std::string plain = g_zsm->decrypt((int64_t)session_, r_.text());
        std::string iv = regexFind1(plain, "<interval>", "</interval>");
        if (!iv.empty() && iv.find_first_not_of("0123456789") == std::string::npos)
            keepInterval_ = atol(iv.c_str());
        dlog("keep ok, next in " + std::to_string(keepInterval_) + "s");
        return {KeepOutcome::OK, "", "", ""};
    } catch (const EmuExit& e) {
        dlog("keep error: guest exit(" + std::to_string(e.code) + ")");
        return {KeepOutcome::NET_FAIL, "", "", "guest exit(" + std::to_string(e.code) + ")"};
    } catch (const std::exception& e) {
        dlog(std::string("keep error: ") + e.what());
        return {KeepOutcome::NET_FAIL, "", "", e.what()};
    }
}

// transient network glitches get immediate retries; protocol rejections return immediately
Dialer::KeepOutcome Dialer::keepWithRetry() {
    KeepOutcome last{KeepOutcome::NET_FAIL, "", "", "unreachable"};
    for (int attempt = 0; attempt < KEEP_MAX_ATTEMPTS && !gStop; attempt++) {
        KeepOutcome k = keepOnce();
        if (k.kind != KeepOutcome::NET_FAIL) return k;
        last = k;
        if (attempt + 1 < KEEP_MAX_ATTEMPTS) {
            dlog("keep attempt " + std::to_string(attempt + 1) + "/" +
                 std::to_string(KEEP_MAX_ATTEMPTS) + " net fail, retry in " +
                 std::to_string(KEEP_RETRY_DELAY_MS) + "ms");
            sleepInterruptible(KEEP_RETRY_DELAY_MS / 1000);
        }
    }
    return last;
}

bool Dialer::hasKeepSession() const {
    return session_ != nullptr && !keepUrl_.empty() && !ticket_.empty();
}

// Lightweight liveness probe between heartbeats (no crypto, 5s timeout):
//  - CHECK_URL 302 with Location => BAS says unauthenticated (kicked/offline) => false
//  - CHECK exception/timeout => link down => false
//  - CHECK 200 (ONLINE) => true; internet 204 is best-effort only (logged, never aborts)
bool Dialer::quickPortalProbe() {
    try {
        HttpRequest r;
        r.url = checkUrl();
        r.headers = {{"User-Agent", kUA}};
        r.connectTimeoutMs = PROBE_TIMEOUT_MS;
        r.readTimeoutMs = PROBE_TIMEOUT_MS;
        HttpResp chk = httpOnce(r);
        std::string loc = chk.header("Location");
        if (!loc.empty()) {
            dlog("probe: portal redirect reappeared -> " + loc.substr(0, 120));
            return false;
        }
        try {
            HttpRequest n;
            n.url = kNet204Url;
            n.headers = {{"User-Agent", kUA}};
            n.connectTimeoutMs = PROBE_TIMEOUT_MS;
            n.readTimeoutMs = PROBE_TIMEOUT_MS;
            HttpResp net = httpOnce(n);
            if (net.code != 204 && net.code != 200)
                dlog("204 probe: HTTP " + std::to_string(net.code) +
                     " (portal ONLINE, keep going)");
        } catch (const std::exception& e) {
            dlog(std::string("204 probe failed: ") + e.what() + " (portal ONLINE, keep going)");
        }
        return true;
    } catch (const std::exception& e) {
        dlog(std::string("probe failed: ") + e.what());
        return false;
    }
}

// sleep keepInterval in 5s slices; return false when probe suggests an early heartbeat/relogin
bool Dialer::sleepWithProbe(long totalSec) {
    long elapsed = 0;
    while (elapsed < totalSec && !gStop) {
        long step =
            PROBE_SLICE_SEC < totalSec - elapsed ? PROBE_SLICE_SEC : totalSec - elapsed;
        sleepInterruptible(step);
        if (gStop) return true;  // shutting down: the caller's loop condition handles exit
        elapsed += step;
        if (elapsed < totalSec && elapsed % PROBE_EVERY_SEC == 0) {
            if (!quickPortalProbe()) return false;
        }
    }
    return true;
}

void Dialer::term(const std::string& reason) {
    if (termUrl_.empty() || !session_ || !g_zsm) return;
    try {
        std::string xml =
            std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?><request><user-agent>") +
            kUA + "</user-agent><client-id>" + clientId_ + "</client-id><local-time>" +
            nowTime() + "</local-time><ticket>" + ticket_ + "</ticket><reason>" + reason +
            "</reason></request>";
        post(termUrl_, g_zsm->encrypt((int64_t)session_, xml));
        dlog("term sent (reason=" + reason + ")");
    } catch (const std::exception& e) {
        dlog(std::string("term error: ") + e.what());
    }
}

void Dialer::resetSession() {
    if (session_ && g_zsm) {
        try {
            g_zsm->freeSession((int64_t)session_);
        } catch (...) {
        }
    }
    session_ = nullptr;
    algoId_ = kZeroAlgo;
}

// ---------------- flows ----------------

int Dialer::loginOnce() {
    try {
        switch (discoverPortal()) {
            case ONLINE:
                info("已在线，无需登录");
                return 0;
            case UNREACHABLE:
                err(portalError_.empty() ? "无法连接校园网认证服务器（请确认已连接 @f-Young）"
                        : "无法连接校园网认证服务器：" + portalError_);
                return 2;
            case PORTAL:
                break;
        }
        dlog("portal found, negotiating…");
        if (!initCrypto() || !ticketRequest()) {
            err("算法模块协商失败");
            return 2;
        }
        const char* reason = auth(opt_.user, opt_.pass);
        if (!reason) {
            info("登录成功（心跳间隔 " + std::to_string(keepInterval_) + "s）");
            return 0;
        }
        err("登录失败：" + std::string(reason));
        return 1;
    } catch (const EmuExit& e) {
        dlog("guest exit(" + std::to_string(e.code) + ")");
        err("网络异常：加密引擎退出");
        resetSession();
        return 2;
    } catch (const EmuError& e) {
        dlog(std::string("loginOnce emu error: ") + e.what());
        err("网络异常：加密引擎故障");
        resetSession();
        return 2;
    } catch (const std::exception& e) {
        dlog(std::string("loginOnce error: ") + e.what());
        err(std::string("网络异常：") + e.what());
        resetSession();
        return 2;
    }
}

int Dialer::dumpZsm(const std::string& path) {
    try {
        switch (discoverPortal()) {
            case ONLINE:
                err("当前已在线（未认证状态下才能下发算法模块）");
                return 0;
            case UNREACHABLE:
                err(portalError_.empty() ? "无法连接校园网认证服务器（请确认已连接 @f-Young）"
                        : "无法连接校园网认证服务器：" + portalError_);
                return 2;
            case PORTAL:
                break;
        }
        HttpResp r_ = post(ticketUrl_, kZeroAlgo);
        std::string errCode = r_.header("Error-Code");
        dlog("zsm-download: HTTP " + std::to_string(r_.code) + " Error-Code=" + errCode +
             " body=" + std::to_string(r_.body.size()) + "B");
        if (errCode != "200" || r_.body.empty()) {
            err("算法模块下发失败 (Error-Code=" + errCode + ")");
            return 2;
        }
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) {
            err("无法写入 " + path);
            return 2;
        }
        fwrite(r_.body.data(), 1, r_.body.size(), f);
        fclose(f);
        info("ZSM 模块已保存到 " + path + "（" + std::to_string(r_.body.size()) + " 字节）");
        return 0;
    } catch (const std::exception& e) {
        err(std::string("网络异常：") + e.what());
        return 2;
    }
}

int Dialer::runLoop() {
    info("进入保活模式，每 " + std::to_string(keepInterval_) + "s 心跳一次+探活（Ctrl+C 退出并下线）");
    while (!gStop) {
        if (hasKeepSession()) {
            KeepOutcome outcome;
            try {
                outcome = keepWithRetry();
            } catch (const std::exception& e) {
                outcome = {KeepOutcome::NET_FAIL, "", "", e.what()};
            }
            if (gStop) break;  // Ctrl+C: the final term() below logs out with the intact session
            switch (outcome.kind) {
                case KeepOutcome::OK: {
                    bool sleptFull = sleepWithProbe(keepInterval_);
                    if (!sleptFull) info("探活异常，提前心跳…");
                    continue;
                }
                case KeepOutcome::PROTO_FAIL:
                    info("心跳失败（" + errCodeText(outcome.code) + " " + outcome.code +
                         "），正在重新认证…");
                    break;
                case KeepOutcome::NET_FAIL:
                    info("心跳失败（网络异常：" + outcome.errMsg + "），正在重新认证…");
                    break;
            }
            try {
                term();
            } catch (...) {
            }
            resetSession();
        }
        while (!gStop) {
            try {
                int rc = loginOnce();
                if (rc == 0) {
                    if (hasKeepSession()) break;
                    // ONLINE idle: portal says online but we hold no keep-url/ticket;
                    // wait before re-polling instead of hammering keep() without a session
                    dlog("online idle (no keep session), re-poll in 15s");
                    sleepInterruptible(15);
                    continue;
                }
                if (rc == 2) {
                    dlog("network down, retry in 10s");
                } else {
                    info("重新认证失败，10s 后重试");
                }
            } catch (const std::exception& e) {
                dlog(std::string("relogin error: ") + e.what());
            }
            sleepInterruptible(10);
        }
    }
    try {
        term();  // exit like the official client: Ctrl+C logs out
    } catch (...) {
    }
    return 0;
}

}  // namespace ty
