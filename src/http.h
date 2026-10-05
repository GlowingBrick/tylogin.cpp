// http.h - minimal HTTP/1.1 client (plain http, Connection: close semantics)
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ty {

struct HttpResp {
    int code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;

    std::string header(const std::string& name) const {
        for (auto& h : headers)
            if (strcasecmp_(h.first, name)) return h.second;
        return "";
    }
    std::string text() const { return std::string(body.begin(), body.end()); }

private:
    static bool strcasecmp_(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++) {
            char x = a[i], y = b[i];
            if (x >= 'A' && x <= 'Z') x += 32;
            if (y >= 'A' && y <= 'Z') y += 32;
            if (x != y) return false;
        }
        return true;
    }
};

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::vector<uint8_t> body;
    std::vector<std::pair<std::string, std::string>> headers;
    int connectTimeoutMs = 8000;
    int readTimeoutMs = 8000;
};

// throws std::runtime_error on network failure; does NOT follow redirects
HttpResp httpOnce(const HttpRequest& req);

}  // namespace ty
