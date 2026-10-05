// util.cpp - logging, time, uuid, config parsing
#include "util.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <fstream>
#include <random>

namespace ty {

extern bool gDebug;  // emu.cpp (zsm subsystem verbose logging)
static bool g_debug = false;

void setDebug(bool on) {
    g_debug = on;
    gDebug = on;
}
bool isDebug() { return g_debug; }

static std::string clockStr() {
    time_t t = time(nullptr);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char b[16];
    strftime(b, sizeof(b), "%H:%M:%S", &tmv);
    return b;
}

void dlog(const std::string& s) {
    if (g_debug) fprintf(stderr, "[%s] %s\n", clockStr().c_str(), s.c_str());
}

void info(const std::string& s) { printf("%s\n", s.c_str()); }

void err(const std::string& s) { fprintf(stderr, "错误: %s\n", s.c_str()); }

std::string nowTime() {
    time_t t = time(nullptr);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char b[32];
    strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tmv);
    return b;
}

std::string uuid4() {
    std::random_device rd;
    uint8_t b[16];
    for (int i = 0; i < 16; i += 4) {
        uint32_t v = rd();
        memcpy(b + i, &v, 4);
    }
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    char out[40];
    snprintf(out, sizeof(out),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0],
             b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
             b[13], b[14], b[15]);
    return out;
}

bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

std::string toLower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}

std::string trim(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool readConfig(const std::string& dir, std::string& user, std::string& pass) {
    static const char* names[] = {"config", "config.txt", "tylogin.conf"};
    std::string used;
    for (const char* n : names) {
        std::string p = dir + "/" + n;
        std::ifstream f(p);
        if (!f) continue;
        std::string line;
        while (std::getline(f, line)) {
            std::string l = trim(line);
            if (l.empty() || l[0] == '#' || l[0] == ';') continue;
            size_t eq = l.find('=');
            if (eq == std::string::npos || eq == 0) continue;
            std::string k = toLower(trim(l.substr(0, eq)));
            std::string v = trim(l.substr(eq + 1));
            if ((k == "account" || k == "user" || k == "username") && user.empty()) user = v;
            if ((k == "password" || k == "pass" || k == "pwd") && pass.empty()) pass = v;
        }
        used = n;
        break;
    }
    if (!used.empty()) dlog("config loaded from " + used);
    return !user.empty() || !pass.empty();
}

}  // namespace ty
