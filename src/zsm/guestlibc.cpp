// guestlibc.cpp - native implementations of libdaproxy.so's bionic imports,
// plus the arm64 SVC syscall layer.
//
// bionic aarch64 va_list:
//   struct { void* __stack; void* __gr_top; void* __vr_top; int __gr_offs; int __vr_offs; }
#define _CRT_RAND_S
#include "emu.h"
#include "util.h"

#include <cstdarg>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <ctime>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <sys/random.h>
#endif
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>    // _mkdir
#include <sys/time.h>  // gettimeofday
#endif
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#ifndef _WIN32
#include <sys/uio.h>
#endif
#include <unistd.h>

namespace ty {

// ------------------------------------------------------------ va_list

struct GuestVa {
    uint64_t stack, grTop, vrTop;
    int32_t grOffs, vrOffs;
};

class VaReader {
public:
    explicit VaReader(Emu& emu, uint64_t vaAddr) : emu_(emu) {
        emu_.readMem(vaAddr, &va_, sizeof(va_));
    }
    // varargs passed directly in registers (x1..x7)
    VaReader(Emu& emu, const uint64_t* x, int first) : emu_(emu), reg_(x), regIdx_(first) {}

    uint64_t nextInt() {
        if (reg_) return regIdx_ < 8 ? reg_[regIdx_++] : 0;
        if (va_.grOffs < 0) {
            uint64_t v = 0;
            emu_.readMem((uint64_t)(va_.grTop + va_.grOffs), &v, 8);
            va_.grOffs += 8;
            return v;
        }
        uint64_t v = 0;
        emu_.readMem(va_.stack, &v, 8);
        va_.stack += 8;
        return v;
    }
    const char* nextPtr() { return reinterpret_cast<const char*>(nextInt()); }

private:
    Emu& emu_;
    GuestVa va_{};
    const uint64_t* reg_ = nullptr;
    int regIdx_ = 0;
};

// ------------------------------------------------------------ mini printf

namespace {

struct Sink {
    std::string buf;
    void put(const char* s, size_t n) { buf.append(s, n); }
};

// reads one integer arg
uint64_t readInt(VaReader& r, int lenMod) {
    uint64_t v = r.nextInt();
    if (lenMod == 'h') return (uint64_t)(int64_t)(int16_t)v;
    if (lenMod == 1) return (uint64_t)(int64_t)(int8_t)v;  // hh
    return v;
}

}  // namespace

// guest-pointer aware %s: we must read the string from guest memory.
// Reimplemented here with Emu access instead of the naive version above.
static std::string formatGuest(Emu& emu, const char* fmt, VaReader& r) {
    Sink out;
    char tmp[64];
    for (const char* p = fmt; *p;) {
        if (*p != '%') {
            out.put(p, 1);
            p++;
            continue;
        }
        const char* start = p;
        p++;
        std::string flags;
        while (*p == '-' || *p == '0' || *p == '+' || *p == ' ' || *p == '#') flags += *p++;
        long width = strtol(p, (char**)&p, 10);
        bool hasPrec = *p == '.';
        long prec = hasPrec ? strtol(p + 1, (char**)&p, 10) : 0;
        int lenMod = 0;
        if (*p == 'l') {
            p++;
            lenMod = 'l';
            if (*p == 'l') p++, lenMod = 'L';
        } else if (*p == 'z') {
            p++, lenMod = 'z';
        } else if (*p == 'h') {
            p++;
            lenMod = 'h';
            if (*p == 'h') p++, lenMod = 1;
        }
        char conv = *p;
        if (conv == 0) break;
        p++;

        switch (conv) {
            case '%': out.put("%", 1); break;
            case 's': {
                uint64_t sp = r.nextInt();
                std::string s = sp ? emu.readCStr(sp) : "(null)";
                // width/prec on strings is rare in libc diagnostics; apply pad
                long pad = width > (long)s.size() ? width - (long)s.size() : 0;
                for (long i = 0; i < pad; i++) out.put(" ", 1);
                out.put(s.data(), s.size());
                break;
            }
            case 'd':
            case 'i': {
                long long v = (long long)readInt(r, lenMod);
                snprintf(tmp, sizeof(tmp), "%*.*lld", (int)width, hasPrec ? (int)prec : -1, v);
                out.put(tmp, strlen(tmp));
                break;
            }
            case 'u': {
                unsigned long long v = readInt(r, lenMod);
                snprintf(tmp, sizeof(tmp), "%*.*llu", (int)width, hasPrec ? (int)prec : -1, v);
                out.put(tmp, strlen(tmp));
                break;
            }
            case 'x':
            case 'X': {
                unsigned long long v = readInt(r, lenMod);
                snprintf(tmp, sizeof(tmp), conv == 'x' ? "%*llx" : "%*llX", (int)width, v);
                out.put(tmp, strlen(tmp));
                break;
            }
            case 'o': {
                unsigned long long v = readInt(r, lenMod);
                snprintf(tmp, sizeof(tmp), "%*llo", (int)width, v);
                out.put(tmp, strlen(tmp));
                break;
            }
            case 'p': {
                uint64_t v = r.nextInt();
                snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)v);
                out.put(tmp, strlen(tmp));
                break;
            }
            case 'c': {
                char c = (char)readInt(r, lenMod);
                out.put(&c, 1);
                break;
            }
            case 'f':
            case 'g':
            case 'e':
                out.put("0.000000", 8);
                break;
            default:
                out.put(start, p - start);
                break;
        }
    }
    return std::move(out.buf);
}

// ------------------------------------------------------------ handlers

namespace {

std::unordered_map<uint64_t, uint64_t>& tlsValues() {
    static std::unordered_map<uint64_t, uint64_t> m;
    return m;
}

uint64_t h_malloc(Emu& e, const uint64_t* x) { return e.gmalloc(x[0]); }
uint64_t h_calloc(Emu& e, const uint64_t* x) { return e.gcalloc(x[0] * x[1]); }
uint64_t h_realloc(Emu& e, const uint64_t* x) { return e.grealloc(x[0], x[1]); }
uint64_t h_free(Emu& e, const uint64_t* x) { e.gfree(x[0]); return 0; }

uint64_t h_posix_memalign(Emu& e, const uint64_t* x) {
    uint64_t p = e.gmallocAligned(x[2], x[1]);
    e.writeMem(x[0], &p, 8);
    return 0;
}

uint64_t h_memcpy(Emu& e, const uint64_t* x) {
    if (x[2]) memcpy(e.hostPtr(x[0], x[2]), e.hostPtr(x[1], x[2]), x[2]);
    return x[0];
}
uint64_t h_memmove(Emu& e, const uint64_t* x) {
    if (x[2]) memmove(e.hostPtr(x[0], x[2]), e.hostPtr(x[1], x[2]), x[2]);
    return x[0];
}
uint64_t h_memset(Emu& e, const uint64_t* x) {
    if (x[2]) memset(e.hostPtr(x[0], x[2]), (int)(x[1] & 0xFF), x[2]);
    return x[0];
}
uint64_t h_memcmp(Emu& e, const uint64_t* x) {
    int r = x[2] ? memcmp(e.hostPtr(x[0], x[2]), e.hostPtr(x[1], x[2]), x[2]) : 0;
    return (uint64_t)(int64_t)r;
}

uint64_t h_strlen(Emu& e, const uint64_t* x) { return e.readCStr(x[0]).size(); }
uint64_t h_strcmp(Emu& e, const uint64_t* x) {
    std::string a = e.readCStr(x[0]), b = e.readCStr(x[1]);
    int r = a.compare(b);
    // strcmp must compare bytes; equal-prefix strings of different length differ
    if (r == 0 && a.size() != b.size()) r = a.size() < b.size() ? -1 : 1;
    return (uint64_t)(int64_t)r;
}
uint64_t h_strcpy(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[1]);
    e.writeMem(x[0], s.c_str(), s.size() + 1);
    return x[0];
}
uint64_t h_stpcpy(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[1]);
    e.writeMem(x[0], s.c_str(), s.size() + 1);
    return x[0] + s.size();
}
uint64_t h_strlcpy(Emu& e, const uint64_t* x) {
    uint64_t dst = x[0], src = x[1], size = x[2];
    std::string s = e.readCStr(src);
    if (size) {
        size_t n = s.size() < size - 1 ? s.size() : size - 1;
        e.writeMem(dst, s.data(), n);
        uint8_t z = 0;
        e.writeMem(dst + n, &z, 1);
    }
    return s.size();
}
uint64_t h_strdup(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    uint64_t p = e.gmalloc(s.size() + 1);
    e.writeMem(p, s.c_str(), s.size() + 1);
    return p;
}
uint64_t h_strsep(Emu& e, const uint64_t* x) {
    uint64_t spPtr = x[0];
    uint64_t sp = 0;
    e.readMem(spPtr, &sp, 8);
    if (!sp) return 0;
    std::string delims = e.readCStr(x[1]);
    const uint8_t* p = e.hostPtr(sp, 1);
    uint64_t i = 0;
    while (p[i]) {
        if (delims.find((char)p[i]) != std::string::npos) {
            uint8_t z = 0;
            e.writeMem(sp + i, &z, 1);
            uint64_t next = sp + i + 1;
            e.writeMem(spPtr, &next, 8);
            return sp;
        }
        i++;
    }
    uint64_t nul = sp + i;
    e.writeMem(spPtr, &nul, 8);
    return sp;
}

// ---- full string/char classification set: the decompressed ZSM module
// resolves these dynamically via dlsym and may actually call them ----

uint64_t h_strncmp(Emu& e, const uint64_t* x) {
    auto a = e.hostPtr(x[0], 1), b = e.hostPtr(x[1], 1);
    size_t n = x[2];
    int r = n ? memcmp(a, b, n) : 0;  // NOTE: memcmp stops at first difference only
    if (r == 0) return 0;
    return r < 0 ? (uint64_t)(int64_t)-1 : 1;
}
uint64_t h_strcasecmp(Emu& e, const uint64_t* x) {
    std::string a = e.readCStr(x[0]), b = e.readCStr(x[1]);
    auto lo = [](char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; };
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i <= n; i++) {
        char ca = lo(a[i]), cb = lo(b[i]);
        if (ca != cb) return ca < cb ? (uint64_t)(int64_t)-1 : 1;
    }
    return 0;
}
uint64_t h_strncasecmp(Emu& e, const uint64_t* x) {
    std::string a = e.readCStr(x[0]), b = e.readCStr(x[1]);
    auto lo = [](char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; };
    size_t n = x[2];
    for (size_t i = 0; i < n; i++) {
        char ca = lo(i <= a.size() ? a[i] : '\0'), cb = lo(i <= b.size() ? b[i] : '\0');
        if (ca != cb) return ca < cb ? (uint64_t)(int64_t)-1 : 1;
        if (!ca) return 0;
    }
    return 0;
}
uint64_t h_strcspn(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    std::string rej = e.readCStr(x[1]);
    size_t n = 0;
    while (n < s.size() && rej.find(s[n]) == std::string::npos) n++;
    return n;
}
uint64_t h_strspn(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    std::string acc = e.readCStr(x[1]);
    size_t n = 0;
    while (n < s.size() && acc.find(s[n]) != std::string::npos) n++;
    return n;
}
uint64_t h_strpbrk(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    std::string set = e.readCStr(x[1]);
    for (size_t i = 0; i < s.size(); i++)
        if (set.find(s[i]) != std::string::npos) return x[0] + i;
    return 0;
}
uint64_t h_strstr(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    size_t p = s.find(e.readCStr(x[1]));
    return p == std::string::npos ? 0 : x[0] + p;
}
uint64_t h_strncat(Emu& e, const uint64_t* x) {
    std::string dst = e.readCStr(x[0]);
    std::string src = e.readCStr(x[1]);
    src.resize(std::min(src.size(), (size_t)x[2]));
    std::string out = dst + src;
    e.writeMem(x[0], out.c_str(), out.size() + 1);
    return x[0];
}
uint64_t h_strchr(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    char c = (char)x[1];
    size_t p = s.find(c);
    if (c == '\0') return x[0] + s.size();
    return p == std::string::npos ? 0 : x[0] + p;
}
uint64_t h_strrchr(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    char c = (char)x[1];
    size_t p = s.rfind(c);
    return p == std::string::npos ? 0 : x[0] + p;
}
uint64_t h_memchr(Emu& e, const uint64_t* x) {
    const uint8_t* p = e.hostPtr(x[0], x[2] ? x[2] : 1);
    for (uint64_t i = 0; i < x[2]; i++)
        if (p[i] == (uint8_t)x[1]) return x[0] + i;
    return 0;
}
uint64_t h_strtok(Emu& e, const uint64_t* x) {
    static uint64_t saved = 0;
    static std::string savedDelims;
    uint64_t s = x[0];
    std::string delims = e.readCStr(x[1]);
    if (!s) {
        s = saved;
        if (!s) return 0;
        if (savedDelims != delims) {
            // caller switched delimiters between calls; restart scan anyway
        }
    }
    std::string str = e.readCStr(s);
    size_t start = 0;
    while (start < str.size() && delims.find(str[start]) != std::string::npos) start++;
    if (start >= str.size()) {
        saved = 0;
        return 0;
    }
    size_t end = start;
    while (end < str.size() && delims.find(str[end]) == std::string::npos) end++;
    uint64_t tok = s + start;
    if (end < str.size()) {
        uint8_t z = 0;
        e.writeMem(s + end, &z, 1);
        saved = s + end + 1;
    } else {
        saved = 0;
    }
    return tok;
}
uint64_t h_strtol(Emu& e, const uint64_t* x) {
    std::string s = e.readCStr(x[0]);
    char* endp = nullptr;
    long v = strtol(s.c_str(), &endp, (int)x[2]);
    if (x[1]) {
        uint64_t consumed = endp - s.c_str();
        uint64_t addr = x[0] + consumed;
        e.writeMem(x[1], &addr, 8);
    }
    return (uint64_t)v;
}
uint64_t h_atoi(Emu& e, const uint64_t* x) { return (uint64_t)atoi(e.readCStr(x[0]).c_str()); }
uint64_t h_isalpha(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ? x[0] : 0;
}
uint64_t h_isdigit(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c >= '0' && c <= '9') ? x[0] : 0;
}
uint64_t h_isspace(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') ? x[0]
                                                                                      : 0;
}
uint64_t h_isalnum(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) ? x[0]
                                                                                        : 0;
}
uint64_t h_isupper(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c >= 'A' && c <= 'Z') ? x[0] : 0;
}
uint64_t h_isprint(Emu&, const uint64_t* x) { return (x[0] >= 0x20 && x[0] < 0x7F) ? x[0] : 0; }
uint64_t h_tolower(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c >= 'A' && c <= 'Z') ? (uint64_t)(c + 32) : x[0];
}
uint64_t h_toupper(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c >= 'a' && c <= 'z') ? (uint64_t)(c - 32) : x[0];
}
uint64_t h_rand(Emu&, const uint64_t*) { return (uint64_t)rand(); }
uint64_t h_srand(Emu&, const uint64_t* x) {
    srand((unsigned)x[0]);
    return 0;
}

// ---- symbols the ZSM module resolves via dlsym and actually calls: the
// module is built for a real Android libc, so give it working ones ----

uint64_t h_time(Emu&, const uint64_t*) { return (uint64_t)time(nullptr); }
uint64_t h_gettimeofday(Emu& e, const uint64_t* x) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    if (x[0]) {
        uint64_t v[2] = {(uint64_t)tv.tv_sec, (uint64_t)tv.tv_usec};
        e.writeMem(x[0], v, 16);
    }
    return 0;
}
uint64_t h_localtime_r(Emu& e, const uint64_t* x) {
    time_t t = (time_t)x[0];
    struct tm tmv;
#ifdef _WIN32
    if (x[0] && localtime_s(&tmv, &t)) return 0;
#else
    if (!localtime_r(x[0] ? &t : nullptr, &tmv)) return 0;
#endif
    // bionic struct tm layout == glibc x86-64 layout (9 ints + gmtoff + zone)
    e.writeMem(x[1], &tmv, sizeof(struct tm) > 56 ? 56 : sizeof(struct tm));
    return x[1];
}
uint64_t h_uname(Emu& e, const uint64_t* x) {
    struct {
        char sys[65], node[65], rel[65], ver[65], mach[65], dom[65];
    } u{};
    snprintf(u.sys, 65, "Linux");
    snprintf(u.node, 65, "localhost");
    snprintf(u.rel, 65, "4.9.112");
    snprintf(u.ver, 65, "#1 SMP PREEMPT");
    snprintf(u.mach, 65, "armv8l");  // matches official Android client sysinfo
    snprintf(u.dom, 65, "(none)");
    e.writeMem(x[0], &u, sizeof(u));
    return 0;
}
uint64_t h_system_property_get(Emu& e, const uint64_t* x) {
    // values matching the unidbg SDK23 image (sysinfo injection expects sdk=23)
    static const std::pair<const char*, const char*> props[] = {
        {"ro.build.version.sdk", "23"},
        {"ro.build.version.release", "6.0"},
        {"ro.build.version.codename", "REL"},
        {"gsm.network.type", "Unknown"},
        {"ro.product.model", "Nexus 5"},
        {"ro.product.manufacturer", "LGE"},
        {"ro.product.brand", "google"},
        {"ro.product.device", "hammerhead"},
        {"ro.product.name", "hammerhead"},
        {"ro.hardware", "hammerhead"},
        {"ro.board.platform", "msm8974"},
        {"ro.secure", "1"},
        {"ro.debuggable", "0"},
    };
    std::string name = e.readCStr(x[0]);
    for (auto& p : props) {
        if (name == p.first) {
            size_t len = strlen(p.second);
            e.writeMem(x[1], p.second, len + 1);
            return len;
        }
    }
    return 0;
}
uint64_t h_strerror(Emu& e, const uint64_t* x) {
    static uint64_t buf = 0;
    if (!buf) buf = e.gmalloc(64);
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "Unknown error %lld", (long long)(int32_t)x[0]);
    e.writeMem(buf, tmp, strlen(tmp) + 1);
    return buf;
}
uint64_t h_strncpy(Emu& e, const uint64_t* x) {
    size_t n = x[2];
    if (n) {
        std::string s = e.readCStr(x[1]);
        if (s.size() < n) s.resize(n, '\0');  // strncpy zero-pads
        e.writeMem(x[0], s.data(), n);
    }
    return x[0];
}
uint64_t h_strcasestr(Emu& e, const uint64_t* x) {
    std::string s = toLower(e.readCStr(x[0]));
    std::string needle = toLower(e.readCStr(x[1]));
    size_t p = s.find(needle);
    return p == std::string::npos ? 0 : x[0] + p;
}
uint64_t h_vsnprintf(Emu& e, const uint64_t* x) {
    VaReader r(e, x[3]);
    std::string s = formatGuest(e, e.readCStr(x[2]).c_str(), r);
    size_t n = x[1];
    if (n) {
        size_t w = s.size() < n - 1 ? s.size() : n - 1;
        e.writeMem(x[0], s.data(), w);
        uint8_t z = 0;
        e.writeMem(x[0] + w, &z, 1);
    }
    return s.size();
}
uint64_t h_vsprintf_chk(Emu& e, const uint64_t* x) {
    // (buf, flags, slen, fmt, va)
    VaReader r(e, x[4]);
    std::string s = formatGuest(e, e.readCStr(x[3]).c_str(), r);
    e.writeMem(x[0], s.c_str(), s.size() + 1);
    return s.size();
}
uint64_t h_strlen_chk(Emu& e, const uint64_t* x) {
    return strnlen((const char*)e.hostPtr(x[0], 1), x[1]);
}

// socket layer: the ZSM reverse-notify channel (udp) carries no traffic per
// protocol analysis; fake success on setup, failure on I/O
uint64_t h_socket(Emu&, const uint64_t*) {
    static uint64_t fakeFd = 0x3100;
    fakeFd += 4;
    return fakeFd;
}
uint64_t h_bind(Emu&, const uint64_t*) { return 0; }
uint64_t h_connect(Emu&, const uint64_t*) { return 0; }
uint64_t h_setsockopt(Emu&, const uint64_t*) { return 0; }
uint64_t h_sendto(Emu&, const uint64_t*) { return (uint64_t)(int64_t)-1; }
uint64_t h_recvfrom(Emu&, const uint64_t*) { return (uint64_t)(int64_t)-1; }
uint64_t h_select(Emu&, const uint64_t*) { return 0; }
uint64_t h_fcntl(Emu&, const uint64_t*) { return 0; }
uint64_t h_fd_set_chk(Emu&, const uint64_t*) { return 0; }
uint64_t h_close_guest(Emu&, const uint64_t*) { return 0; }
uint64_t h_inet_addr(Emu& e, const uint64_t* x) {
    unsigned a, b, c, d;
    std::string s = e.readCStr(x[0]);
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0xFFFFFFFF;
    return a | (b << 8) | (c << 16) | ((uint32_t)d << 24);
}
uint64_t h_inet_ntoa(Emu& e, const uint64_t* x) {
    static uint64_t buf = 0;
    if (!buf) buf = e.gmalloc(16);
    uint32_t in = (uint32_t)x[0];
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u", in & 0xFF, (in >> 8) & 0xFF, (in >> 16) & 0xFF,
             (in >> 24) & 0xFF);
    e.writeMem(buf, tmp, strlen(tmp) + 1);
    return buf;
}
uint64_t h_fclose(Emu&, const uint64_t*) { return 0; }
uint64_t h_fgets(Emu&, const uint64_t*) { return 0; }

// pthread family: single-threaded guest, no-op the sync primitives
uint64_t h_pthread_mutex_init(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_mutex_destroy(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_mutexattr_init(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_mutexattr_settype(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_mutexattr_destroy(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_join(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_exit(Emu&, const uint64_t*) {
    logRaw("[libc] pthread_exit called -> ending guest call");
    throw EmuExit{0};
}
uint64_t h_fd_isset_chk(Emu&, const uint64_t*) { return 0; }
uint64_t h_fd_clr_chk(Emu&, const uint64_t*) { return 0; }
uint64_t h_fd_zero_chk(Emu&, const uint64_t*) { return 0; }
uint64_t h_snprintf_chk(Emu& e, const uint64_t* x) {
    // (buf, size, flags, slen, fmt, ...)
    VaReader r(e, x, 5);
    std::string s = formatGuest(e, e.readCStr(x[4]).c_str(), r);
    size_t n = x[1];
    if (n) {
        size_t w = s.size() < n - 1 ? s.size() : n - 1;
        e.writeMem(x[0], s.data(), w);
        uint8_t z = 0;
        e.writeMem(x[0] + w, &z, 1);
    }
    return s.size();
}
uint64_t h_sprintf_chk(Emu& e, const uint64_t* x) {
    // (buf, flags, slen, fmt, ...)
    VaReader r(e, x, 4);
    std::string s = formatGuest(e, e.readCStr(x[3]).c_str(), r);
    e.writeMem(x[0], s.c_str(), s.size() + 1);
    return s.size();
}
uint64_t h_recvfrom_chk(Emu&, const uint64_t*) { return (uint64_t)(int64_t)-1; }
uint64_t h_read_chk(Emu& e, const uint64_t* x) {
    ssize_t n = read((int)x[0], e.hostPtr(x[1], x[2] ? x[2] : 1), x[2]);
    return n < 0 ? (uint64_t)(int64_t)-1 : (uint64_t)n;
}
uint64_t h_poll_chk(Emu&, const uint64_t*) { return 0; }
uint64_t h_getifaddrs(Emu&, const uint64_t*) { return (uint64_t)(int64_t)-1; }
uint64_t h_freeifaddrs(Emu&, const uint64_t*) { return 0; }
uint64_t h_if_nametoindex(Emu&, const uint64_t*) { return 0; }
uint64_t h_assert(Emu& e, const uint64_t*) {
    e.dumpState("guest assert failed");
    throw EmuError("guest __assert/__assert2");
}
uint64_t h_android_log_print(Emu& e, const uint64_t* x) {
    // (prio, tag, fmt, ...): 2=V 3=D 4=I 5=W 6=E
    static const char prioChar[] = "VDIWEF";
    int prio = (int)(x[0] & 0xFF);
    VaReader r(e, x, 3);
    std::string msg = formatGuest(e, e.readCStr(x[2]).c_str(), r);
    char pc = (prio >= 2 && prio <= 7) ? prioChar[prio - 2] : '?';
    logRaw("[logcat] %c/%s: %s", pc, e.readCStr(x[1]).c_str(), msg.c_str());
    return 1;
}

int isStreamStdout(Emu& e, uint64_t f) {
    return f >= SF_ADDR && f < SF_ADDR + 3 * SF_SIZE && (f - SF_ADDR) / SF_SIZE == 1;
}

uint64_t h_fputc(Emu& e, const uint64_t* x) {
    char c = (char)x[0];
    fputc(c, isStreamStdout(e, x[1]) ? stdout : stderr);
    return (uint8_t)c;
}
uint64_t h_vfprintf(Emu& e, const uint64_t* x) {
    VaReader r(e, x[2]);
    std::string s = formatGuest(e, e.readCStr(x[1]).c_str(), r);
    FILE* f = isStreamStdout(e, x[0]) ? stdout : stderr;
    fwrite(s.data(), 1, s.size(), f);
    fflush(f);
    return s.size();
}
uint64_t h_vasprintf(Emu& e, const uint64_t* x) {
    VaReader r(e, x[2]);
    std::string s = formatGuest(e, e.readCStr(x[1]).c_str(), r);
    uint64_t p = e.gmalloc(s.size() + 1);
    e.writeMem(p, s.c_str(), s.size() + 1);
    e.writeMem(x[0], &p, 8);
    return s.size();
}
uint64_t h_vsnprintf_chk(Emu& e, const uint64_t* x) {
    // (dst, supplied, flags, srclen, fmt, va)
    VaReader r(e, x[5]);
    std::string s = formatGuest(e, e.readCStr(x[4]).c_str(), r);
    size_t cap = x[1];
    if (cap) {
        size_t n = s.size() < cap - 1 ? s.size() : cap - 1;
        e.writeMem(x[0], s.data(), n);
        uint8_t z = 0;
        e.writeMem(x[0] + n, &z, 1);
    }
    return s.size();
}
uint64_t h_write_chk(Emu& e, const uint64_t* x) {
    ssize_t n = write((int)x[0], e.hostPtr(x[1], x[2] ? x[2] : 1), x[2]);
    return (uint64_t)n;
}

uint64_t h_abort(Emu& e, const uint64_t*) {
    e.dumpState("guest abort()");
    throw EmuError("guest abort(): " + e.abortMessage());
}
uint64_t h_set_abort_message(Emu& e, const uint64_t* x) {
    e.setAbortMessage(e.readCStr(x[0]));
    return 0;
}
uint64_t h_stack_chk_fail(Emu& e, const uint64_t*) {
    e.dumpState("__stack_chk_fail");
    throw EmuError("guest stack smashing detected");
}
uint64_t h_errno(Emu& e, const uint64_t*) { return GUEST_ERRNO; }
uint64_t h_fstat(Emu& e, const uint64_t* x) {
    // imported bionic fstat(fd, stat*) - fill the guest buffer in bionic layout
    struct stat st {};
    if (fstat((int)x[0], &st) != 0) return (uint64_t)(int64_t)-9;  // EBADF
    uint8_t b[128];
    memset(b, 0, sizeof(b));
    auto put64 = [&](size_t off, uint64_t v) { memcpy(b + off, &v, 8); };
    auto put32 = [&](size_t off, uint32_t v) { memcpy(b + off, &v, 4); };
    put64(0, st.st_dev);
    put64(8, st.st_ino);
    put32(16, st.st_mode);
    put32(20, st.st_uid);
    put32(24, st.st_gid);
    put64(32, st.st_rdev);
    put64(40, st.st_size);
    put64(48, 4096);
#ifdef _WIN32
    put64(56, (uint64_t)(st.st_size + 4095) / 4096);
#else
    put64(56, st.st_blocks);
#endif
    e.writeMem(x[1], b, sizeof(b));
    return 0;
}
uint64_t h_cxa_atexit(Emu&, const uint64_t*) { return 0; }
uint64_t h_cxa_finalize(Emu&, const uint64_t*) { return 0; }
uint64_t h_exit(Emu&, const uint64_t* x) { throw EmuExit{(int)x[0]}; }
uint64_t h_islower(Emu&, const uint64_t* x) {
    return (x[0] >= 'a' && x[0] <= 'z') ? x[0] : 0;
}
uint64_t h_isxdigit(Emu&, const uint64_t* x) {
    char c = (char)x[0];
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

uint64_t h_mmap(Emu& e, const uint64_t* x) {
    if (x[4] != ~0ull && x[4] != 0) {
        logDbg("[libc] mmap fd-backed (fd=%llu) -> anonymous", (unsigned long long)x[4]);
    }
    return e.guestMmap(x[0], x[1], x[3]);
}
uint64_t h_mprotect(Emu&, const uint64_t*) { return 0; }
uint64_t h_munmap(Emu&, const uint64_t*) { return 0; }
uint64_t h_prctl(Emu&, const uint64_t*) { return 0; }
uint64_t h_openlog(Emu&, const uint64_t*) { return 0; }
uint64_t h_closelog(Emu&, const uint64_t*) { return 0; }
uint64_t h_syslog(Emu& e, const uint64_t* x) {
    // syslog(pri, fmt, ...): extra args in x2..
    VaReader r(e, x, 2);
    std::string s = formatGuest(e, e.readCStr(x[1]).c_str(), r);
    logRaw("[guest syslog] %s", s.c_str());
    return 0;
}

uint64_t h_pthread_create(Emu& e, const uint64_t* x) {
    static uint64_t fakeTid = 0x90000000;
    const char* mode = getenv("TY_THREAD_SYNC");
    if (mode && mode[0] == '1') {
        logRaw("[libc] pthread_create: running start routine synchronously");
        e.callGuest(x[2], {x[3]});
    } else {
        logDbg("[libc] pthread_create: skipped (fire-and-forget thread)");
    }
    e.writeMem(x[0], &fakeTid, 8);
    fakeTid += 0x1000;
    return 0;
}
uint64_t h_pthread_once(Emu& e, const uint64_t* x) {
    uint32_t st = 0;
    e.readMem(x[0], &st, 4);
    if (st != 2) {
        e.callGuest(x[1], {});
        st = 2;
        e.writeMem(x[0], &st, 4);
    }
    return 0;
}
uint64_t h_pthread_key_create(Emu& e, const uint64_t* x) {
    static uint32_t nextKey = 1;
    e.writeMem(x[0], &nextKey, 4);
    nextKey++;
    return 0;
}
uint64_t h_pthread_setspecific(Emu&, const uint64_t* x) {
    tlsValues()[x[0]] = x[1];
    return 0;
}
uint64_t h_pthread_getspecific(Emu&, const uint64_t* x) {
    auto& m = tlsValues();
    auto it = m.find(x[0]);
    return it == m.end() ? 0 : it->second;
}
uint64_t h_pthread_mutex_lock(Emu&, const uint64_t*) { return 0; }
uint64_t h_pthread_mutex_unlock(Emu&, const uint64_t*) { return 0; }
uint64_t h_register_atfork(Emu&, const uint64_t*) { return 0; }

uint64_t h_dlopen(Emu& e, const uint64_t* x) {
    // distinct handle per library name (unidbg semantics; a shared handle reads
    // as tampering to the module's probe)
    static std::unordered_map<std::string, uint64_t> handles;
    std::string name = e.readCStr(x[0]);
    auto it = handles.find(name);
    if (it == handles.end()) it = handles.emplace(name, 0xD000ull + handles.size() * 0x100).first;
    logDbg("[libc] dlopen('%s', %#llx) -> %#llx", name.c_str(), (unsigned long long)x[1],
           (unsigned long long)it->second);
    return it->second;
}
// dlsym: only the module's own exports resolve. Every libc symbol the ZSM
// module probes (popen/strcspn/malloc/...) must return 0, matching unidbg,
// whose SDK23 libs export none of them - the module then uses its internal
// fallbacks. Resolving them to stubs corrupts its XML pipeline.
uint64_t h_popen(Emu& e, const uint64_t* x) {
    logDbg("[libc] popen('%s') -> NULL", e.readCStr(x[0]).c_str());
    return 0;
}
uint64_t h_pclose(Emu&, const uint64_t*) { return (uint64_t)(int64_t)-1; }
uint64_t h_dlsym(Emu& e, const uint64_t* x) {
    std::string name = e.readCStr(x[1]);
    auto ex = e.exports.find(name);
    if (ex != e.exports.end()) return ex->second;
    uint64_t stub = e.importStubAddr(name);
    if (stub) return stub;
    logDbg("[libc] dlsym('%s') -> 0", name.c_str());
    return 0;
}

}  // namespace

void registerGuestLibc(Emu& emu) {
    struct Entry {
        const char* name;
        Emu::NativeFn fn;
    };
    static const Entry entries[] = {
        {"malloc", h_malloc},              {"calloc", h_calloc},
        {"realloc", h_realloc},            {"free", h_free},
        {"posix_memalign", h_posix_memalign},
        {"memcpy", h_memcpy},              {"__memcpy_chk", h_memcpy},
        {"memmove", h_memmove},            {"__memmove_chk", h_memmove},
        {"memset", h_memset},              {"__memset_chk", h_memset},
        {"memcmp", h_memcmp},
        {"strlen", h_strlen},              {"__strlen_chk", h_strlen},
        {"strcmp", h_strcmp},
        {"strcpy", h_strcpy},              {"__strcpy_chk", h_strcpy},
        {"stpcpy", h_stpcpy},              {"__stpcpy_chk", h_stpcpy},
        {"strlcpy", h_strlcpy},            {"__strlcpy_chk", h_strlcpy},
        {"strdup", h_strdup},              {"strsep", h_strsep},
        {"strncmp", h_strncmp},            {"strcasecmp", h_strcasecmp},
        {"strncasecmp", h_strncasecmp},    {"strcspn", h_strcspn},
        {"strspn", h_strspn},              {"strpbrk", h_strpbrk},
        {"strstr", h_strstr},              {"strncat", h_strncat},
        {"strchr", h_strchr},              {"strrchr", h_strrchr},
        {"memchr", h_memchr},              {"strtok", h_strtok},
        {"strtol", h_strtol},              {"atoi", h_atoi},
        {"isalpha", h_isalpha},            {"isdigit", h_isdigit},
        {"isspace", h_isspace},            {"isalnum", h_isalnum},
        {"isupper", h_isupper},            {"isprint", h_isprint},
        {"tolower", h_tolower},            {"toupper", h_toupper},
        {"rand", h_rand},                  {"srand", h_srand},
        // dlsym-resolved set used by the ZSM module's inner code
        {"time", h_time},                  {"gettimeofday", h_gettimeofday},
        {"localtime_r", h_localtime_r},    {"uname", h_uname},
        {"__system_property_get", h_system_property_get},
        {"strerror", h_strerror},          {"strncpy", h_strncpy},
        {"__strncpy_chk", h_strncpy},      {"strcasestr", h_strcasestr},
        {"vsnprintf", h_vsnprintf},        {"__vsnprintf_chk", h_vsnprintf_chk},
        {"__vsprintf_chk", h_vsprintf_chk}, {"__strlen_chk", h_strlen_chk},
        {"socket", h_socket},              {"bind", h_bind},
        {"connect", h_connect},            {"setsockopt", h_setsockopt},
        {"sendto", h_sendto},              {"recvfrom", h_recvfrom},
        {"select", h_select},              {"fcntl", h_fcntl},
        {"__FD_SET_chk", h_fd_set_chk},    {"close", h_close_guest},
        {"inet_addr", h_inet_addr},        {"inet_ntoa", h_inet_ntoa},
        {"fclose", h_fclose},              {"fgets", h_fgets},
        {"pthread_mutex_init", h_pthread_mutex_init},
        {"pthread_mutex_destroy", h_pthread_mutex_destroy},
        {"pthread_mutexattr_init", h_pthread_mutexattr_init},
        {"pthread_mutexattr_settype", h_pthread_mutexattr_settype},
        {"pthread_mutexattr_destroy", h_pthread_mutexattr_destroy},
        {"pthread_join", h_pthread_join},
        {"pthread_exit", h_pthread_exit},
        {"__FD_ISSET_chk", h_fd_isset_chk}, {"__FD_CLR_chk", h_fd_clr_chk},
        {"__FD_ZERO_chk", h_fd_zero_chk},   {"__snprintf_chk", h_snprintf_chk},
        {"__sprintf_chk", h_sprintf_chk},   {"__recvfrom_chk", h_recvfrom_chk},
        {"__read_chk", h_read_chk},         {"__poll_chk", h_poll_chk},
        {"getifaddrs", h_getifaddrs},       {"freeifaddrs", h_freeifaddrs},
        {"if_nametoindex", h_if_nametoindex},
        {"__assert", h_assert},             {"__assert2", h_assert},
        {"__android_log_print", h_android_log_print},
        {"fputc", h_fputc},
        {"vfprintf", h_vfprintf},
        {"vasprintf", h_vasprintf},
        {"__vsnprintf_chk", h_vsnprintf_chk},
        {"__write_chk", h_write_chk},
        {"abort", h_abort},
        {"android_set_abort_message", h_set_abort_message},
        {"__stack_chk_fail", h_stack_chk_fail},
        {"__errno", h_errno},
        {"fstat", h_fstat},
        {"__cxa_atexit", h_cxa_atexit},
        {"__cxa_finalize", h_cxa_finalize},
        {"exit", h_exit},
        {"islower", h_islower},            {"isxdigit", h_isxdigit},
        {"mmap", h_mmap},                  {"mprotect", h_mprotect},
        {"munmap", h_munmap},              {"prctl", h_prctl},
        {"openlog", h_openlog},            {"syslog", h_syslog},
        {"closelog", h_closelog},
        {"pthread_create", h_pthread_create},
        {"pthread_once", h_pthread_once},
        {"pthread_key_create", h_pthread_key_create},
        {"pthread_setspecific", h_pthread_setspecific},
        {"pthread_getspecific", h_pthread_getspecific},
        {"pthread_mutex_lock", h_pthread_mutex_lock},
        {"pthread_mutex_unlock", h_pthread_mutex_unlock},
        {"__register_atfork", h_register_atfork},
        {"dlopen", h_dlopen},              {"dlsym", h_dlsym},
        {"popen", h_popen},                {"pclose", h_pclose},
    };
    for (auto& en : entries) emu.addImport(en.name, en.fn);
}

// ------------------------------------------------------------ syscalls

namespace {

// minimal fd-based VFS: virtual files + host passthrough
std::string mapsContent(Emu& emu) {
    char line[128];
    std::string s;
    const char* rows[] = {
        "%08llx-%08llx rw-p 00000000 00:00 0    [stack]\n",
    };
    (void)rows;
    snprintf(line, sizeof(line), "%08llx-%08llx rw-p 00000000 00:00 0    [stack]\n",
             (unsigned long long)STACK_BASE, (unsigned long long)(STACK_BASE + STACK_SIZE));
    s += line;
    snprintf(line, sizeof(line), "%08llx-%08llx r-xp 00000000 00:00 0    /libdaproxy.so\n",
             (unsigned long long)IMAGE_BASE, (unsigned long long)IMAGE_BASE + 0x40000);
    s += line;
    snprintf(line, sizeof(line), "%08llx-%08llx rw-p 00000000 00:00 0    [anon:heap]\n",
             (unsigned long long)HEAP_BASE, (unsigned long long)(HEAP_BASE + HEAP_SIZE));
    s += line;
    snprintf(line, sizeof(line), "%08llx-%08llx rw-p 00000000 00:00 0    [anon:mmap]\n",
             (unsigned long long)MMAP_BASE, (unsigned long long)(MMAP_BASE + MMAP_SIZE));
    s += line;
    snprintf(line, sizeof(line), "%08llx-%08llx rwxp 00000000 00:00 0    [anon:scratch]\n",
             (unsigned long long)SCRATCH_BASE, (unsigned long long)(SCRATCH_BASE + SCRATCH_SIZE));
    s += line;
    (void)emu;
    return s;
}

bool hostStatToBionic(int fd, Emu& emu, uint64_t bufAddr) {
    struct stat st {};
    if (fstat(fd, &st) != 0) return false;
    uint8_t b[128];
    memset(b, 0, sizeof(b));
    auto put64 = [&](size_t off, uint64_t v) { memcpy(b + off, &v, 8); };
    auto put32 = [&](size_t off, uint32_t v) { memcpy(b + off, &v, 4); };
    put64(0, st.st_dev);
    put64(8, st.st_ino);
    put32(16, st.st_mode);
    put32(20, st.st_uid);
    put32(24, st.st_gid);
    put64(32, st.st_rdev);
    put64(40, st.st_size);
    put64(48, 4096);
#ifdef _WIN32
    put64(56, (uint64_t)(st.st_size + 4095) / 4096);
#else
    put64(56, st.st_blocks);
#endif
    emu.writeMem(bufAddr, b, sizeof(b));
    return true;
}

}  // namespace

uint64_t guestSyscall(Emu& emu, const uint64_t* x) {
    uint64_t nr = x[8];
    if (gDebug)
        logDbg("[syscall] nr=%llu x0=0x%llx x1=0x%llx x2=0x%llx",
               (unsigned long long)nr, (unsigned long long)x[0],
               (unsigned long long)x[1], (unsigned long long)x[2]);
    auto err = [](int e) { return (uint64_t)(int64_t)-e; };

    switch (nr) {
        case 56: {  // openat(dirfd, path, flags, mode)
            std::string path = emu.readCStr(x[1]);
            if (path == "/proc/self/maps") {
                std::string c = mapsContent(emu);
#if defined(__linux__)
                int fd = syscall(SYS_memfd_create, "maps", 0);
#else
                // no memfd_create outside Linux: anonymous temp file
                int fd = fileno(tmpfile());
#endif
                if (fd < 0) return err(12);
                size_t off = 0;
                while (off < c.size()) {
                    ssize_t n = write(fd, c.data() + off, c.size() - off);
                    if (n <= 0) break;
                    off += n;
                }
                lseek(fd, 0, SEEK_SET);
                return (uint64_t)fd;
            }
            int fd = open(path.c_str(), (int)(x[2] & 0xFFFFFFFF), 0600);
            if (fd < 0) return err(errno ? errno : 2);
            return (uint64_t)fd;
        }
        case 57:  // close
            if (x[0] > 2) close((int)x[0]);
            return 0;
        case 63: {  // read
            ssize_t n = read((int)x[0], emu.hostPtr(x[1], x[2] ? x[2] : 1), x[2]);
            return n < 0 ? err(5) : (uint64_t)n;
        }
        case 64: {  // write
            ssize_t n = write((int)x[0], emu.hostPtr(x[1], x[2] ? x[2] : 1), x[2]);
            return n < 0 ? err(5) : (uint64_t)n;
        }
        case 66: {  // writev
            struct iov64 {
                uint64_t base, len;
            };
            ssize_t total = 0;
            for (uint64_t i = 0; i < x[2]; i++) {
                iov64 iv;
                emu.readMem(x[1] + i * sizeof(iov64), &iv, sizeof(iv));
                if (iv.len) {
                    ssize_t n = write((int)x[0], emu.hostPtr(iv.base, iv.len), iv.len);
                    if (n < 0) return err(5);
                    total += n;
                }
            }
            return total;
        }
        case 78:  // readlinkat -> fail
            return err(2);
        case 33: {  // mkdirat(dirfd, path, mode) - module cache dirs
            std::string path = emu.readCStr(x[1]);
#ifdef _WIN32
            int rc = _mkdir(path.c_str());
#else
            int rc = x[0] == ~0ull ? mkdir(path.c_str(), 0755)
                                   : mkdirat((int)x[0], path.c_str(), 0755);
#endif
            if (rc != 0 && errno != EEXIST) return err(13);  // EACCES-ish
            return 0;
        }
        case 79:  // newfstatat
        case 80:  // fstat
            return hostStatToBionic((int)x[0], emu, x[1]) ? 0 : err(9);
        case 93:
        case 94:  // exit / exit_group
            throw EmuExit{(int)x[0]};
        case 96:  // set_tid_address
            return 1000;
        case 98:  // futex
            return 0;
        case 99:  // set_robust_list
            return 0;
        case 113: {  // clock_gettime(clk, ts)
            struct timespec ts {};
            clock_gettime(x[0] == 1 ? CLOCK_MONOTONIC : CLOCK_REALTIME, &ts);
            uint64_t v[2] = {(uint64_t)ts.tv_sec, (uint64_t)ts.tv_nsec};
            emu.writeMem(x[1], v, 16);
            return 0;
        }
        case 124:  // sched_yield
            return 0;
        case 134:
        case 135:  // rt_sigaction / rt_sigprocmask
            return 0;
        case 160: {  // uname
            struct {
                char sys[65], node[65], rel[65], ver[65], mach[65], dom[65];
            } u{};
            snprintf(u.sys, 65, "Linux");
            snprintf(u.node, 65, "localhost");
            snprintf(u.rel, 65, "4.9.112");
            snprintf(u.ver, 65, "#1 SMP PREEMPT");
            snprintf(u.mach, 65, "armv8l");  // matches official Android client sysinfo
            snprintf(u.dom, 65, "(none)");
            emu.writeMem(x[0], &u, sizeof(u));
            return 0;
        }
        case 172: return 1000;   // getpid
        case 173: return 1;      // getppid
        case 174: return 1000;   // getuid
        case 175: return 1000;   // geteuid
        case 176: return 1000;   // getgid
        case 178: return 1000;   // gettid
        case 215: return 0;      // munmap
        case 222:                // mmap
            return emu.guestMmap(x[0], x[1], x[3]);
        case 226: return 0;      // mprotect
        case 233: return 0;      // madvise
        case 278: {              // getrandom
            size_t want = x[1];
            uint8_t* p = emu.hostPtr(x[0], want ? want : 1);
            size_t got = 0;
            while (got < want) {
#ifdef _WIN32
                // rand_s fills 32 bits per call, returns 0 on success
                unsigned int v;
                if (rand_s(&v) != 0) break;
                size_t chunk = want - got < 4 ? want - got : 4;
                memcpy(p + got, &v, chunk);
                got += chunk;
#else
                ssize_t n = getrandom(p + got, want - got, 0);
                if (n <= 0) break;
                got += n;
#endif
            }
            return got;
        }
        default:
            logRaw("[syscall] unimplemented nr=%llu (x0=0x%llx) -> ENOSYS",
                   (unsigned long long)nr, (unsigned long long)x[0]);
            return err(38);
    }
}

}  // namespace ty
