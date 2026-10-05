// md5.cpp - MD5 message digest (RFC 1321)
#include "md5.h"

#include <cstring>

namespace ty {

namespace {

struct Ctx {
    uint32_t a, b, c, d;
    uint64_t nbits;
    uint8_t buf[64];
    size_t buflen;
};

inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

void block(Ctx& c, const uint8_t* p) {
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
    static const int R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = p[i * 4] | (p[i * 4 + 1] << 8) | (p[i * 4 + 2] << 16) | ((uint32_t)p[i * 4 + 3] << 24);
    uint32_t a = c.a, b = c.b, cc = c.c, d = c.d;
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & cc) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & cc);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ cc ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = cc ^ (b | ~d);
            g = (7 * i) % 16;
        }
        uint32_t tmp = d;
        d = cc;
        cc = b;
        b = b + rol(a + f + K[i] + m[g], R[i]);
        a = tmp;
    }
    c.a += a;
    c.b += b;
    c.c += cc;
    c.d += d;
}

void update(Ctx& c, const uint8_t* data, size_t len) {
    c.nbits += len * 8;
    while (len) {
        size_t take = 64 - c.buflen < len ? 64 - c.buflen : len;
        memcpy(c.buf + c.buflen, data, take);
        c.buflen += take;
        data += take;
        len -= take;
        if (c.buflen == 64) {
            block(c, c.buf);
            c.buflen = 0;
        }
    }
}

void final(Ctx& c, uint8_t out[16]) {
    uint64_t bits = c.nbits;
    uint8_t pad = 0x80;
    update(c, &pad, 1);
    uint8_t z = 0;
    while (c.buflen != 56) update(c, &z, 1);
    update(c, (uint8_t*)&bits, 8);  // little-endian length
    uint32_t v[4] = {c.a, c.b, c.c, c.d};
    memcpy(out, v, 16);
}

}  // namespace

void md5(const uint8_t* data, size_t len, uint8_t out[16]) {
    Ctx c{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0, {0}, 0};
    update(c, data, len);
    final(c, out);
}

std::string md5hex(const uint8_t* data, size_t len) {
    uint8_t d[16];
    md5(data, len, d);
    static const char* hx = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 16; i++) {
        s += hx[d[i] >> 4];
        s += hx[d[i] & 15];
    }
    return s;
}

}  // namespace ty
