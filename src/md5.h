// md5.h - minimal MD5 (RFC 1321)
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace ty {

void md5(const uint8_t* data, size_t len, uint8_t out[16]);
std::string md5hex(const uint8_t* data, size_t len);
inline std::string md5hex(const std::string& s) {
    return md5hex((const uint8_t*)s.data(), s.size());
}

}  // namespace ty
