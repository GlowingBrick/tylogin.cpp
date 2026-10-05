// util.h - small shared helpers: logging, time, uuid, config file, hex
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace ty {

// debug logging goes to stderr; info to stdout
void dlog(const std::string& s);          // [HH:mm:ss] prefixed, only with --debug
void info(const std::string& s);          // user-facing, always printed
void err(const std::string& s);           // "错误: ..." to stderr
void setDebug(bool on);
bool isDebug();

std::string nowTime();                    // yyyy-MM-dd HH:mm:ss (local)
std::string uuid4();                      // random v4 UUID, lowercase
bool readFile(const std::string& path, std::vector<uint8_t>& out);
std::string toLower(std::string s);
std::string trim(std::string s);

// config file: account=/user=/username=, password=/pass=/pwd=
bool readConfig(const std::string& dir, std::string& user, std::string& pass);

}  // namespace ty
