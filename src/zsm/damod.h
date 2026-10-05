// damod.h - ZSM crypto session over emulated libdaproxy.so
// (equivalent of Java tylogin.hook.AndroidMock + Session)
#pragma once
#include "emu.h"
#include "jni.h"

#include <memory>

namespace ty {

class ZsmRuntime {
public:
    // packageName: emulated Android package; rootDir: writable emulator home
    ZsmRuntime(const std::string& packageName, const std::string& rootDir);

    // one ZSM session: handle != 0 on success
    int64_t load(const std::vector<uint8_t>& zsm);
    std::string encrypt(int64_t session, const std::string& plaintextXml);
    std::string decrypt(int64_t session, const std::string& hexCiphertext);
    std::string algoId(int64_t session);
    std::string sessionKey(int64_t session);
    std::string prefix(int64_t session);
    void freeSession(int64_t session);

private:
    uint64_t callNative(const char* nameSig, std::vector<uint64_t> args);
    std::string callNativeString(const char* nameSig, std::vector<uint64_t> args);

    Emu emu_;
    Jni jni_;
    uint64_t jniOnLoad_ = 0;
};

}  // namespace ty
