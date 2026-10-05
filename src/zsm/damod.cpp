#include "damod.h"

#include "elfload.h"
#include "libdaproxy_so.h"

#include <cstring>

namespace ty {

ZsmRuntime::ZsmRuntime(const std::string& packageName, const std::string& rootDir)
    : jni_(emu_, packageName, rootDir) {
    registerGuestLibc(emu_);

    loadElf(emu_, embed::libdaproxy_so, embed::libdaproxy_so_len);

    // run DT_INIT / DT_INIT_ARRAY like the Android linker would
    for (uint64_t fn : emu_.initRoutines) {
        logDbg("[damod] running init at 0x%llx", (unsigned long long)fn);
        emu_.callGuest(fn, {});
    }

    // JNI_OnLoad(JavaVM*, void*) -> JNI_VERSION
    auto it = emu_.exports.find("JNI_OnLoad");
    if (it == emu_.exports.end()) throw EmuError("libdaproxy.so has no JNI_OnLoad export");
    uint64_t ver = emu_.callGuest(it->second, {jni_.vmPtr(), 0});
    logDbg("[damod] JNI_OnLoad -> 0x%llx", (unsigned long long)ver);
    if (ver < 0x00010002 || ver > 0x00010006)
        logRaw("[damod] warning: JNI_OnLoad returned 0x%llx", (unsigned long long)ver);

    // fall back to exported Java_* symbols if RegisterNatives was not used
    if (jni_.natives().empty()) {
        int n = 0;
        for (auto& kv : emu_.exports) {
            if (kv.first.rfind("Java_", 0) == 0) {
                size_t pos = kv.first.find("DaMod_");
                if (pos == std::string::npos) continue;
                std::string m = kv.first.substr(pos + 6);
                jni_.addNative(m + "#export", kv.second);
                n++;
            }
        }
        if (n) logRaw("[damod] registered %d natives from Java_ exports", n);
    }
    if (jni_.natives().empty()) throw EmuError("no DaMod natives registered");
}

uint64_t ZsmRuntime::callNative(const char* nameSig, std::vector<uint64_t> args) {
    uint64_t fn = jni_.findNative(nameSig);
    if (!fn) throw EmuError(std::string("native not registered: ") + nameSig);
    std::vector<uint64_t> full = {jni_.envPtr(), jni_.daModClass()};
    for (auto a : args) full.push_back(a);
    return emu_.callGuest(fn, full);
}

std::string ZsmRuntime::callNativeString(const char* nameSig, std::vector<uint64_t> args) {
    uint64_t h = callNative(nameSig, std::move(args));
    if (!h) return "";
    return jni_.getString(h);
}

int64_t ZsmRuntime::load(const std::vector<uint8_t>& zsm) {
    uint64_t arr = jni_.newByteArray(zsm.data(), zsm.size());
    uint64_t h = callNative("load([B)J", {arr});
    return (int64_t)h;
}

std::string ZsmRuntime::encrypt(int64_t session, const std::string& xml) {
    uint64_t arr = jni_.newByteArray(xml.data(), xml.size());
    uint64_t ret = callNative("enc(J[B)[B", {(uint64_t)session, arr});
    if (!ret) return "";
    auto v = jni_.getByteArray(ret);
    return std::string(v.begin(), v.end());
}

std::string ZsmRuntime::decrypt(int64_t session, const std::string& hex) {
    uint64_t arr = jni_.newByteArray(hex.data(), hex.size());
    uint64_t ret = callNative("dec(J[B)[B", {(uint64_t)session, arr});
    if (!ret) return "";
    auto v = jni_.getByteArray(ret);
    return std::string(v.begin(), v.end());
}

std::string ZsmRuntime::algoId(int64_t session) {
    return callNativeString("aid(J)Ljava/lang/String;", {(uint64_t)session});
}
std::string ZsmRuntime::sessionKey(int64_t session) {
    return callNativeString("key(J)Ljava/lang/String;", {(uint64_t)session});
}
std::string ZsmRuntime::prefix(int64_t session) {
    return callNativeString("prev(J)Ljava/lang/String;", {(uint64_t)session});
}

void ZsmRuntime::freeSession(int64_t session) {
    if (session) callNative("free(J)V", {(uint64_t)session});
}

}  // namespace ty
