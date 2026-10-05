// jni.h - fake JNI environment (JavaVM + JNIEnv) with a tiny DVM object model
#pragma once
#include "emu.h"

namespace ty {

class Jni {
public:
    Jni(Emu& emu, const std::string& packageName, const std::string& rootDir);

    // dispatch JNIEnv (idx 0..232) / JavaVM (idx 1000..1007) calls; returns x0
    uint64_t dispatch(int idx, const uint64_t* x);

    uint64_t envPtr() const { return ENV_PTR_ADDR; }
    uint64_t vmPtr() const { return VM_PTR_ADDR; }

    // DaMod native methods captured via RegisterNatives (or Java_ exports)
    const std::unordered_map<std::string, uint64_t>& natives() const { return natives_; }
    uint64_t daModClass() const { return daModClass_; }
    void addNative(const std::string& nameSig, uint64_t fn) { natives_[nameSig] = fn; }
    // exact "name(sig)" match, else match by method name (handles Java_ export fallback)
    uint64_t findNative(const std::string& nameSig) const;

    // object helpers used by the dispatch table and the DaMod wrapper
    uint64_t newClass(const std::string& name);
    uint64_t newString(const std::string& s);
    uint64_t newObject(const std::string& cls, const std::string& payload);
    uint64_t newByteArray(const void* data, size_t len);
    uint64_t newObjectArray(const std::vector<uint64_t>& elems);
    std::string getString(uint64_t obj);
    std::vector<uint8_t> getByteArray(uint64_t obj);
    size_t getArrayLength(uint64_t obj);

private:
    struct Obj {
        std::string cls;
        int kind = 0;  // 0=object 1=class 2=string 3=bytearray 4=objarray
        std::string str;
        uint64_t buf = 0;
        size_t len = 0;
        std::vector<uint64_t> elems;
    };
    struct Method {
        std::string cls, name, sig;
    };

    uint64_t allocObj(Obj o);
    Obj& obj(uint64_t handle);
    const Method& method(uint64_t mid) const;
    uint64_t callObjectMethodImpl(uint64_t obj, uint64_t mid);

    Emu& emu_;
    std::string packageName_, rootDir_;
    std::vector<Obj> objs_;
    std::vector<Method> methods_;
    std::unordered_map<std::string, uint64_t> natives_;
    uint64_t daModClass_ = 0;
};

}  // namespace ty
