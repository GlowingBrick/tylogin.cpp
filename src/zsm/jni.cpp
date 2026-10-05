// jni.cpp - fake JavaVM/JNIEnv: function-table stubs routed through the SVC
// trampoline, object model, and the 4 mocked Android calls JNI_OnLoad needs.
#include "jni.h"

#include <cstring>

namespace ty {

Jni* g_jni = nullptr;

// canonical JNINativeInterface slot order (jni.h); names used for logging
enum JniIdx {
    JNI_GetVersion = 4,
    JNI_DefineClass = 5,
    JNI_FindClass = 6,
    JNI_FromReflectedMethod = 7,
    JNI_FromReflectedField = 8,
    JNI_ToReflectedMethod = 9,
    JNI_GetSuperclass = 10,
    JNI_IsAssignableFrom = 11,
    JNI_ToReflectedField = 12,
    JNI_Throw = 13,
    JNI_ThrowNew = 14,
    JNI_ExceptionOccurred = 15,
    JNI_ExceptionDescribe = 16,
    JNI_ExceptionClear = 17,
    JNI_FatalError = 18,
    JNI_PushLocalFrame = 19,
    JNI_PopLocalFrame = 20,
    JNI_NewGlobalRef = 21,
    JNI_DeleteGlobalRef = 22,
    JNI_DeleteLocalRef = 23,
    JNI_IsSameObject = 24,
    JNI_NewLocalRef = 25,
    JNI_EnsureLocalCapacity = 26,
    JNI_AllocObject = 27,
    JNI_NewObject = 28,
    JNI_NewObjectV = 29,
    JNI_NewObjectA = 30,
    JNI_GetObjectClass = 31,
    JNI_IsInstanceOf = 32,
    JNI_GetMethodID = 33,
    JNI_CallObjectMethod = 34,
    JNI_CallObjectMethodV = 35,
    JNI_CallObjectMethodA = 36,
    JNI_CallBooleanMethod = 37,
    JNI_CallBooleanMethodV = 38,
    JNI_CallBooleanMethodA = 39,
    JNI_CallByteMethod = 40,
    JNI_CallByteMethodV = 41,
    JNI_CallByteMethodA = 42,
    JNI_CallCharMethod = 43,
    JNI_CallCharMethodV = 44,
    JNI_CallCharMethodA = 45,
    JNI_CallShortMethod = 46,
    JNI_CallShortMethodV = 47,
    JNI_CallShortMethodA = 48,
    JNI_CallIntMethod = 49,
    JNI_CallIntMethodV = 50,
    JNI_CallIntMethodA = 51,
    JNI_CallLongMethod = 52,
    JNI_CallLongMethodV = 53,
    JNI_CallLongMethodA = 54,
    JNI_CallFloatMethod = 55,
    JNI_CallFloatMethodV = 56,
    JNI_CallFloatMethodA = 57,
    JNI_CallDoubleMethod = 58,
    JNI_CallDoubleMethodV = 59,
    JNI_CallDoubleMethodA = 60,
    JNI_CallVoidMethod = 61,
    JNI_CallVoidMethodV = 62,
    JNI_CallVoidMethodA = 63,
    JNI_CallNonvirtualObjectMethod = 64,
    JNI_CallNonvirtualObjectMethodV = 65,
    JNI_CallNonvirtualObjectMethodA = 66,
    JNI_CallNonvirtualBooleanMethod = 67,
    JNI_CallNonvirtualBooleanMethodV = 68,
    JNI_CallNonvirtualBooleanMethodA = 69,
    JNI_CallNonvirtualByteMethod = 70,
    JNI_CallNonvirtualByteMethodV = 71,
    JNI_CallNonvirtualByteMethodA = 72,
    JNI_CallNonvirtualCharMethod = 73,
    JNI_CallNonvirtualCharMethodV = 74,
    JNI_CallNonvirtualCharMethodA = 75,
    JNI_CallNonvirtualShortMethod = 76,
    JNI_CallNonvirtualShortMethodV = 77,
    JNI_CallNonvirtualShortMethodA = 78,
    JNI_CallNonvirtualIntMethod = 79,
    JNI_CallNonvirtualIntMethodV = 80,
    JNI_CallNonvirtualIntMethodA = 81,
    JNI_CallNonvirtualLongMethod = 82,
    JNI_CallNonvirtualLongMethodV = 83,
    JNI_CallNonvirtualLongMethodA = 84,
    JNI_CallNonvirtualFloatMethod = 85,
    JNI_CallNonvirtualFloatMethodV = 86,
    JNI_CallNonvirtualFloatMethodA = 87,
    JNI_CallNonvirtualDoubleMethod = 88,
    JNI_CallNonvirtualDoubleMethodV = 89,
    JNI_CallNonvirtualDoubleMethodA = 90,
    JNI_CallNonvirtualVoidMethod = 91,
    JNI_CallNonvirtualVoidMethodV = 92,
    JNI_CallNonvirtualVoidMethodA = 93,
    JNI_GetFieldID = 94,
    JNI_GetObjectField = 95,
    JNI_GetBooleanField = 96,
    JNI_GetByteField = 97,
    JNI_GetCharField = 98,
    JNI_GetShortField = 99,
    JNI_GetIntField = 100,
    JNI_GetLongField = 101,
    JNI_GetFloatField = 102,
    JNI_GetDoubleField = 103,
    JNI_SetObjectField = 104,
    JNI_SetBooleanField = 105,
    JNI_SetByteField = 106,
    JNI_SetCharField = 107,
    JNI_SetShortField = 108,
    JNI_SetIntField = 109,
    JNI_SetLongField = 110,
    JNI_SetFloatField = 111,
    JNI_SetDoubleField = 112,
    JNI_GetStaticMethodID = 113,
    JNI_CallStaticObjectMethod = 114,
    JNI_CallStaticObjectMethodV = 115,
    JNI_CallStaticObjectMethodA = 116,
    JNI_CallStaticBooleanMethod = 117,
    JNI_CallStaticBooleanMethodV = 118,
    JNI_CallStaticBooleanMethodA = 119,
    JNI_CallStaticByteMethod = 120,
    JNI_CallStaticByteMethodV = 121,
    JNI_CallStaticByteMethodA = 122,
    JNI_CallStaticCharMethod = 123,
    JNI_CallStaticCharMethodV = 124,
    JNI_CallStaticCharMethodA = 125,
    JNI_CallStaticShortMethod = 126,
    JNI_CallStaticShortMethodV = 127,
    JNI_CallStaticShortMethodA = 128,
    JNI_CallStaticIntMethod = 129,
    JNI_CallStaticIntMethodV = 130,
    JNI_CallStaticIntMethodA = 131,
    JNI_CallStaticLongMethod = 132,
    JNI_CallStaticLongMethodV = 133,
    JNI_CallStaticLongMethodA = 134,
    JNI_CallStaticFloatMethod = 135,
    JNI_CallStaticFloatMethodV = 136,
    JNI_CallStaticFloatMethodA = 137,
    JNI_CallStaticDoubleMethod = 138,
    JNI_CallStaticDoubleMethodV = 139,
    JNI_CallStaticDoubleMethodA = 140,
    JNI_CallStaticVoidMethod = 141,
    JNI_CallStaticVoidMethodV = 142,
    JNI_CallStaticVoidMethodA = 143,
    JNI_GetStaticFieldID = 144,
    JNI_GetStaticObjectField = 145,
    JNI_GetStaticBooleanField = 146,
    JNI_GetStaticByteField = 147,
    JNI_GetStaticCharField = 148,
    JNI_GetStaticShortField = 149,
    JNI_GetStaticIntField = 150,
    JNI_GetStaticLongField = 151,
    JNI_GetStaticFloatField = 152,
    JNI_GetStaticDoubleField = 153,
    JNI_SetStaticObjectField = 154,
    JNI_SetStaticBooleanField = 155,
    JNI_SetStaticByteField = 156,
    JNI_SetStaticCharField = 157,
    JNI_SetStaticShortField = 158,
    JNI_SetStaticIntField = 159,
    JNI_SetStaticLongField = 160,
    JNI_SetStaticFloatField = 161,
    JNI_SetStaticDoubleField = 162,
    JNI_NewString = 163,
    JNI_GetStringLength = 164,
    JNI_GetStringChars = 165,
    JNI_ReleaseStringChars = 166,
    JNI_NewStringUTF = 167,
    JNI_GetStringUTFLength = 168,
    JNI_GetStringUTFChars = 169,
    JNI_ReleaseStringUTFChars = 170,
    JNI_GetArrayLength = 171,
    JNI_NewObjectArray = 172,
    JNI_GetObjectArrayElement = 173,
    JNI_SetObjectArrayElement = 174,
    JNI_NewBooleanArray = 175,
    JNI_NewByteArray = 176,
    JNI_NewCharArray = 177,
    JNI_NewShortArray = 178,
    JNI_NewIntArray = 179,
    JNI_NewLongArray = 180,
    JNI_NewFloatArray = 181,
    JNI_NewDoubleArray = 182,
    JNI_GetBooleanArrayElements = 183,
    JNI_GetByteArrayElements = 184,
    JNI_GetCharArrayElements = 185,
    JNI_GetShortArrayElements = 186,
    JNI_GetIntArrayElements = 187,
    JNI_GetLongArrayElements = 188,
    JNI_GetFloatArrayElements = 189,
    JNI_GetDoubleArrayElements = 190,
    JNI_ReleaseBooleanArrayElements = 191,
    JNI_ReleaseByteArrayElements = 192,
    JNI_ReleaseCharArrayElements = 193,
    JNI_ReleaseShortArrayElements = 194,
    JNI_ReleaseIntArrayElements = 195,
    JNI_ReleaseLongArrayElements = 196,
    JNI_ReleaseFloatArrayElements = 197,
    JNI_ReleaseDoubleArrayElements = 198,
    JNI_GetBooleanArrayRegion = 199,
    JNI_GetByteArrayRegion = 200,
    JNI_GetCharArrayRegion = 201,
    JNI_GetShortArrayRegion = 202,
    JNI_GetIntArrayRegion = 203,
    JNI_GetLongArrayRegion = 204,
    JNI_GetFloatArrayRegion = 205,
    JNI_GetDoubleArrayRegion = 206,
    JNI_SetBooleanArrayRegion = 207,
    JNI_SetByteArrayRegion = 208,
    JNI_SetCharArrayRegion = 209,
    JNI_SetShortArrayRegion = 210,
    JNI_SetIntArrayRegion = 211,
    JNI_SetLongArrayRegion = 212,
    JNI_SetFloatArrayRegion = 213,
    JNI_SetDoubleArrayRegion = 214,
    JNI_RegisterNatives = 215,
    JNI_UnregisterNatives = 216,
    JNI_MonitorEnter = 217,
    JNI_MonitorExit = 218,
    JNI_GetJavaVM = 219,
    JNI_GetStringRegion = 220,
    JNI_GetStringUTFRegion = 221,
    JNI_GetPrimitiveArrayCritical = 222,
    JNI_ReleasePrimitiveArrayCritical = 223,
    JNI_GetStringCritical = 224,
    JNI_ReleaseStringCritical = 225,
    JNI_NewWeakGlobalRef = 226,
    JNI_DeleteWeakGlobalRef = 227,
    JNI_ExceptionCheck = 228,
    JNI_NewDirectByteBuffer = 229,
    JNI_GetDirectBufferAddress = 230,
    JNI_GetDirectBufferCapacity = 231,
    JNI_GetObjectRefType = 232,
};

enum JvmIdx {
    JVM_DestroyJavaVM = 3,
    JVM_AttachCurrentThread = 4,
    JVM_DetachCurrentThread = 5,
    JVM_GetEnv = 6,
    JVM_AttachCurrentThreadAsDaemon = 7,
};

static const char* jniSlotName(int idx) {
    static const char* names[] = {
        "reserved0", "reserved1", "reserved2", "reserved3", "GetVersion", "DefineClass",
        "FindClass", "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod",
        "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew",
        "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError",
        "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef",
        "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity",
        "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass",
        "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV",
        "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV",
        "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA",
        "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod",
        "CallShortMethodV", "CallShortMethodA", "CallIntMethod", "CallIntMethodV",
        "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA",
        "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod",
        "CallDoubleMethodV", "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV",
        "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV",
        "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod",
        "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
        "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV",
        "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod",
        "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA",
        "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV",
        "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod",
        "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA",
        "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV",
        "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod",
        "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA",
        "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV",
        "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod",
        "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA", "GetFieldID",
        "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField",
        "GetShortField", "GetIntField", "GetLongField", "GetFloatField",
        "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField",
        "SetCharField", "SetShortField", "SetIntField", "SetLongField",
        "SetFloatField", "SetDoubleField", "GetStaticMethodID",
        "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
        "CallStaticBooleanMethod", "CallStaticBooleanMethodV",
        "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV",
        "CallStaticByteMethodA", "CallStaticCharMethod", "CallStaticCharMethodV",
        "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV",
        "CallStaticShortMethodA", "CallStaticIntMethod", "CallStaticIntMethodV",
        "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV",
        "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV",
        "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV",
        "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV",
        "CallStaticVoidMethodA", "GetStaticFieldID", "GetStaticObjectField",
        "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField",
        "GetStaticShortField", "GetStaticIntField", "GetStaticLongField",
        "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField",
        "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField",
        "SetStaticShortField", "SetStaticIntField", "SetStaticLongField",
        "SetStaticFloatField", "SetStaticDoubleField", "NewString", "GetStringLength",
        "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength",
        "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength",
        "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
        "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray",
        "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
        "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements",
        "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements",
        "GetFloatArrayElements", "GetDoubleArrayElements",
        "ReleaseBooleanArrayElements", "ReleaseByteArrayElements",
        "ReleaseCharArrayElements", "ReleaseShortArrayElements",
        "ReleaseIntArrayElements", "ReleaseLongArrayElements",
        "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
        "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion",
        "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion",
        "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion",
        "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion",
        "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion",
        "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives", "MonitorEnter",
        "MonitorExit", "GetJavaVM", "GetStringRegion", "GetStringUTFRegion",
        "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
        "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef",
        "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer",
        "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType",
    };
    if (idx >= 1000) {
        switch (idx - 1000) {
            case 3: return "DestroyJavaVM";
            case 4: return "AttachCurrentThread";
            case 5: return "DetachCurrentThread";
            case 6: return "GetEnv";
            case 7: return "AttachCurrentThreadAsDaemon";
            default: return "JvmUnknown";
        }
    }
    return (idx >= 0 && idx < (int)(sizeof(names) / sizeof(names[0]))) ? names[idx]
                                                                       : "JniUnknown";
}

// ------------------------------------------------------------ object model

Jni::Jni(Emu& emu, const std::string& packageName, const std::string& rootDir)
    : emu_(emu), packageName_(packageName), rootDir_(rootDir) {
    g_jni = this;
    // JavaVM: pointer -> table -> stubs
    uint64_t vmTable = VM_TABLE_ADDR;
    for (int i = 0; i < (int)STUB_JVM_SLOTS; i++) {
        uint64_t a = STUB_JVM_BASE + i * 4;
        emu_.writeMem(vmTable + i * 8, &a, 8);
    }
    emu_.writeMem(VM_PTR_ADDR, &vmTable, 8);

    // JNIEnv: pointer -> table -> stubs
    uint64_t envTable = ENV_TABLE_ADDR;
    for (int i = 0; i < (int)JNI_TABLE_SLOTS; i++) {
        uint64_t a = STUB_JNI_BASE + i * 4;
        emu_.writeMem(envTable + i * 8, &a, 8);
    }
    emu_.writeMem(ENV_PTR_ADDR, &envTable, 8);

    // __sF: 3 zeroed 256-byte FILE slots (stdin/stdout/stderr)
    // pre-create common classes
    newClass("java/lang/Object");
}

uint64_t Jni::allocObj(Obj o) {
    objs_.push_back(std::move(o));
    return OBJ_BASE + (objs_.size() - 1) * 8;
}

Jni::Obj& Jni::obj(uint64_t handle) {
    if (handle < OBJ_BASE || (handle - OBJ_BASE) % 8 != 0 ||
        (handle - OBJ_BASE) / 8 >= objs_.size())
        throw EmuError("bad jobject handle");
    return objs_[(handle - OBJ_BASE) / 8];
}

const Jni::Method& Jni::method(uint64_t mid) const {
    if (mid < METHOD_BASE || (mid - METHOD_BASE) % 8 != 0 ||
        (mid - METHOD_BASE) / 8 >= methods_.size())
        throw EmuError("bad jmethodID handle");
    return methods_[(mid - METHOD_BASE) / 8];
}

uint64_t Jni::newClass(const std::string& name) {
    for (size_t i = 0; i < objs_.size(); i++)
        if (objs_[i].kind == 1 && objs_[i].cls == name) return OBJ_BASE + i * 8;
    Obj o;
    o.kind = 1;
    o.cls = name;
    return allocObj(std::move(o));
}

uint64_t Jni::newString(const std::string& s) {
    Obj o;
    o.kind = 2;
    o.cls = "java/lang/String";
    o.str = s;
    return allocObj(std::move(o));
}

uint64_t Jni::newObject(const std::string& cls, const std::string& payload) {
    Obj o;
    o.kind = 0;
    o.cls = cls;
    o.str = payload;
    return allocObj(std::move(o));
}

uint64_t Jni::newByteArray(const void* data, size_t len) {
    Obj o;
    o.kind = 3;
    o.cls = "[B";
    o.len = len;
    if (len) {
        o.buf = emu_.gmalloc(len);
        emu_.writeMem(o.buf, data, len);
    } else {
        o.buf = emu_.gmalloc(1);
    }
    return allocObj(std::move(o));
}

uint64_t Jni::newObjectArray(const std::vector<uint64_t>& elems) {
    Obj o;
    o.kind = 4;
    o.cls = "[Ljava/lang/String;";
    o.elems = elems;
    return allocObj(std::move(o));
}

std::string Jni::getString(uint64_t h) { return obj(h).str; }

std::vector<uint8_t> Jni::getByteArray(uint64_t h) {
    Obj& o = obj(h);
    std::vector<uint8_t> v(o.len);
    if (o.len) emu_.readMem(o.buf, v.data(), o.len);
    return v;
}

size_t Jni::getArrayLength(uint64_t h) {
    Obj& o = obj(h);
    return o.kind == 3 ? o.len : o.elems.size();
}

// ------------------------------------------------------------ dispatch

uint64_t Jni::callObjectMethodImpl(uint64_t objH, uint64_t mid) {
    Obj& o = obj(objH);
    const Method& m = method(mid);
    logDbg("[jni] Call %s->%s", o.cls.c_str(), m.name.c_str());
    if (m.name == "getFilesDir") {
        std::string cls = "java/io/File";
        return newObject(cls, rootDir_);
    }
    if (m.name == "getAbsolutePath") return newString(o.str);
    if (m.name == "getPackageName" || m.name == "currentPackageName")
        return newString(packageName_);
    logRaw("[jni] unhandled object method: %s->%s%s", o.cls.c_str(), m.name.c_str(),
           m.sig.c_str());
    return 0;
}

uint64_t Jni::dispatch(int idx, const uint64_t* x) {
    if (gDebug)
        logDbg("[jni] %s x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx", jniSlotName(idx),
               (unsigned long long)x[1], (unsigned long long)x[2],
               (unsigned long long)x[3], (unsigned long long)x[4]);
    if (idx >= 1000) {  // JavaVM
        switch (idx - 1000) {
            case JVM_DestroyJavaVM:
                return 0;
            case JVM_AttachCurrentThread:
            case JVM_AttachCurrentThreadAsDaemon:
                emu_.writeMem(x[1], &ENV_PTR_ADDR, 8);
                return 0;
            case JVM_DetachCurrentThread:
                return 0;
            case JVM_GetEnv: {
                uint32_t ver = (uint32_t)x[2];  // GetEnv(vm, void** env, jint version)
                if (ver == 0x00010002 || ver == 0x00010004 || ver == 0x00010006) {
                    emu_.writeMem(x[1], &ENV_PTR_ADDR, 8);
                    return 0;
                }
                return (uint64_t)(int64_t)-2;  // JNI_EVERSION
            }
            default:
                return 0;
        }
    }

    switch (idx) {
        case JNI_GetVersion:
            return 0x00010006;
        case JNI_FindClass: {
            std::string name = emu_.readCStr(x[1]);
            uint64_t c = newClass(name);
            logDbg("[jni] FindClass(%s)", name.c_str());
            return c;
        }
        case JNI_GetSuperclass:
            return newClass("java/lang/Object");
        case JNI_IsAssignableFrom:
            return 1;
        case JNI_Throw:
        case JNI_ThrowNew:
            logRaw("[jni] ThrowNew called (ignored)");
            return 0;
        case JNI_ExceptionOccurred:
        case JNI_ExceptionCheck:
            return 0;
        case JNI_ExceptionDescribe:
        case JNI_ExceptionClear:
            return 0;
        case JNI_FatalError:
            throw EmuError("JNI FatalError: " + emu_.readCStr(x[1]));
        case JNI_PushLocalFrame:
            return 0;
        case JNI_PopLocalFrame:
            return x[1];
        case JNI_NewGlobalRef:
        case JNI_NewLocalRef:
            return x[1];
        case JNI_DeleteGlobalRef:
        case JNI_DeleteLocalRef:
        case JNI_DeleteWeakGlobalRef:
        case JNI_NewWeakGlobalRef:
            return 0;
        case JNI_IsSameObject:
            return x[1] == x[2] ? 1 : 0;
        case JNI_EnsureLocalCapacity:
            return 0;
        case JNI_AllocObject: {
            Obj& c = obj(x[1]);
            return newObject(c.cls, "");
        }
        case JNI_NewObject:
        case JNI_NewObjectV:
        case JNI_NewObjectA: {
            Obj& c = obj(x[1]);
            return newObject(c.cls, "");
        }
        case JNI_GetObjectClass: {
            Obj& o = obj(x[1]);
            return newClass(o.cls);
        }
        case JNI_IsInstanceOf:
            return 1;
        case JNI_GetMethodID:
        case JNI_GetStaticMethodID: {
            std::string cls = obj(x[1]).cls;
            std::string name = emu_.readCStr(x[2]);
            std::string sig = emu_.readCStr(x[3]);
            methods_.push_back({cls, name, sig});
            uint64_t mid = METHOD_BASE + (methods_.size() - 1) * 8;
            logDbg("[jni] %s(%s.%s%s) = 0x%llx",
                   idx == JNI_GetMethodID ? "GetMethodID" : "GetStaticMethodID",
                   cls.c_str(), name.c_str(), sig.c_str(), (unsigned long long)mid);
            return mid;
        }
        case JNI_CallObjectMethod:
        case JNI_CallObjectMethodV:
        case JNI_CallObjectMethodA:
            return callObjectMethodImpl(x[1], x[2]);
        case JNI_CallBooleanMethod:
        case JNI_CallBooleanMethodV:
        case JNI_CallBooleanMethodA:
            return 0;
        case JNI_CallVoidMethod:
        case JNI_CallVoidMethodV:
        case JNI_CallVoidMethodA:
        case JNI_CallIntMethod:
        case JNI_CallIntMethodV:
        case JNI_CallIntMethodA:
        case JNI_CallLongMethod:
        case JNI_CallLongMethodV:
        case JNI_CallLongMethodA:
            logDbg("[jni] unhandled Call*Method idx=%d", idx);
            return 0;
        case JNI_CallStaticObjectMethod:
        case JNI_CallStaticObjectMethodV:
        case JNI_CallStaticObjectMethodA: {
            const Method& m = method(x[2]);
            logDbg("[jni] CallStatic %s->%s", m.cls.c_str(), m.name.c_str());
            if (m.name == "currentPackageName") return newString(packageName_);
            if (m.name == "currentApplication") {
                // class chain ContextWrapper <- Context must resolve for later
                // GetObjectClass/getFilesDir calls
                newClass("android/content/Context");
                newClass("android/content/ContextWrapper");
                return newObject("android/app/Application", "");
            }
            logRaw("[jni] unhandled static method: %s->%s%s", m.cls.c_str(),
                   m.name.c_str(), m.sig.c_str());
            return 0;
        }
        case JNI_GetFieldID:
        case JNI_GetStaticFieldID: {
            std::string name = emu_.readCStr(x[2]);
            logDbg("[jni] Get*FieldID(%s)", name.c_str());
            return FIELD_BASE;  // generic field handle
        }
        case JNI_GetObjectField:
        case JNI_GetStaticObjectField:
            return 0;
        case JNI_GetStaticIntField:
        case JNI_GetIntField:
            return 0;
        case JNI_GetStaticBooleanField:
        case JNI_GetBooleanField:
            return 0;
        case JNI_NewStringUTF: {
            std::string s = emu_.readCStr(x[1]);
            return newString(s);
        }
        case JNI_GetStringLength:
            return obj(x[1]).str.size();  // approx: UTF-16 len ~= utf8 len for ascii
        case JNI_GetStringChars: {
            // return UTF-16LE buffer + isCopy=0
            std::string s = obj(x[1]).str;
            size_t n = s.size() * 2 + 2;
            uint64_t p = emu_.gmalloc(n);
            std::vector<uint8_t> b(n, 0);
            for (size_t i = 0; i < s.size(); i++) b[i * 2] = s[i];
            emu_.writeMem(p, b.data(), n);
            return p;
        }
        case JNI_ReleaseStringChars:
            emu_.gfree(x[1]);
            return 0;
        case JNI_GetStringUTFLength:
            return obj(x[1]).str.size();
        case JNI_GetStringUTFChars: {
            std::string s = obj(x[1]).str;
            uint64_t p = emu_.gmalloc(s.size() + 1);
            emu_.writeMem(p, s.c_str(), s.size() + 1);
            if (x[2]) {
                uint32_t isCopy = 0;
                emu_.writeMem(x[2], &isCopy, 4);
            }
            return p;
        }
        case JNI_ReleaseStringUTFChars:
            emu_.gfree(x[2]);
            return 0;
        case JNI_GetStringRegion:
        case JNI_GetStringUTFRegion: {
            Obj& o = obj(x[1]);
            size_t start = x[2], len = x[3];
            if (start <= o.str.size()) {
                std::string sub = o.str.substr(start, len);
                emu_.writeMem(x[4], sub.data(), sub.size());
            }
            return 0;
        }
        case JNI_GetArrayLength:
            return getArrayLength(x[1]);
        case JNI_NewByteArray: {
            Obj o;
            o.kind = 3;
            o.cls = "[B";
            o.len = x[1];
            o.buf = emu_.gmalloc(o.len ? o.len : 1);
            if (o.len) memset(emu_.hostPtr(o.buf, o.len), 0, o.len);
            return allocObj(std::move(o));
        }
        case JNI_GetByteArrayElements:
        case JNI_GetPrimitiveArrayCritical: {
            Obj& o = obj(x[1]);
            if (x[2]) {
                uint32_t isCopy = 0;
                emu_.writeMem(x[2], &isCopy, 4);
            }
            return o.buf;
        }
        case JNI_ReleaseByteArrayElements:
        case JNI_ReleasePrimitiveArrayCritical:
            return 0;
        case JNI_GetByteArrayRegion: {
            Obj& o = obj(x[1]);
            size_t start = x[2], len = x[3];
            if (start + len <= o.len && len)
                emu_.writeMem(x[4], emu_.hostPtr(o.buf + start, len), len);
            return 0;
        }
        case JNI_SetByteArrayRegion: {
            Obj& o = obj(x[1]);
            size_t start = x[2], len = x[3];
            if (start + len <= o.len && len)
                memcpy(emu_.hostPtr(o.buf + start, len), emu_.hostPtr(x[4], len), len);
            return 0;
        }
        case JNI_NewObjectArray: {
            Obj o;
            o.kind = 4;
            o.cls = "[Ljava/lang/Object;";
            return allocObj(std::move(o));
        }
        case JNI_GetObjectArrayElement: {
            Obj& o = obj(x[1]);
            if (x[2] < o.elems.size()) return o.elems[x[2]];
            return 0;
        }
        case JNI_SetObjectArrayElement: {
            Obj& o = obj(x[1]);
            if (x[2] >= o.elems.size()) o.elems.resize(x[2] + 1, 0);
            o.elems[x[2]] = x[3];
            return 0;
        }
        case JNI_RegisterNatives: {
            Obj& c = obj(x[1]);
            uint32_t n = (uint32_t)x[3];
            struct JNM {
                const char* name;
                const char* sig;
                void* fn;
            };
            for (uint32_t i = 0; i < n; i++) {
                JNM m;
                emu_.readMem(x[2] + i * sizeof(JNM), &m, sizeof(m));
                std::string name = emu_.readCStr((uint64_t)m.name);
                std::string sig = emu_.readCStr((uint64_t)m.sig);
                std::string key = name + sig;
                natives_[key] = (uint64_t)m.fn;
                logDbg("[jni] RegisterNatives %s.%s%s -> 0x%llx", c.cls.c_str(),
                       name.c_str(), sig.c_str(), (unsigned long long)(uint64_t)m.fn);
            }
            if (c.cls.find("DaMod") != std::string::npos) daModClass_ = x[1];
            return 0;
        }
        case JNI_UnregisterNatives:
            return 0;
        case JNI_MonitorEnter:
        case JNI_MonitorExit:
            return 0;
        case JNI_GetJavaVM:
            emu_.writeMem(x[1], &VM_PTR_ADDR, 8);
            return 0;
        case JNI_NewDirectByteBuffer:
            return newObject("java/nio/ByteBuffer", "");
        case JNI_GetDirectBufferAddress:
        case JNI_GetDirectBufferCapacity:
            return 0;
        case JNI_GetObjectRefType:
            return 1;  // local ref
        default:
            logRaw("[jni] UNIMPLEMENTED slot %d (%s) -> 0", idx, jniSlotName(idx));
            return 0;
    }
}

// bridge used by Emu::resume for JNI/JVM stub hits (single instance per process)
uint64_t jniDispatch(Emu& emu, int idx, const uint64_t* x) {
    (void)emu;
    if (!g_jni) throw EmuError("JNI dispatch without bound Jni instance");
    return g_jni->dispatch(idx, x);
}

uint64_t Jni::findNative(const std::string& nameSig) const {
    auto it = natives_.find(nameSig);
    if (it != natives_.end()) return it->second;
    std::string mname = nameSig.substr(0, nameSig.find('('));
    for (auto& kv : natives_) {
        size_t p = kv.first.find('(');
        if (p != std::string::npos && kv.first.substr(0, p) == mname) return kv.second;
    }
    for (auto& kv : natives_) {
        size_t p = kv.first.find('#');
        if (p != std::string::npos && kv.first.substr(0, p) == mname) return kv.second;
    }
    return 0;
}

}  // namespace ty
