// emu.h - unicorn-backed AArch64 execution runtime for libdaproxy.so
//
// Design: the guest calls into "native" implementations (libc imports, fake
// JNI, syscalls) through SVC stubs. A UC_HOOK_INTR hook identifies the call
// site by PC, records a pending event, and stops emulation; the main loop
// (Emu::resume) dispatches the event outside of uc_emu_start, so handlers may
// freely re-enter the guest via callGuest().
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <unicorn/unicorn.h>

namespace ty {

// ---- guest memory layout ----
constexpr uint64_t STACK_BASE   = 0x00200000;
constexpr uint64_t STACK_SIZE   = 0x00800000;          // 8 MB
constexpr uint64_t SP_INIT      = STACK_BASE + STACK_SIZE - 0x1000;
constexpr uint64_t IMAGE_BASE   = 0x01000000;          // libdaproxy.so
constexpr uint64_t HEAP_BASE    = 0x10000000;          // guest malloc arena
constexpr uint64_t HEAP_SIZE    = 0x04000000;          // 64 MB
constexpr uint64_t MMAP_BASE    = 0x20000000;          // guest mmap arena
constexpr uint64_t MMAP_SIZE    = 0x08000000;          // 128 MB
constexpr uint64_t SCRATCH_BASE = 0x30000000;
constexpr uint64_t SCRATCH_SIZE = 0x00100000;

// scratch sub-ranges (SVC stub pages)
constexpr uint64_t STUB_IMPORT_BASE = SCRATCH_BASE;        // 1024 stubs * 4B
constexpr uint64_t STUB_IMPORT_MAX  = 1024;
constexpr uint64_t STUB_JNI_BASE    = SCRATCH_BASE + 0x1000; // 233 stubs * 4B
constexpr uint64_t JNI_TABLE_SLOTS  = 233;
constexpr uint64_t STUB_JVM_BASE    = SCRATCH_BASE + 0x2000; // 8 stubs * 4B
constexpr uint64_t STUB_JVM_SLOTS   = 8;
constexpr uint64_t MAGIC_RET        = SCRATCH_BASE + 0x3000;

// scratch data area
constexpr uint64_t SCRATCH_DATA     = SCRATCH_BASE + 0x10000;
constexpr uint64_t GUEST_ERRNO      = SCRATCH_DATA;          // int
constexpr uint64_t VM_PTR_ADDR      = SCRATCH_DATA + 0x100;  // holds VM_TABLE
constexpr uint64_t ENV_PTR_ADDR     = SCRATCH_DATA + 0x108;  // holds ENV_TABLE
constexpr uint64_t VM_TABLE_ADDR    = SCRATCH_DATA + 0x110;  // 8 slots
constexpr uint64_t ENV_TABLE_ADDR   = SCRATCH_DATA + 0x180;  // 233 slots
constexpr uint64_t SF_ADDR          = SCRATCH_DATA + 0x1000; // bionic __sF[3], 256B each
constexpr uint64_t SF_SIZE          = 256;

// fake handle ranges (never mapped; host-side tables only)
constexpr uint64_t OBJ_BASE    = 0x50000000;   // jobject / jclass
constexpr uint64_t METHOD_BASE = 0x51000000;   // jmethodID
constexpr uint64_t FIELD_BASE  = 0x52000000;   // jfieldID

struct EmuError : std::runtime_error {
    explicit EmuError(const std::string& m) : std::runtime_error(m) {}
};
struct EmuExit {
    int code;
};

struct Event {
    enum Kind { NONE, NATIVE, JNI, JVM, SYSCALL } kind = Event::NONE;
    int idx = 0;         // stub index / jni index / syscall nr
    uint64_t resumePc = 0;
};

class Jni;  // jni.h

class Emu {
public:
    Emu();
    ~Emu();
    Emu(const Emu&) = delete;
    Emu& operator=(const Emu&) = delete;

    bool debug = false;

    // native handler: receives x[0..7] (x0..x7), returns x0
    using NativeFn = uint64_t (*)(Emu&, const uint64_t* x);
    uint64_t addImport(const std::string& name, NativeFn fn);  // returns stub addr
    const std::string& importName(int stubIdx) const { return importNames_[stubIdx]; }

    // ELF loading is a free function in elfload.h (needs Emu internals)
    std::unordered_map<std::string, uint64_t> exports;    // exported symbol -> guest addr
    std::vector<uint64_t> initRoutines;                   // DT_INIT + DT_INIT_ARRAY (absolute)
    uint64_t importStubAddr(const std::string& name) const {
        auto it = importStubs_.find(name);
        return it == importStubs_.end() ? 0 : it->second;
    }
    uint64_t imageBase() const { return IMAGE_BASE; }

    // run guest code at fn(args...) until it returns to MAGIC_RET
    uint64_t callGuest(uint64_t fn, const std::vector<uint64_t>& args);

    // main dispatch loop (drives unicorn between events)
    uint64_t resume();

    // memory access (all regions are host-backed)
    uint8_t* hostPtr(uint64_t addr, uint64_t size = 1);
    std::string readCStr(uint64_t addr, size_t maxLen = 1 << 20);
    void readMem(uint64_t addr, void* buf, size_t n);
    void writeMem(uint64_t addr, const void* buf, size_t n);
    void mapRegion(uint64_t addr, uint64_t size);

    // heap
    uint64_t gmalloc(size_t n);
    uint64_t gcalloc(size_t n);
    uint64_t grealloc(uint64_t p, size_t n);
    void gfree(uint64_t p);
    uint64_t gmallocAligned(size_t n, size_t align);
    size_t heapUsed() const { return heapUsed_; }

    // guest mmap arena
    uint64_t guestMmap(uint64_t addr, size_t len, uint64_t flags);

    // registers
    void setReg(int reg, uint64_t v);   // UC_ARM64_REG_* ids
    uint64_t getReg(int reg);
    void setArgs(const std::vector<uint64_t>& args);
    void dumpState(const char* why);

    // misc guest facilities
    uint64_t dataImport(const std::string& name);  // __sF etc -> scratch addr
    int& guestErrno() { return *reinterpret_cast<int*>(hostPtr(GUEST_ERRNO, 8)); }

    void setAbortMessage(const std::string& m) { abortMsg_ = m; }
    const std::string& abortMessage() const { return abortMsg_; }

    Event evt;  // pending event for the resume loop

private:
    friend void emuIntrHook(uc_engine*, uint64_t, void*);
    friend void emuMemHook(uc_engine*, uc_mem_type, uint64_t, int, int64_t, void*);

    struct Region {
        uint64_t addr, size;
        uint8_t* host;
    };
    bool isMapped(uint64_t addr, uint64_t size) const;

    uc_engine* uc_ = nullptr;
    std::vector<Region> regions_;
    std::vector<NativeFn> importFns_;
    std::vector<std::string> importNames_;
    std::unordered_map<std::string, uint64_t> importStubs_;  // name -> stub addr
    int nextStub_ = 0;

    // heap state
    uint64_t heapPtr_ = HEAP_BASE;
    size_t heapUsed_ = 0;

    // mmap arena state
    uint64_t mmapPtr_ = MMAP_BASE;

    int depth_ = 0;
    std::string abortMsg_;
    uint64_t timeoutUs_ = 0;
};

// registered by guestlibc.cpp
void registerGuestLibc(Emu& emu);

// logging helpers (util.h declares; keep simple here to avoid include cycles)
void logRaw(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void logDbg(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
extern bool gDebug;

}  // namespace ty
