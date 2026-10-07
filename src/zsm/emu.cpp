// emu.cpp - unicorn runtime core: main loop, SVC dispatch, memory, heap
#include "emu.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace ty {
bool gDebug = false;

static void clockPrefix() {
    time_t t = time(nullptr);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char b[32];
    strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tmv);
    fprintf(stderr, "[%s] ", b);
}

// hook entry points (defined below, used by the Emu ctor)
void emuIntrHook(uc_engine* uc, uint64_t intno, void* user);
void emuMemHook(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value,
                void* user);

void logRaw(const char* fmt, ...) {
    va_list ap;
    clockPrefix();
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void logDbg(const char* fmt, ...) {
    if (!gDebug) return;
    va_list ap;
    clockPrefix();
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// ---------------------------------------------------------------- setup

Emu::Emu() {
    uc_err e = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc_);
    if (e != UC_ERR_OK) throw EmuError(std::string("uc_open: ") + uc_strerror(e));

    mapRegion(STACK_BASE, STACK_SIZE);
    mapRegion(HEAP_BASE, HEAP_SIZE);
    mapRegion(MMAP_BASE, MMAP_SIZE);
    mapRegion(SCRATCH_BASE, SCRATCH_SIZE);

    // SVC stubs: fill the whole stub area (imports + JNI + JVM + gaps) with
    // `svc #0` (0xD4000001); stub hits are identified by PC range.
    for (uint64_t a = STUB_IMPORT_BASE; a < SCRATCH_BASE + 0x4000; a += 4) {
        uint32_t svc = 0xD4000001;
        memcpy(hostPtr(a, 4), &svc, 4);
    }

    {
        uc_hook h = 0;
        uc_hook_add(uc_, &h, UC_HOOK_INTR, (void*)emuIntrHook, this, 1, 0);
        uc_hook_add(uc_, &h, UC_HOOK_MEM_INVALID, (void*)emuMemHook, this, 1, 0);
    }

    // guest errno
    memset(hostPtr(GUEST_ERRNO, 8), 0, 8);

    // bionic AArch64 TLS: TPIDR_EL0 points at the slot array (slot N = tp+N*8).
    // slot 0 = pthread self, slot 5 = stack guard (offset 0x28).
    constexpr uint64_t TLS_ADDR = SCRATCH_DATA + 0x2000;
    memset(hostPtr(TLS_ADDR, 256), 0, 256);
    uint64_t self = TLS_ADDR;
    uint64_t guard = 0xDEADBEEF12345678ull;
    writeMem(TLS_ADDR + 0, &self, 8);
    writeMem(TLS_ADDR + 5 * 8, &guard, 8);
    setReg(UC_ARM64_REG_TPIDR_EL0, TLS_ADDR);
    setReg(UC_ARM64_REG_TPIDRRO_EL0, TLS_ADDR);

    // watchdog: one uc_emu_start segment (between SVC stops) should never take
    // minutes; a runaway guest loop must not hang the daemon forever
    timeoutUs_ = 60ull * 1000000ull;
    const char* t = getenv("TY_EMU_TIMEOUT");
    if (t) timeoutUs_ = strtoull(t, nullptr, 10) * 1000000ull;
}

Emu::~Emu() {
    if (uc_) uc_close(uc_);
    for (auto& r : regions_) {
#ifdef _WIN32
        VirtualFree(r.host, 0, MEM_RELEASE);
#else
        munmap(r.host, r.size);
#endif
    }
}

void Emu::mapRegion(uint64_t addr, uint64_t size) {
    size = (size + 0xFFF) & ~0xFFFull;
    void* p;
#ifdef _WIN32
    p = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) throw EmuError("host VirtualAlloc failed");
#else
    p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) throw EmuError("host mmap failed");
#endif
    uc_err e = uc_mem_map_ptr(uc_, addr, size, UC_PROT_ALL, p);
    if (e != UC_ERR_OK) throw EmuError(std::string("uc_mem_map_ptr: ") + uc_strerror(e));
    regions_.push_back({addr, size, (uint8_t*)p});
}

bool Emu::isMapped(uint64_t addr, uint64_t size) const {
    for (auto& r : regions_)
        if (addr >= r.addr && addr + size <= r.addr + r.size) return true;
    return false;
}

uint8_t* Emu::hostPtr(uint64_t addr, uint64_t size) {
    for (auto& r : regions_)
        if (addr >= r.addr && size <= r.size && addr - r.addr <= r.size - size)
            return r.host + (addr - r.addr);
    throw EmuError("hostPtr: unmapped guest address 0x" + [&] {
        char b[32];
        snprintf(b, sizeof(b), "%llx", (unsigned long long)addr);
        return std::string(b);
    }());
}

void Emu::readMem(uint64_t addr, void* buf, size_t n) {
    memcpy(buf, hostPtr(addr, n ? n : 1), n);
}
void Emu::writeMem(uint64_t addr, const void* buf, size_t n) {
    memcpy(hostPtr(addr, n ? n : 1), buf, n);
}

std::string Emu::readCStr(uint64_t addr, size_t maxLen) {
    for (auto& r : regions_) {
        if (addr >= r.addr && addr < r.addr + r.size) {
            const uint8_t* p = r.host + (addr - r.addr);
            size_t avail = r.size - (addr - r.addr);
            size_t n = strnlen((const char*)p, avail < maxLen ? avail : maxLen);
            return std::string((const char*)p, n);
        }
    }
    throw EmuError("readCStr: unmapped guest address");
}

// ---------------------------------------------------------------- registers

void Emu::setReg(int reg, uint64_t v) { uc_reg_write(uc_, (uc_arm64_reg)reg, &v); }
uint64_t Emu::getReg(int reg) {
    uint64_t v = 0;
    uc_reg_read(uc_, (uc_arm64_reg)reg, &v);
    return v;
}

void Emu::setArgs(const std::vector<uint64_t>& args) {
    static const int regs[8] = {UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                UC_ARM64_REG_X6, UC_ARM64_REG_X7};
    for (int i = 0; i < 8; i++) setReg(regs[i], i < (int)args.size() ? args[i] : 0);
}

// ---------------------------------------------------------------- hooks

void emuIntrHook(uc_engine* uc, uint64_t intno, void* user) {
    Emu& e = *(Emu*)user;
    uint64_t pc = 0, lr = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    if (intno != 2) {
        fprintf(stderr, "[intr] non-SVC exception intno=%llu pc=0x%llx\n",
                (unsigned long long)intno, (unsigned long long)pc);
        return;
    }

    // unicorn reports PC = SVC + 4 (ELR semantics): the stub slot index must be
    // derived from pc-4; a real syscall resumes at pc itself (next instruction).
    if (pc >= STUB_IMPORT_BASE + 4 && pc < STUB_IMPORT_BASE + STUB_IMPORT_MAX * 4) {
        e.evt = {Event::NATIVE, (int)((pc - 4 - STUB_IMPORT_BASE) / 4), lr};
    } else if (pc >= STUB_JNI_BASE + 4 && pc < STUB_JNI_BASE + JNI_TABLE_SLOTS * 4) {
        e.evt = {Event::JNI, (int)((pc - 4 - STUB_JNI_BASE) / 4), lr};
    } else if (pc >= STUB_JVM_BASE + 4 && pc < STUB_JVM_BASE + STUB_JVM_SLOTS * 4) {
        e.evt = {Event::JVM, (int)((pc - 4 - STUB_JVM_BASE) / 4), lr};
    } else {
        e.evt = {Event::SYSCALL, 0, pc};
    }
    uc_emu_stop(uc);
}

void emuMemHook(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value,
                void* user) {
    Emu& e = *(Emu*)user;
    uint64_t pc = e.getReg(UC_ARM64_REG_PC);
    fprintf(stderr, "[emu] invalid memory: type=%d addr=0x%llx size=%d pc=0x%llx\n", type,
            (unsigned long long)addr, size, (unsigned long long)pc);
    (void)uc; (void)value;
}

// ---------------------------------------------------------------- main loop

uint64_t Emu::resume() {
    static const int X0 = UC_ARM64_REG_X0, PC = UC_ARM64_REG_PC;
    for (;;) {
        evt = Event{};
        uint64_t pc = getReg(PC);
        uc_err err = uc_emu_start(uc_, pc, MAGIC_RET, timeoutUs_, 0);
        pc = getReg(PC);
        if (pc == MAGIC_RET) return getReg(X0);
        if (err != UC_ERR_OK) {
            dumpState("emu fault");
            throw EmuError(std::string("uc_emu_start: ") + uc_strerror(err));
        }
        switch (evt.kind) {
            case Event::NATIVE: {
                if (evt.idx >= (int)importFns_.size() || !importFns_[evt.idx])
                    throw EmuError("call to unregistered import #" + std::to_string(evt.idx));
                if (gDebug) {
                    uint64_t a[8];
                    for (int i = 0; i < 8; i++)
                        a[i] = getReg(UC_ARM64_REG_X0 + i);
                    logDbg("[libc] %s(0x%llx, 0x%llx, 0x%llx, 0x%llx)", importNames_[evt.idx].c_str(),
                           (unsigned long long)a[0], (unsigned long long)a[1],
                           (unsigned long long)a[2], (unsigned long long)a[3]);
                }
                uint64_t x[8];
                for (int i = 0; i < 8; i++) x[i] = getReg(UC_ARM64_REG_X0 + i);
                uint64_t ret = importFns_[evt.idx](*this, x);
                setReg(X0, ret);
                setReg(PC, evt.resumePc);
                break;
            }
            case Event::JNI:
            case Event::JVM: {
                extern uint64_t jniDispatch(Emu&, int idx, const uint64_t* x);
                uint64_t x[8];
                for (int i = 0; i < 8; i++) x[i] = getReg(UC_ARM64_REG_X0 + i);
                int idx = (evt.kind == Event::JVM) ? evt.idx + 1000 : evt.idx;
                uint64_t ret = jniDispatch(*this, idx, x);
                setReg(X0, ret);
                setReg(PC, evt.resumePc);
                break;
            }
            case Event::SYSCALL: {
                extern uint64_t guestSyscall(Emu&, const uint64_t* x);
                uint64_t x[9];  // x0..x8 (x8 = syscall nr)
                for (int i = 0; i < 9; i++) x[i] = getReg(UC_ARM64_REG_X0 + i);
                uint64_t ret = guestSyscall(*this, x);
                setReg(X0, ret);
                setReg(PC, evt.resumePc);
                break;
            }
            default:
                dumpState("spurious emu stop");
                throw EmuError("emulation stopped without event at pc=0x" +
                               std::to_string(pc));
        }
    }
}

uint64_t Emu::callGuest(uint64_t fn, const std::vector<uint64_t>& args) {
    depth_++;
    struct DepthGuard {
        int& d;
        ~DepthGuard() { d--; }
    } dg{depth_};

    uint64_t savedSp = getReg(UC_ARM64_REG_SP);
    uint64_t sp = (depth_ == 1) ? SP_INIT : savedSp - 0x400;
    setArgs(args);
    setReg(UC_ARM64_REG_SP, sp);
    setReg(UC_ARM64_REG_LR, MAGIC_RET);
    setReg(UC_ARM64_REG_PC, fn);
    uint64_t ret = resume();
    setReg(UC_ARM64_REG_SP, savedSp);  // interrupted frame keeps its sp-relative locals
    return ret;
}

void Emu::dumpState(const char* why) {
    fprintf(stderr, "[emu] ---- fault: %s ----\n", why);
    if (!abortMsg_.empty()) fprintf(stderr, "[emu] abort message: %s\n", abortMsg_.c_str());
    // NOTE: UC_ARM64_REG_X0..X28 are contiguous but X29/X30 are NOT (V0..V31
    // sits in between) - read FP/LR explicitly instead of X0+29/X0+30.
    for (int i = 0; i < 29; i++) {
        uint64_t v = getReg(UC_ARM64_REG_X0 + i);
        fprintf(stderr, "  x%d=0x%llx%s", i, (unsigned long long)v,
                (i % 4 == 3) ? "\n" : "  ");
    }
    fprintf(stderr, "\n  fp=0x%llx lr=0x%llx pc=0x%llx sp=0x%llx\n",
            (unsigned long long)getReg(UC_ARM64_REG_FP),
            (unsigned long long)getReg(UC_ARM64_REG_LR),
            (unsigned long long)getReg(UC_ARM64_REG_PC),
            (unsigned long long)getReg(UC_ARM64_REG_SP));
}

// ---------------------------------------------------------------- imports

uint64_t Emu::addImport(const std::string& name, NativeFn fn) {
    auto it = importStubs_.find(name);
    if (it != importStubs_.end()) return it->second;  // versioned dupes collapse
    if (nextStub_ >= STUB_IMPORT_MAX) throw EmuError("too many import stubs");
    uint64_t addr = STUB_IMPORT_BASE + nextStub_ * 4;
    importFns_.push_back(fn);
    importNames_.push_back(name);
    importStubs_[name] = addr;
    nextStub_++;
    return addr;
}

uint64_t Emu::dataImport(const std::string& name) {
    // currently only __sF is referenced as data
    if (name == "__sF") return SF_ADDR;
    logRaw("[emu] warning: unknown data import '%s', returning scratch", name.c_str());
    return SCRATCH_DATA + 0x8000;
}

// ---------------------------------------------------------------- heap

struct HeapHdr {
    uint64_t size;   // payload size
    uint32_t used;
    uint32_t magic;  // 0x1DEA
};

static constexpr uint64_t HDR_SIZE = sizeof(HeapHdr);

uint64_t Emu::gmallocAligned(size_t n, size_t align) {
    if (n == 0) n = 1;
    if (align < 16) align = 16;
    // first-fit scan
    uint64_t p = HEAP_BASE;
    while (p + HDR_SIZE + n < HEAP_BASE + HEAP_SIZE) {
        HeapHdr h;
        memcpy(&h, hostPtr(p, HDR_SIZE), HDR_SIZE);
        if (h.magic == 0x1DEA && !h.used) {
            uint64_t payload = p + HDR_SIZE;
            uint64_t aligned = (payload + align - 1) & ~(uint64_t)(align - 1);
            if (aligned + n <= p + HDR_SIZE + h.size) {
                h.used = 1;
                memcpy(hostPtr(p, HDR_SIZE), &h, HDR_SIZE);
                heapUsed_ += n;
                return aligned;
            }
        }
        if (h.magic != 0x1DEA) break;  // reached virgin area
        p += HDR_SIZE + ((h.size + 15) & ~15ull);
    }
    // carve new chunk at heapPtr_
    uint64_t payload = heapPtr_ + HDR_SIZE;
    uint64_t aligned = (payload + align - 1) & ~(uint64_t)(align - 1);
    uint64_t need = (aligned + n) - heapPtr_;
    need = (need + 15) & ~15ull;
    if (heapPtr_ + need > HEAP_BASE + HEAP_SIZE)
        throw EmuError("guest heap exhausted (" + std::to_string(heapUsed_) + " bytes used)");
    HeapHdr h{need - HDR_SIZE, 1, 0x1DEA};
    memcpy(hostPtr(heapPtr_, HDR_SIZE), &h, HDR_SIZE);
    heapPtr_ += need;
    heapUsed_ += n;
    return aligned;
}

uint64_t Emu::gmalloc(size_t n) { return gmallocAligned(n, 16); }

uint64_t Emu::gcalloc(size_t n) {
    uint64_t p = gmalloc(n);
    memset(hostPtr(p, n ? n : 1), 0, n);
    return p;
}

uint64_t Emu::grealloc(uint64_t p, size_t n) {
    if (!p) return gmalloc(n);
    HeapHdr h;
    memcpy(&h, hostPtr(p - HDR_SIZE, HDR_SIZE), HDR_SIZE);
    uint64_t np = gmalloc(n);
    size_t copy = h.size < n ? h.size : n;
    memcpy(hostPtr(np, copy ? copy : 1), hostPtr(p, copy ? copy : 1), copy);
    gfree(p);
    return np;
}

void Emu::gfree(uint64_t p) {
    if (p < HEAP_BASE + HDR_SIZE || p >= HEAP_BASE + HEAP_SIZE) return;
    HeapHdr h;
    memcpy(&h, hostPtr(p - HDR_SIZE, HDR_SIZE), HDR_SIZE);
    if (h.magic != 0x1DEA || !h.used) return;
    h.used = 0;
    memcpy(hostPtr(p - HDR_SIZE, HDR_SIZE), &h, HDR_SIZE);
    if (heapUsed_ >= h.size) heapUsed_ -= h.size;
    // coalesce forward
    uint64_t base = p - HDR_SIZE;
    uint64_t next = base + HDR_SIZE + ((h.size + 15) & ~15ull);
    HeapHdr hn;
    memcpy(&hn, hostPtr(next, HDR_SIZE), HDR_SIZE);
    if (hn.magic == 0x1DEA && !hn.used) {
        h.size = (next - base) - HDR_SIZE + hn.size;
        memcpy(hostPtr(base, HDR_SIZE), &h, HDR_SIZE);
    }
}

// ---------------------------------------------------------------- guest mmap

uint64_t Emu::guestMmap(uint64_t addr, size_t len, uint64_t flags) {
    if (len == 0) return 0;
    if (addr && (flags & 0x10)) {  // MAP_FIXED
        // ensure coverage
        uint64_t a = addr & ~0xFFFull, s = ((addr & 0xFFF) + len + 0xFFF) & ~0xFFFull;
        if (!isMapped(a, s)) mapRegion(a, s);
        return addr;
    }
    uint64_t p = (mmapPtr_ + 0xFFF) & ~0xFFFull;
    if (p + len > MMAP_BASE + MMAP_SIZE)
        throw EmuError("guest mmap arena exhausted");
    mmapPtr_ = p + ((len + 0xFFF) & ~0xFFFull);
    return p;
}

}  // namespace ty
