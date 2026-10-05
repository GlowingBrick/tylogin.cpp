// elfload.cpp - AArch64 ELF loader: PT_LOAD mapping, dynamic table, relocations
#include "elfload.h"

#include <cstring>

namespace ty {

namespace {

struct Elf64_Ehdr_ {
    uint8_t e_ident[16];
    uint16_t e_type, e_machine, e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};

struct Elf64_Phdr_ {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};

struct Elf64_Dyn_ {
    int64_t d_tag;
    uint64_t d_val;
};

struct Elf64_Rela_ {
    uint64_t r_offset, r_info;
    int64_t r_addend;
};

struct Elf64_Sym_ {
    uint32_t st_name;
    uint8_t st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
};

constexpr uint32_t PT_LOAD = 1, PT_DYNAMIC = 2;
constexpr uint64_t DT_NULL = 0, DT_STRTAB = 5, DT_SYMTAB = 6, DT_RELA = 7, DT_RELASZ = 8,
                   DT_SYMENT = 11, DT_INIT = 12, DT_FINI = 13, DT_STRSZ = 10,
                   DT_JMPREL = 23, DT_PLTRELSZ = 2, DT_INIT_ARRAY = 25,
                   DT_INIT_ARRAYSZ = 27, DT_GNU_HASH = 0x6ffffef5, DT_ANDROID_RELA = 0x6000000f;

constexpr uint32_t R_AARCH64_RELATIVE = 1027, R_AARCH64_ABS64 = 257,
                   R_AARCH64_GLOB_DAT = 1025, R_AARCH64_JUMP_SLOT = 1026;

constexpr int EM_AARCH64 = 183;

uint64_t elfRead(const uint8_t* base, size_t off, size_t len) {
    uint64_t v = 0;
    memcpy(&v, base + off, len);
    return v;
}

// number of dynsym entries from DT_GNU_HASH (fallback: strtab - symtab)
size_t countSymbols(const uint8_t* img, uint64_t symtab, uint64_t gnuHash, uint64_t strtab,
                    uint64_t syment) {
    if (gnuHash) {
        uint32_t nbuckets = elfRead(img, gnuHash, 4);
        uint32_t symoffset = elfRead(img, gnuHash + 4, 4);
        uint32_t bloomSize = elfRead(img, gnuHash + 8, 4);
        const uint64_t buckets = gnuHash + 16 + bloomSize * 8;
        const uint64_t chains = buckets + nbuckets * 4;
        size_t last = symoffset;
        for (uint32_t i = 0; i < nbuckets; i++) {
            uint32_t b = elfRead(img, buckets + i * 4, 4);
            if (b < symoffset) continue;
            size_t idx = b;
            while ((elfRead(img, chains + (idx - symoffset) * 4, 4) & 1) == 0) idx++;
            if (idx > last) last = idx;
        }
        return last + 1;
    }
    if (strtab > symtab && syment) return (strtab - symtab) / syment;
    return 0;
}

}  // namespace

uint64_t loadElf(Emu& emu, const uint8_t* data, size_t size) {
    // note: "\x7f" "ELF" must be split - "\x7fELF" would lex as \x7fE + "LF"
    if (size < sizeof(Elf64_Ehdr_) || memcmp(data, "\x7f" "ELF", 4) != 0)
        throw EmuError("not an ELF file");
    Elf64_Ehdr_ eh;
    memcpy(&eh, data, sizeof(eh));
    if (eh.e_ident[4] != 2 || eh.e_machine != EM_AARCH64 || eh.e_type != 3)
        throw EmuError("unsupported ELF (need AArch64 ET_DYN)");

    // ---- map PT_LOAD segments into one image region ----
    uint64_t maxAddr = 0;
    std::vector<Elf64_Phdr_> phdrs(eh.e_phnum);
    for (int i = 0; i < eh.e_phnum; i++) {
        memcpy(&phdrs[i], data + eh.e_phoff + i * eh.e_phentsize, sizeof(Elf64_Phdr_));
        if (phdrs[i].p_type == PT_LOAD) {
            uint64_t end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
            if (end > maxAddr) maxAddr = end;
        }
    }
    uint64_t imgSize = (maxAddr + 0xFFF) & ~0xFFFull;
    if (IMAGE_BASE + imgSize > HEAP_BASE) throw EmuError("image too large");
    emu.mapRegion(IMAGE_BASE, imgSize);
    // region is zero-filled already (fresh mmap); copy file-backed parts
    for (auto& ph : phdrs) {
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_filesz)
            emu.writeMem(IMAGE_BASE + ph.p_vaddr, data + ph.p_offset, ph.p_filesz);
    }

    // ---- parse PT_DYNAMIC ----
    uint64_t symtab = 0, strtab = 0, strsz = 0, syment = 24, rela = 0, relasz = 0,
             jmprel = 0, pltrelsz = 0, init = 0, initArr = 0, initArrSz = 0, gnuHash = 0;
    for (auto& ph : phdrs) {
        if (ph.p_type != PT_DYNAMIC) continue;
        size_t n = ph.p_filesz / sizeof(Elf64_Dyn_);
        for (size_t i = 0; i < n; i++) {
            Elf64_Dyn_ d;
            memcpy(&d, data + ph.p_offset + i * sizeof(Elf64_Dyn_), sizeof(d));
            switch (d.d_tag) {
                case DT_SYMTAB: symtab = d.d_val; break;
                case DT_STRTAB: strtab = d.d_val; break;
                case DT_STRSZ: strsz = d.d_val; break;
                case DT_SYMENT: syment = d.d_val; break;
                case DT_RELA: rela = d.d_val; break;
                case DT_RELASZ: relasz = d.d_val; break;
                case DT_JMPREL: jmprel = d.d_val; break;
                case DT_PLTRELSZ: pltrelsz = d.d_val; break;
                case DT_INIT: init = d.d_val; break;
                case DT_INIT_ARRAY: initArr = d.d_val; break;
                case DT_INIT_ARRAYSZ: initArrSz = d.d_val; break;
                case DT_GNU_HASH: gnuHash = d.d_val; break;
                case DT_ANDROID_RELA:
                    throw EmuError("packed Android relocations not supported");
                default: break;
            }
            if (d.d_tag == DT_NULL) break;
        }
    }
    if (!symtab || !strtab) throw EmuError("missing dynsym/dynstr");

    const uint8_t* img = emu.hostPtr(IMAGE_BASE, imgSize);
    size_t nsyms = countSymbols(img, symtab, gnuHash, strtab, syment);
    logDbg("[elf] nsyms=%zu relasz=%zu pltrelsz=%zu", nsyms, relasz, pltrelsz);

    auto symName = [&](const Elf64_Sym_& s) -> const char* {
        if (s.st_name >= strsz) return "";
        return (const char*)(img + strtab + s.st_name);
    };

    auto resolve = [&](uint32_t symIdx) -> uint64_t {
        if (symIdx == 0 || symIdx >= nsyms) return 0;
        Elf64_Sym_ s;
        memcpy(&s, img + symtab + symIdx * syment, sizeof(s));
        if (s.st_shndx != 0) {  // defined here
            uint64_t a = IMAGE_BASE + s.st_value;
            if (s.st_info >> 4 == 1 /*GLOBAL*/) emu.exports[symName(s)] = a;
            return a;
        }
        // imported
        std::string name = symName(s);
        uint32_t type = s.st_info & 0xF;
        if (type == 1 /*OBJECT*/) return emu.dataImport(name);
        uint64_t stub = emu.importStubAddr(name);
        if (!stub) {
            logRaw("[elf] warning: unresolved import '%s' -> trap stub", name.c_str());
        }
        return stub;
    };

    // ---- relocations ----
    auto applyRela = [&](uint64_t off, size_t count) {
        for (size_t i = 0; i < count; i++) {
            Elf64_Rela_ r;
            memcpy(&r, img + off + i * sizeof(Elf64_Rela_), sizeof(r));
            uint32_t type = r.r_info & 0xFFFFFFFF, sym = r.r_info >> 32;
            uint64_t place = IMAGE_BASE + r.r_offset;
            uint64_t val = 0;
            switch (type) {
                case R_AARCH64_RELATIVE:
                    val = IMAGE_BASE + r.r_addend;
                    break;
                case R_AARCH64_ABS64:
                case R_AARCH64_GLOB_DAT:
                case R_AARCH64_JUMP_SLOT:
                    val = resolve(sym) + r.r_addend;
                    break;
                default:
                    throw EmuError("unsupported reloc type " + std::to_string(type));
            }
            emu.writeMem(place, &val, 8);
        }
    };
    if (rela && relasz) applyRela(rela, relasz / sizeof(Elf64_Rela_));
    if (jmprel && pltrelsz) applyRela(jmprel, pltrelsz / sizeof(Elf64_Rela_));

    // ---- exports (also from defined symbols not referenced by relocs) ----
    for (size_t i = 0; i < nsyms; i++) {
        Elf64_Sym_ s;
        memcpy(&s, img + symtab + i * syment, sizeof(s));
        if (s.st_shndx != 0 && (s.st_info >> 4) == 1 && s.st_name < strsz)
            emu.exports[symName(s)] = IMAGE_BASE + s.st_value;
    }

    // ---- record init routines ----
    if (init) emu.initRoutines.push_back(IMAGE_BASE + init);
    if (initArr && initArrSz) {
        for (size_t i = 0; i < initArrSz / 8; i++) {
            uint64_t fn = 0;
            emu.readMem(IMAGE_BASE + initArr + i * 8, &fn, 8);
            if (fn) emu.initRoutines.push_back(fn);
        }
    }

    logDbg("[elf] loaded at 0x%llx, %zu exports, %zu init routines",
           (unsigned long long)IMAGE_BASE, emu.exports.size(), emu.initRoutines.size());
    return IMAGE_BASE;
}

}  // namespace ty
