// elfload.h - minimal AArch64 ELF shared object loader
#pragma once
#include "emu.h"

namespace ty {

// Loads an ET_DYN AArch64 ELF at IMAGE_BASE, applies relocations, fills
// emu.exports. Does NOT run init (caller does, after native env is ready).
uint64_t loadElf(Emu& emu, const uint8_t* data, size_t size);

}  // namespace ty
