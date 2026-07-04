//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ElfFile.hpp"
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>

namespace Keystone {

static size_t
fstatFileSize(int filep) {
  int rc;
  struct stat stat_buf;
  rc = fstat(filep, &stat_buf);
  return (rc == 0 ? stat_buf.st_size : 0);
}

ElfFile::ElfFile(std::string filename) {
  fileSize = 0;
  ptr      = NULL;
  filep    = open(filename.c_str(), O_RDONLY);

  if (filep < 0) {
    ERROR("file does not exist - %s", filename.c_str());
    return;
  }

  fileSize = fstatFileSize(filep);
  if (!fileSize) {
    ERROR("invalid file size - %s", filename.c_str());
  }

  ptr = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, filep, 0);

  if (!ptr) {
    ERROR("mmap failed for %s", filename.c_str());
  }
    /* preparation for libelf */
  if (elf_newFile(ptr, fileSize, &elf)) {
    return;
  }

  /* get bound vaddrs */
  elf_getMemoryBounds(&elf, VIRTUAL, &minVaddr, &maxVaddr);

  if (!IS_ALIGNED(minVaddr, PAGE_SIZE)) {
    return;
  }

  maxVaddr = ROUND_UP(maxVaddr, PAGE_BITS);
}

ElfFile::~ElfFile() {
  close(filep);
  munmap(ptr, fileSize);
}

uintptr_t
ElfFile::getSymbolAddress(const char* symbolName) {
  if (!symbolName) {
    return 0;
  }

  size_t sections = elf_getNumSections(&elf);
  for (size_t section = 1; section < sections; section++) {
    uint32_t type = elf_getSectionType(&elf, section);
    if (type != SHT_SYMTAB && type != SHT_DYNSYM) {
      continue;
    }

    void* table = elf_getSection(&elf, section);
    const char* strings = elf_getStringTable(&elf, elf_getSectionLink(&elf, section));
    size_t entrySize = elf_getSectionEntrySize(&elf, section);
    size_t tableSize = elf_getSectionSize(&elf, section);

    if (!table || !strings || entrySize != sizeof(Elf64_Sym)) {
      continue;
    }

    for (size_t offset = 0; offset + entrySize <= tableSize; offset += entrySize) {
      Elf64_Sym* symbol = (Elf64_Sym*)((uintptr_t)table + offset);
      if (std::strcmp(strings + symbol->st_name, symbolName) == 0) {
        return symbol->st_value;
      }
    }
  }

  return 0;
}

}  // namespace Keystone
