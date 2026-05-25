#define __PREPROCESSING__
#include "mm/vm_defs.h"
#include <asm/csr.h>
#include "util/asm_helpers.h"

.section .text
_start:
  // a0: SlotTEE slot token. Zero means the original slot 0 run path.
  // a1: dram_base
  // a2: dram_size
  // a3: runtime_base
  // a4: user_base
  // a5: free_base
  // a6: untrusted_ptr
  // a7: untrusted_size

  // use designated stack
  la sp, _estack

  // save all args to stack 
  addi sp, sp, -(REGBYTES*8)
  STORE a0, 0(sp)
  STORE a1, 1*REGBYTES(sp)
  STORE a2, 2*REGBYTES(sp)
  STORE a3, 3*REGBYTES(sp)
  STORE a4, 4*REGBYTES(sp)
  STORE a5, 5*REGBYTES(sp)
  STORE a6, 6*REGBYTES(sp)
  STORE a7, 7*REGBYTES(sp)

  // call load_runtime
  call load_runtime 

  // exit if errors
  bne a0, zero, exit

  // switch to va and jump to runtime code 
  li t0, RUNTIME_VA_START
  csrw stvec, t0  // store runtime start addresss in stvec 

  // construct new satp
  // below assembly and fences work on CVA6, for satp specifically.
  // FIXME: declutter if possible according to more testing
  la a0, root_page_table_storage  
  li a1, RISCV_PAGE_BITS
  li a2, SATP_MODE
  srl a0, a0, a1
  or a0, a0, a2

  // flush TLB's just in case
  fence.i
  sfence.vma

  // keep a0 as the new satp value until csrw satp below.
  LOAD t6, 0(sp)
  // set arguments for eyrie_boot
  LOAD a1, 1*REGBYTES(sp)
  LOAD a2, 2*REGBYTES(sp)
  LOAD a3, 3*REGBYTES(sp)
  LOAD a4, 4*REGBYTES(sp)
  LOAD a5, free_base_final
  LOAD a6, 6*REGBYTES(sp)
  LOAD a7, 7*REGBYTES(sp)

  // flush TLB's just in case
  fence.i
  sfence.vma

  csrw satp, a0 // switch to virtual addresssing 
  sfence.vma

exit:
  call error_and_exit
