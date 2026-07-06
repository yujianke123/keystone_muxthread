//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "mm/mm.h"
#include "util/rt_util.h"
#include "util/printf.h"
#include "uaccess.h"
#include "mm/vm.h"
#include "sys/slottee.h"
#include <asm/csr.h>

// Statically allocated copy-buffer
unsigned char rt_copy_buffer_1[RISCV_PAGE_SIZE];
unsigned char rt_copy_buffer_2[RISCV_PAGE_SIZE];

size_t rt_util_getrandom(void* vaddr, size_t buflen){
  size_t remaining = buflen;
  uintptr_t rnd;
  uintptr_t* next = (uintptr_t*)vaddr;
  // Get data
  while(remaining > sizeof(uintptr_t)){
    rnd = sbi_random();
    ALLOW_USER_ACCESS( *next = rnd );
    remaining -= sizeof(uintptr_t);
    next++;
  }
  // Cleanup
  if( remaining > 0 ){
    rnd = sbi_random();
    copy_to_user(next, &rnd, remaining);
  }
  size_t ret = buflen;
  return ret;
}

void rt_util_misc_fatal(){
  //Better hope we can debug it!
  sbi_exit_enclave(-1);
}

void not_implemented_fatal(struct encl_ctx* ctx){
    /* 诊断: 指数节流(1,2,4,8,...)——静默故障吞掉循环可见化 */
    static unsigned long nif_count;
    nif_count++;
    if ((nif_count & (nif_count - 1)) == 0)
      printf("[slottee] NIF count=%lu pc=0x%lx addr=0x%lx scause=0x%lx spp=%lu\r\n",
          nif_count, ctx->regs.sepc, ctx->sbadaddr, ctx->scause,
          (unsigned long)((ctx->sstatus & SR_SPP) ? 1 : 0));
#ifdef FATAL_DEBUG
    unsigned long addr, cause, pc;
    pc = ctx->regs.sepc;
    addr = ctx->sbadaddr;
    cause = ctx->scause;
    printf("[runtime] non-handlable interrupt/exception at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
#endif

    if (slottee_active_user_fault_exit(ctx, SLOTTEE_LT_USER_ILLEGAL_MAGIC))
      return;

    // Bail to m-mode
    __asm__ volatile("csrr a0, scause\r\nli a7, 1111\r\n ecall");

    return;
}

void rt_page_fault(struct encl_ctx* ctx)
{
  /* 诊断: 指数节流页故障可见化 */
  static unsigned long pf_count;
  pf_count++;
  if ((pf_count & (pf_count - 1)) == 0)
    printf("[slottee] PF count=%lu pc=0x%lx addr=0x%lx scause=0x%lx spp=%lu\r\n",
        pf_count, ctx->regs.sepc, ctx->sbadaddr, ctx->scause,
        (unsigned long)((ctx->sstatus & SR_SPP) ? 1 : 0));
#ifdef FATAL_DEBUG
  unsigned long addr, cause, pc;
  pc = ctx->regs.sepc;
  addr = ctx->sbadaddr;
  cause = ctx->scause;
  printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
#endif

  if (slottee_active_user_fault_exit(ctx, SLOTTEE_LT_USER_PAGE_FAULT_MAGIC))
    return;

  sbi_exit_enclave(-1);

  /* never reach here */
  assert(false);
  return;
}

void tlb_flush(void)
{
  __asm__ volatile("fence.i\t\nsfence.vma\t\n");
}
