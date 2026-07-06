//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include "thread.h"

void switch_vector_enclave(void){
  csr_write(mtvec, &trap_vector_enclave);
}

void switch_vector_host(void){
  csr_write(mtvec, &_trap_handler);
}

void swap_prev_mstatus(struct thread_state* thread, struct sbi_trap_regs* regs, uintptr_t current_mstatus) {
  //Time interrupts can occur in either user mode or supervisor mode
  uintptr_t mstatus_mask = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP |
                            MSTATUS_MPP | MSTATUS_FS | MSTATUS_SUM |
                            MSTATUS_MXR;

  uintptr_t tmp = thread->prev_mstatus;
  thread->prev_mstatus = (current_mstatus & ~mstatus_mask) | (current_mstatus & mstatus_mask);
  regs->mstatus = (current_mstatus & ~mstatus_mask) | tmp;
}

/* Swaps the entire s-mode visible state, general registers and then csrs */
void swap_prev_state(struct thread_state* thread, struct sbi_trap_regs* regs, int return_on_resume)
{
  int i;

  uintptr_t* prev = (uintptr_t*) &thread->prev_state;
  for(i=0; i<32; i++)
  {
    /* swap state */
    uintptr_t tmp = prev[i];
    prev[i] = ((unsigned long *)regs)[i];
    ((unsigned long *)regs)[i] = tmp;
  }

  prev[0] = !return_on_resume;

  swap_prev_smode_csrs(thread);

  return;
}

/* Swaps all s-mode csrs defined in 1.10 standard */
/* TODO: Right now we are only handling the ones that our test
   platforms support. Realistically we should have these behind
   defines for extensions (ex: N extension)*/
void swap_prev_smode_csrs(struct thread_state*
thread){

  uintptr_t tmp;

#define LOCAL_SWAP_CSR(csrname) \
  tmp = thread->prev_csrs.csrname;                 \
  thread->prev_csrs.csrname = csr_read(csrname);   \
  csr_write(csrname, tmp);

  LOCAL_SWAP_CSR(sstatus);
  // These only exist with N extension.
  //LOCAL_SWAP_CSR(sedeleg);
  //LOCAL_SWAP_CSR(sideleg);
  LOCAL_SWAP_CSR(sie);
  LOCAL_SWAP_CSR(stvec);
  LOCAL_SWAP_CSR(scounteren);
  LOCAL_SWAP_CSR(sscratch);
  LOCAL_SWAP_CSR(sepc);
  LOCAL_SWAP_CSR(scause);
  LOCAL_SWAP_CSR(sbadaddr);
  LOCAL_SWAP_CSR(sip);
  LOCAL_SWAP_CSR(satp);

#undef LOCAL_SWAP_CSR
}

void swap_prev_mepc(struct thread_state* thread, struct sbi_trap_regs* regs, uintptr_t current_mepc)
{
  uintptr_t tmp = thread->prev_mepc;
  thread->prev_mepc = current_mepc;
  regs->mepc = tmp;
}

/*
 * 交换 FP 寄存器堆(f0-f31+fcsr)与 thread->prev_fpr——SM 直停(M_SOFT IPI/
 * 非 RT 中介 timer)不经 RT 的 entry.S FP 保存,host↔enclave 互踩 FP。
 * ⚠️必须先在 M-mode 打开 mstatus.FS 再执行 fsd/fld:FS=Off 时 M-mode FP
 * 指令触非法指令→M 级陷阱死循环(当年 SM-FP 尝试挂死真机的根因)。结束后
 * 恢复原 mstatus(host 的 FS 状态对 Linux 语义不变;寄存器内容按交换还原)。
 */
void swap_prev_fp_state(struct thread_state* thread)
{
  uintptr_t old_mstatus = csr_read(mstatus);
  uintptr_t tmp[33];

  csr_set(mstatus, MSTATUS_FS);   /* FS=Dirty: M-mode FP 指令可执行 */

#define LOCAL_FP_SAVE(n)  __asm__ volatile("fsd f" #n ", %0" : "=m"(tmp[n]))
#define LOCAL_FP_LOAD(n)  __asm__ volatile("fld f" #n ", %0" :: "m"(thread->prev_fpr[n]))
  LOCAL_FP_SAVE(0);  LOCAL_FP_SAVE(1);  LOCAL_FP_SAVE(2);  LOCAL_FP_SAVE(3);
  LOCAL_FP_SAVE(4);  LOCAL_FP_SAVE(5);  LOCAL_FP_SAVE(6);  LOCAL_FP_SAVE(7);
  LOCAL_FP_SAVE(8);  LOCAL_FP_SAVE(9);  LOCAL_FP_SAVE(10); LOCAL_FP_SAVE(11);
  LOCAL_FP_SAVE(12); LOCAL_FP_SAVE(13); LOCAL_FP_SAVE(14); LOCAL_FP_SAVE(15);
  LOCAL_FP_SAVE(16); LOCAL_FP_SAVE(17); LOCAL_FP_SAVE(18); LOCAL_FP_SAVE(19);
  LOCAL_FP_SAVE(20); LOCAL_FP_SAVE(21); LOCAL_FP_SAVE(22); LOCAL_FP_SAVE(23);
  LOCAL_FP_SAVE(24); LOCAL_FP_SAVE(25); LOCAL_FP_SAVE(26); LOCAL_FP_SAVE(27);
  LOCAL_FP_SAVE(28); LOCAL_FP_SAVE(29); LOCAL_FP_SAVE(30); LOCAL_FP_SAVE(31);
  __asm__ volatile("frcsr %0" : "=r"(tmp[32]));

  LOCAL_FP_LOAD(0);  LOCAL_FP_LOAD(1);  LOCAL_FP_LOAD(2);  LOCAL_FP_LOAD(3);
  LOCAL_FP_LOAD(4);  LOCAL_FP_LOAD(5);  LOCAL_FP_LOAD(6);  LOCAL_FP_LOAD(7);
  LOCAL_FP_LOAD(8);  LOCAL_FP_LOAD(9);  LOCAL_FP_LOAD(10); LOCAL_FP_LOAD(11);
  LOCAL_FP_LOAD(12); LOCAL_FP_LOAD(13); LOCAL_FP_LOAD(14); LOCAL_FP_LOAD(15);
  LOCAL_FP_LOAD(16); LOCAL_FP_LOAD(17); LOCAL_FP_LOAD(18); LOCAL_FP_LOAD(19);
  LOCAL_FP_LOAD(20); LOCAL_FP_LOAD(21); LOCAL_FP_LOAD(22); LOCAL_FP_LOAD(23);
  LOCAL_FP_LOAD(24); LOCAL_FP_LOAD(25); LOCAL_FP_LOAD(26); LOCAL_FP_LOAD(27);
  LOCAL_FP_LOAD(28); LOCAL_FP_LOAD(29); LOCAL_FP_LOAD(30); LOCAL_FP_LOAD(31);
  __asm__ volatile("fscsr %0" :: "r"(thread->prev_fcsr));
#undef LOCAL_FP_SAVE
#undef LOCAL_FP_LOAD

  {
    int i;
    for (i = 0; i < 32; i++)
      thread->prev_fpr[i] = tmp[i];
    thread->prev_fcsr = tmp[32];
  }

  csr_write(mstatus, old_mstatus);
}


void clean_state(struct thread_state* state){
  int i;
  uintptr_t* prev = (uintptr_t*) &state->prev_state;
  for(i=1; i<32; i++)
  {
    prev[i] = 0;
  }

  for(i=0; i<32; i++)
    state->prev_fpr[i] = 0;
  state->prev_fcsr = 0;

  state->prev_mpp = -1; // 0x800;
  clean_smode_csrs(state);
}

void clean_smode_csrs(struct thread_state* state){

  state->prev_csrs.sstatus = 0;

  // We can't read these or set these from M-mode?
  state->prev_csrs.sedeleg = 0;
  state->prev_csrs.sideleg = 0;

  state->prev_csrs.sie = 0;
  state->prev_csrs.stvec = 0;
  // For now we take whatever the OS was doing
  state->prev_csrs.scounteren = csr_read(scounteren);
  state->prev_csrs.sscratch = 0;
  state->prev_csrs.sepc = 0;
  state->prev_csrs.scause = 0;
  state->prev_csrs.sbadaddr = 0;
  state->prev_csrs.sip = 0;
  state->prev_csrs.satp = 0;

}
