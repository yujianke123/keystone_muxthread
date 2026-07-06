//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "util/regs.h"
#include "call/sbi.h"
#include "sys/timex.h"
#include "sys/interrupt.h"
#include "sys/slottee.h"
#include "util/printf.h"
#include <asm/csr.h>

void init_timer(void)
{
  sbi_set_timer(get_cycles64() + SLOTTEE_LT_QUANTUM_CYCLES);
  /*
   * Leave SIE clear until the final sret so reentry cannot take a timer
   * interrupt while sscratch still points at the user LT stack.
   */
  csr_set(sstatus, SR_SPIE);
  csr_set(sie, SIE_STIE | SIE_SSIE);
}

void handle_timer_interrupt(struct encl_ctx* regs)
{
  /* 诊断: RT 收到的 timer 心跳(指数节流)——RT 级 timer 可见性 */
  static unsigned long th_count;
  th_count++;
  if ((th_count & (th_count - 1)) == 0)
    printf("[slottee] TIMERHB count=%lu sepc=0x%lx spp=%lu\r\n",
        th_count, regs->regs.sepc,
        (unsigned long)((regs->sstatus & SR_SPP) ? 1 : 0));
  if (!slottee_lt_timer_preempt(regs))
    sbi_stop_enclave(STOP_TIMER_INTERRUPT);
  unsigned long next_cycle = get_cycles64() + SLOTTEE_LT_QUANTUM_CYCLES;
  sbi_set_timer(next_cycle);
  /*
   * Do not re-enable SIE inside the S-mode trap handler.  return_to_encl may
   * temporarily stage the user LT stack in sscratch before the final sret; a
   * nested timer interrupt in that window would save the trap frame on U memory.
   */
  csr_set(sstatus, SR_SPIE);
  return;
}

void handle_interrupts(struct encl_ctx* regs)
{
  unsigned long cause = regs->scause;

  switch(cause) {
    case INTERRUPT_CAUSE_TIMER:
      handle_timer_interrupt(regs);
      break;
    /* ignore other interrupts */
    case INTERRUPT_CAUSE_SOFTWARE:
    case INTERRUPT_CAUSE_EXTERNAL:
    default: {
      /* 诊断: 非 timer 中断进 RT(指数节流) */
      static unsigned long oi_count;
      oi_count++;
      if ((oi_count & (oi_count - 1)) == 0)
        printf("[slottee] OTHERIRQ count=%lu cause=0x%lx sepc=0x%lx\r\n",
            oi_count, cause, regs->regs.sepc);
      sbi_stop_enclave(0);
      return;
    }
  }
}
