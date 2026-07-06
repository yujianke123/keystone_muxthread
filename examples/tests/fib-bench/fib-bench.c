//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"

/* benchmark 周期读：VF2(U74) rdcycle 触发不可处理中断→rdtime；QEMU/generic→rdcycle。 */
#ifdef SLOTTEE_BENCH_RDTIME
#define SLOTTEE_RDCYCLE_INSN "rdtime %0"
#else
#define SLOTTEE_RDCYCLE_INSN "rdcycle %0"
#endif

unsigned long read_cycles(void)
{
  unsigned long cycles;
  asm volatile (SLOTTEE_RDCYCLE_INSN : "=r" (cycles));
  return cycles;
}

unsigned long fibonacci_rec(unsigned long in){
  if( in <= 1)
    return 1;
  else
    return fibonacci_rec(in-1)+fibonacci_rec(in-2);
}

// Returns the number of cycles for a given fibonacci execution
unsigned long fib_eapp(unsigned long in) {
  unsigned long start = read_cycles();
  fibonacci_rec(in);
  unsigned long end = read_cycles();
  return end - start;
}

void EAPP_ENTRY eapp_entry(){
  int arg = 35;
  EAPP_RETURN(fib_eapp(arg));
}
