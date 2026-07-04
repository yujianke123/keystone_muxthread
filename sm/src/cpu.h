//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __CPU_H__
#define __CPU_H__

#include "sm.h"
#include "enclave.h"

/* hart state for regulating SBI */
struct cpu_state
{
  int is_enclave;
  enclave_id eid;
  uintptr_t thread_index;
};

/* external functions */
int cpu_is_enclave_context(void);
int cpu_get_enclave_id(void);
uintptr_t cpu_get_enclave_thread_index(void);
void cpu_enter_enclave_context(enclave_id eid, uintptr_t thread_index);
void cpu_exit_enclave_context(void);

#endif
