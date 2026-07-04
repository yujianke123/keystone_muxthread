//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_SBI_H_
#define _KEYSTONE_SBI_H_

#include <sbi/sbi_types.h>
#include <sbi/sbi_trap.h>

unsigned long
sbi_sm_create_enclave(unsigned long *out_val, uintptr_t create_args);

unsigned long
sbi_sm_destroy_enclave(unsigned long eid);

unsigned long
sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid);

unsigned long
sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval);

unsigned long
sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request);

unsigned long
sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid);

unsigned long
sbi_sm_enter_slot(
    struct sbi_trap_regs *regs, unsigned long *out_val, unsigned long eid, uintptr_t enter_slot_req,
    uintptr_t enter_slot_resp);

unsigned long
sbi_sm_mark_revoke(
    unsigned long *out_val, unsigned long eid, uintptr_t mark_revoke_req,
    uintptr_t mark_revoke_resp);

unsigned long
sbi_sm_slottee_debug(
    unsigned long *out_val, unsigned long eid, uintptr_t debug_req,
    uintptr_t debug_resp);

unsigned long
sbi_sm_lease_watchdog_check(unsigned long *out_val, unsigned long eid);

unsigned long
sbi_sm_mint_slot_cap(
    unsigned long *out_val, uintptr_t mint_req, uintptr_t mint_resp);

unsigned long
sbi_sm_current_hart(unsigned long *out_val);

unsigned long
sbi_sm_exit_slot(
    struct sbi_trap_regs *regs, uintptr_t slot_id, uintptr_t lease_id,
    uintptr_t exit_reason, uintptr_t value);

unsigned long
sbi_sm_init_reentry_template(struct sbi_trap_regs *regs);

unsigned long
sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size);

unsigned long
sbi_sm_get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size);

unsigned long
sbi_sm_random(void);

unsigned long
sbi_sm_lt_ecall_probe(
    unsigned long *out_val, uintptr_t slot_id, uintptr_t lease_id, uintptr_t request);

unsigned long
sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1);

#endif
