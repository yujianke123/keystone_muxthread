//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "mprv.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "plugins/plugins.h"
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>

unsigned long sbi_sm_create_enclave(unsigned long* eid, uintptr_t create_args)
{
  struct keystone_sbi_create_t create_args_local;
  unsigned long ret;

  ret = copy_enclave_create_args(create_args, &create_args_local);

  if (ret)
    return ret;

  ret = create_enclave(eid, create_args_local);
  return ret;
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid)
{
  unsigned long ret;
  ret = destroy_enclave((unsigned int)eid);
  return ret;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  regs->a0 = run_enclave(regs, (unsigned int) eid);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  unsigned long ret;
  ret = resume_enclave(regs, (unsigned int) eid);
  if (!regs->zero)
    regs->a0 = ret;
  regs->mepc += 4;

  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_enter_slot(
    struct sbi_trap_regs *regs, unsigned long *out_val, unsigned long eid, uintptr_t enter_slot_req,
    uintptr_t enter_slot_resp)
{
  struct enter_slot_req_t req;
  struct enter_slot_resp_t resp = {0};
  unsigned long ret;

  if (out_val)
    *out_val = 0;

  if (copy_to_sm(&req, enter_slot_req, sizeof(req)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (req.version != SLOTTEE_ENTER_SLOT_VERSION ||
      req.cap.version != SLOTTEE_ENTER_SLOT_VERSION ||
      (req.flags != SLOTTEE_ENTER_SLOT_FLAG_NONE &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  req.cap.eid = eid;
  if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL) {
    ret = activate_enclave_slot((enclave_id) eid, &req.cap, &resp);
    resp.value = 0;
    if (out_val)
      *out_val = 0;
    if (enter_slot_resp && copy_from_sm(enter_slot_resp, &resp, sizeof(resp)))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
      return ret;

    enter_activated_enclave_slot(regs, (enclave_id) eid, req.cap.slot_id, resp.lease_id);
    regs->mepc += 4;
    sbi_trap_exit(regs);
    return 0;
  }

  ret = reserve_enclave_slot((enclave_id) eid, &req.cap, &resp);
  if (out_val)
    *out_val = resp.value;

out:
  resp.status = ret;
  if (enter_slot_resp && copy_from_sm(enter_slot_resp, &resp, sizeof(resp)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long sbi_sm_exit_slot(
    struct sbi_trap_regs *regs, uintptr_t slot_id, uintptr_t lease_id,
    uintptr_t exit_reason, uintptr_t value)
{
  unsigned long ret;

  ret = exit_enclave_slot(
      regs, cpu_get_enclave_id(), slot_id, lease_id, exit_reason, value);
  regs->a0 = ret;
  regs->a1 = (ret == SBI_ERR_SM_ENCLAVE_SUCCESS) ? value : 0;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval)
{
  regs->a0 = exit_enclave(regs, cpu_get_enclave_id());
  regs->a1 = retval;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request)
{
  regs->a0 = stop_enclave(regs, request, cpu_get_enclave_id());
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  unsigned long ret;
  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                       size_t key_ident_size)
{
  unsigned long ret;
  ret = get_sealing_key(sealing_key, key_ident, key_ident_size,
                         cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_random(void)
{
  return (unsigned long) platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}
