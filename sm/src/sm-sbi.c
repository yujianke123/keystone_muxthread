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
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_BIND &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_TRAP_SAFE &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_ECALL &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_RESUME_LT_USER_OCALL)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  req.cap.eid = eid;
  if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_RESUME_LT_USER_OCALL) {
    ret = resume_enclave_slot((struct sbi_trap_regs*)regs, (enclave_id)eid,
        req.cap.slot_id, req.host_nonce);
    if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS) {
      /* regs now hold the resumed enclave thread's frame (satp/PMP already
       * switched).  Touching host memory here fails under MPRV translation,
       * and returning through the OpenSBI ecall path would apply mepc+=4 /
       * a0=error / a1=value to the ENCLAVE frame — clobbering registers at
       * the enclave's stop-ecall resume point (a1 is not in the runtime's
       * SBI clobber set, so this corrupted live state and caused PC=0 jumps
       * on real hardware).  Bump mepc past the enclave's stop ecall and
       * exit the trap directly, leaving every other register as saved. */
      regs->mepc += 4;
      sbi_trap_exit(regs);
      return 0;
    }
    /* Failure: still on the host frame; writing the response is safe. */
    if (out_val)
      *out_val = ret;
    resp.status = ret;
    if (enter_slot_resp && copy_from_sm(enter_slot_resp, &resp, sizeof(resp)))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_BIND ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_TRAP_SAFE ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_ECALL ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL ||
      req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT) {
    uintptr_t slot_mode = SLOTTEE_SLOT_TOKEN_MODE_TRAMPOLINE;

    if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_SCHED;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_CONTEXT;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_YIELD;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_BIND)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_BIND;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_TRAP_SAFE)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_TRAP_SAFE;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_ECALL)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_ECALL;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_USER;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL;
    else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT)
      slot_mode = SLOTTEE_SLOT_TOKEN_MODE_LT_USER_REVOKE_FAULT;

    ret = activate_enclave_slot((enclave_id) eid, &req.cap, slot_mode, &resp);
    resp.value = 0;
    if (out_val)
      *out_val = 0;
    if (enter_slot_resp && copy_from_sm(enter_slot_resp, &resp, sizeof(resp)))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
      return ret;

    enter_activated_enclave_slot(
        regs, (enclave_id) eid, req.cap.slot_id, resp.lease_id, slot_mode);
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

unsigned long sbi_sm_mark_revoke(
    unsigned long *out_val, unsigned long eid, uintptr_t mark_revoke_req,
    uintptr_t mark_revoke_resp)
{
  struct mark_revoke_req_t req;
  struct mark_revoke_resp_t resp = {0};
  unsigned long ret;

  if (out_val)
    *out_val = 0;

  if (copy_to_sm(&req, mark_revoke_req, sizeof(req)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  ret = mark_revoke_enclave_slot((enclave_id) eid, &req, &resp);
  if (out_val)
    *out_val = resp.epoch;

  if (mark_revoke_resp && copy_from_sm(mark_revoke_resp, &resp, sizeof(resp)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return ret;
}

unsigned long sbi_sm_slottee_debug(
    unsigned long *out_val, unsigned long eid, uintptr_t debug_req,
    uintptr_t debug_resp)
{
  struct slottee_debug_req_t req;
  struct slottee_debug_resp_t resp = {0};
  unsigned long ret;

  if (out_val)
    *out_val = 0;

  if (copy_to_sm(&req, debug_req, sizeof(req)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  ret = debug_enclave_slot_state((enclave_id) eid, &req, &resp);
  if (out_val) {
    int wants_cap_key = req.op == SLOTTEE_DEBUG_OP_CAP_KEY_STATUS;
#ifdef SLOTTEE_DEBUG_MINT_ENABLE
    wants_cap_key = wants_cap_key || req.op == SLOTTEE_DEBUG_OP_MINT_CAP;
#endif
    *out_val = wants_cap_key ? resp.cap_key_ready : resp.reentry_ready;
  }

  if (debug_resp && copy_from_sm(debug_resp, &resp, sizeof(resp)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return ret;
}

unsigned long sbi_sm_lease_watchdog_check(unsigned long *out_val, unsigned long eid)
{
  unsigned long reclaimed = lease_watchdog_check((enclave_id)eid);

  if (out_val)
    *out_val = reclaimed;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_mint_slot_cap(
    unsigned long *out_val, uintptr_t mint_req, uintptr_t mint_resp)
{
  struct mint_slot_cap_req_t req;
  struct mint_slot_cap_resp_t resp = {0};
  unsigned long ret;

  if (out_val)
    *out_val = 0;

  if (copy_to_sm(&req, mint_req, sizeof(req)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  ret = mint_enclave_slot_cap(cpu_get_enclave_id(), &req, &resp);
  if (out_val)
    *out_val = resp.status;

  if (mint_resp && copy_from_sm(mint_resp, &resp, sizeof(resp)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return ret;
}

unsigned long sbi_sm_current_hart(unsigned long *out_val)
{
  if (!out_val)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  *out_val = csr_read(mhartid);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
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

unsigned long sbi_sm_init_reentry_template(struct sbi_trap_regs *regs)
{
  return init_enclave_slot_reentry_template(regs, cpu_get_enclave_id());
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

unsigned long sbi_sm_lt_ecall_probe(
    unsigned long *out_val, uintptr_t slot_id, uintptr_t lease_id, uintptr_t request)
{
  if (!out_val || slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS || lease_id == 0 ||
      request != SLOTTEE_LT_ECALL_MAKE_REQUEST(slot_id, lease_id))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  *out_val = SLOTTEE_LT_ECALL_MAKE_REPLY(slot_id, lease_id);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}
