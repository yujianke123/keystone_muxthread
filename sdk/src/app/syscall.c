//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"

/* this implementes basic system calls for the enclave */

int
ocall(
    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
    size_t return_len) {
  return SYSCALL_5(RUNTIME_SYSCALL_OCALL,
      call_id, data, data_len, return_buffer, return_len);
}

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len) {
  return SYSCALL_3(RUNTIME_SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

int
attest_enclave(void* report, void* data, size_t size) {
  return SYSCALL_3(RUNTIME_SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

/* returns sealing key */
int
get_sealing_key(
    struct sealing_key* sealing_key_struct, size_t sealing_key_struct_size,
    void* key_ident, size_t key_ident_size) {
  return SYSCALL_4(RUNTIME_SYSCALL_GET_SEALING_KEY,
      sealing_key_struct, sealing_key_struct_size,
      key_ident, key_ident_size);
}

int
slottee_mint_cap(
    const struct mint_slot_cap_req_t* req, struct mint_slot_cap_resp_t* resp) {
  return SYSCALL_2(RUNTIME_SYSCALL_SLOTTEE_MINT_CAP, req, resp);
}

int
slottee_slot_request(const struct slottee_slot_policy* policy) {
  return SYSCALL_1(RUNTIME_SYSCALL_SLOTTEE_SLOT_REQUEST, policy);
}

int
slottee_slot_release(uintptr_t slot_id) {
  return SYSCALL_1(RUNTIME_SYSCALL_SLOTTEE_SLOT_RELEASE, slot_id);
}

int
slottee_lt_spawn(uintptr_t slot_id, slottee_lt_fn_t fn, void* arg) {
  return SYSCALL_3(RUNTIME_SYSCALL_SLOTTEE_LT_SPAWN, slot_id, fn, arg);
}

int
slottee_lt_wait_value(const long* ptr, long target, uintptr_t op) {
  return SYSCALL_3(RUNTIME_SYSCALL_SLOTTEE_LT_WAIT_VALUE, ptr, target, op);
}

int
slottee_lt_notify_value(const long* ptr) {
  return SYSCALL_1(RUNTIME_SYSCALL_SLOTTEE_LT_NOTIFY_VALUE, ptr);
}

int
slottee_lt_host_yield(void) {
  return SYSCALL_0(RUNTIME_SYSCALL_SLOTTEE_LT_HOST_YIELD);
}

int
slottee_lt_collect_stats(struct slottee_lt_runtime_stats* stats) {
  return SYSCALL_1(RUNTIME_SYSCALL_SLOTTEE_LT_COLLECT_STATS, stats);
}

int
slottee_preempt_run(const struct slottee_preempt_spec* specs, uintptr_t count,
    uintptr_t switch_budget, uintptr_t flags) {
  return SYSCALL_4(RUNTIME_SYSCALL_SLOTTEE_PREEMPT_RUN, specs, count,
      switch_budget, flags);
}

int
slottee_preempt_collect_stats(struct slottee_preempt_sched_stats* stats) {
  return SYSCALL_1(RUNTIME_SYSCALL_SLOTTEE_PREEMPT_STATS, stats);
}
