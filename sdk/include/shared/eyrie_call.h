#ifndef __EYRIE_CALL_H__
#define __EYRIE_CALL_H__

#include <stdint.h>

#define RUNTIME_SYSCALL_UNKNOWN             1000
#define RUNTIME_SYSCALL_OCALL               1001
#define RUNTIME_SYSCALL_SHAREDCOPY          1002
#define RUNTIME_SYSCALL_ATTEST_ENCLAVE      1003
#define RUNTIME_SYSCALL_GET_SEALING_KEY     1004
#define RUNTIME_SYSCALL_SLOTTEE_MINT_CAP    1005
#define RUNTIME_SYSCALL_SLOTTEE_LT_SPAWN    1006
#define RUNTIME_SYSCALL_SLOTTEE_LT_WAIT_VALUE 1007
#define RUNTIME_SYSCALL_SLOTTEE_LT_NOTIFY_VALUE 1008
#define RUNTIME_SYSCALL_SLOTTEE_LT_COLLECT_STATS 1009
#define RUNTIME_SYSCALL_SLOTTEE_SLOT_REQUEST 1010
#define RUNTIME_SYSCALL_SLOTTEE_SLOT_RELEASE 1011
#define RUNTIME_SYSCALL_EXIT                1101

#define SLOTTEE_LT_WAIT_OP_EQ          0
#define SLOTTEE_LT_WAIT_OP_GE          1
#define SLOTTEE_LT_WAIT_RESULT_READY   0
#define SLOTTEE_LT_WAIT_RESULT_BLOCKED 1
#define SLOTTEE_LT_NOTIFY_RESULT_MISS  0
#define SLOTTEE_LT_NOTIFY_RESULT_WOKE  1

struct slottee_slot_policy {
  uintptr_t max_concurrent;
  uintptr_t affinity_hint;
  uintptr_t priority;
};

struct slottee_lt_runtime_stats {
  uintptr_t wait_blocks;
  uintptr_t wait_wakeups;
  uintptr_t notify_misses;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t user_context_entries;
  uintptr_t user_context_exits;
  uintptr_t syscall_traps;
  uintptr_t ocall_traps;
  uintptr_t ocall_resumes;
  uintptr_t exit_traps;
  uintptr_t fault_traps;
  uintptr_t timer_wait_stops;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t tls_resume_ok;
};

#endif  // __EYRIE_CALL_H__
