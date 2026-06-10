#ifndef __EYRIE_CALL_H__
#define __EYRIE_CALL_H__

#include <stdint.h>

#include "sm_call.h"

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
#define RUNTIME_SYSCALL_SLOTTEE_PREEMPT_RUN  1012
#define RUNTIME_SYSCALL_SLOTTEE_PREEMPT_STATS 1013
/* timer-independent 轻量让出：仅 stop 到 host 让 resume loop 推进，不注册 wait
 * queue、不依赖 notify/timer——用于纯 AMO poll 型 join（no-preempt 模式可用）。 */
#define RUNTIME_SYSCALL_SLOTTEE_LT_HOST_YIELD 1014
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
  uintptr_t preempt_count;
  uintptr_t preempt_yields;
  uintptr_t preempt_dispatches;
  uintptr_t runnable_queue_depth;
  uintptr_t wait_queue_depth;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_wait_residue;
  uintptr_t scheduler_unfinished;
  uintptr_t fairness_min;
  uintptr_t fairness_max;
  uintptr_t fairness_gap;
  uintptr_t fairness_checks;
  uintptr_t fairness_violations;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t tls_resume_ok;
  uintptr_t hart_id[SLOTTEE_MAX_SLOTS];
};

/*
 * One in-runtime preemptive worker specification handed from the eapp scheduler
 * thread to the Eyrie RT preempt scheduler: a U-mode entry function pointer plus
 * its argument.  All workers belong to the same eapp (share .data/gp).
 */
struct slottee_preempt_spec {
  uintptr_t fn;
  uintptr_t arg;
  uintptr_t slot;  /* explicit worker slot id; cross-hart groups must be disjoint */
};

/*
 * Snapshot of the Eyrie RT OS-level preemptive timer scheduler after a
 * PREEMPT_RUN completes.  preempt_switches counts timer-driven in-runtime
 * context swaps that changed the running LT; host_yields counts stop_enclave
 * calls made during the run (must stay 0 to prove zero host mediation).
 */
struct slottee_preempt_sched_stats {
  uintptr_t worker_count;
  uintptr_t completed;
  uintptr_t preempt_switches;
  uintptr_t preempt_ticks;
  uintptr_t host_yields;
  uintptr_t exit_switches;
  uintptr_t runnable_queue_depth;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_wait_residue;
  uintptr_t scheduler_unfinished;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t fairness_min;
  uintptr_t fairness_max;
  uintptr_t fairness_gap;
  uintptr_t fairness_violations;
  uintptr_t active;
  uintptr_t steals;
  uintptr_t steal_skips;
  uintptr_t rebalances;
  uintptr_t steal_victim_slot;   /* scheduler slot of the victim this group last stole from */
  uintptr_t steal_victim_count;  /* that victim's runnable count at steal time (best-victim evidence) */
  uintptr_t per_worker_slot[SLOTTEE_MAX_SLOTS];
  uintptr_t per_worker_dispatch[SLOTTEE_MAX_SLOTS];
  uintptr_t per_worker_preempts[SLOTTEE_MAX_SLOTS];
};

#endif  // __EYRIE_CALL_H__
