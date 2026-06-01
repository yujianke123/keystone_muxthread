#ifndef __SLOTTEE_MULTIHART_H__
#define __SLOTTEE_MULTIHART_H__

#include <stdint.h>

#define SLOTTEE_MULTIHART_TICKET_WINDOWS     3
#define SLOTTEE_MULTIHART_TICKET_TOTAL       20
#define SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS 7
#define SLOTTEE_MULTIHART_TICKET_MAX_TOTAL   64
#define SLOTTEE_MULTIHART_TICKET_MAGIC       0x51513737
#define SLOTTEE_MULTIHART_TICKET_CONFIG_MAGIC 0x51513838
#define SLOTTEE_EDGECALL_STRESS_MAGIC        0x51513939
#define SLOTTEE_TIMER_PREEMPT_MAGIC          0x51513a3a
#define SLOTTEE_EDGECALL_STRESS_FIRST_WORKER_SLOT 2
#define SLOTTEE_EDGECALL_STRESS_WORKERS      3
#define SLOTTEE_EDGECALL_STRESS_ITERS        100
#define SLOTTEE_EDGECALL_STRESS_LAST_WORKER_SLOT \
  (SLOTTEE_EDGECALL_STRESS_FIRST_WORKER_SLOT + \
   SLOTTEE_EDGECALL_STRESS_WORKERS - 1)
#define SLOTTEE_MULTIHART_FAIRNESS_POLICY_RR 1
#define SLOTTEE_MULTIHART_JOIN_MODE_SPIN     0
#define SLOTTEE_MULTIHART_JOIN_MODE_WAIT     1
#define SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT 2
#define SLOTTEE_TIMER_PREEMPT_WORKERS        3
#define SLOTTEE_TIMER_PREEMPT_LAST_WORKER_SLOT \
  (SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT + \
   SLOTTEE_TIMER_PREEMPT_WORKERS - 1)
#define SLOTTEE_TIMER_PREEMPT_ITERS          8000000UL

struct slottee_multihart_ticket_config {
  uintptr_t magic;
  uintptr_t windows;
  uintptr_t total_tickets;
  uintptr_t join_mode;
  uintptr_t wait_budget;
};

struct slottee_multihart_ticket_report {
  uintptr_t magic;
  uintptr_t configured_windows;
  uintptr_t max_windows;
  uintptr_t total_tickets;
  uintptr_t join_mode;
  uintptr_t wait_calls;
  uintptr_t wait_blocks;
  uintptr_t wait_wakeups;
  uintptr_t wait_notify_misses;
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t user_context_entries;
  uintptr_t user_context_exits;
  uintptr_t syscall_traps;
  uintptr_t ocall_traps;
  uintptr_t ocall_resumes;
  uintptr_t exit_traps;
  uintptr_t timer_wait_stops;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t tls_resume_ok;
  uintptr_t ready_windows;
  uintptr_t nonzero_windows;
  uintptr_t min_sold;
  uintptr_t max_sold;
  uintptr_t fairness_gap;
  uintptr_t fairness_policy;
  uintptr_t fairness_budget;
  uintptr_t fairness_policy_ok;
  uintptr_t dominant_window;
  uintptr_t total_sold;
  uintptr_t remaining_tickets;
  uintptr_t active_workers;
  uintptr_t failures;
  uintptr_t hart_id[SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS];
  uintptr_t sold[SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS];
};

struct slottee_edgecall_stress_payload {
  uintptr_t slot_id;
  uintptr_t iter;
  uintptr_t marker;
  uintptr_t checksum;
};

struct slottee_edgecall_stress_report {
  uintptr_t magic;
  uintptr_t worker_slots;
  uintptr_t per_lt_iters;
  uintptr_t expected_worker_ocalls;
  uintptr_t total_ocalls;
  uintptr_t worker_ocalls;
  uintptr_t main_ocalls;
  uintptr_t failures;
  uintptr_t context_corruption_count;
  uintptr_t ready_workers;
  uintptr_t active_workers;
  uintptr_t wait_calls;
  uintptr_t wait_blocks;
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t ocall_traps;
  uintptr_t ocall_resumes;
};

struct slottee_timer_preempt_report {
  uintptr_t magic;
  uintptr_t worker_slots;
  uintptr_t iterations_per_worker;
  uintptr_t completed_workers;
  uintptr_t active_workers;
  uintptr_t ready_workers;
  uintptr_t failures;
  uintptr_t wait_calls;
  uintptr_t wait_blocks;
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
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
  uintptr_t timer_wait_stops;
  uintptr_t user_context_entries;
  uintptr_t user_context_exits;
  uintptr_t syscall_traps;
  uintptr_t exit_traps;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t worker_checksums[SLOTTEE_TIMER_PREEMPT_WORKERS];
};

#endif
