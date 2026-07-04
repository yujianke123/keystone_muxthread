#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

#define OCALL_TIMER_PREEMPT_REPORT 10

static long active_workers;
static long ready_workers;
static long completed_workers;
static long failures;
static long wait_calls;
static long wait_blocks;
static long notify_calls;
static long notify_wakes;
static uintptr_t worker_checksums[SLOTTEE_TIMER_PREEMPT_WORKERS];
static struct slottee_timer_preempt_report final_report;

static uintptr_t
slottee_read_tp(void)
{
  uintptr_t tp;

  __asm__ volatile("mv %0, tp" : "=r"(tp));
  return tp;
}

static void
slottee_return_with_tp(uintptr_t tp, unsigned long value)
    __attribute__((noreturn));

static void
slottee_return_with_tp(uintptr_t tp, unsigned long value)
{
  __asm__ volatile("mv tp, %0" :: "r"(tp) : "memory");
  EAPP_RETURN(value);
}

static void
notify_value(const long* ptr)
{
  int ret = slottee_lt_notify_value(ptr);

  slottee_atomic_fetch_add(&notify_calls, 1);
  if (ret == SLOTTEE_LT_NOTIFY_RESULT_WOKE)
    slottee_atomic_fetch_add(&notify_wakes, 1);
}

static void
wait_until_value(const long* ptr, long target, uintptr_t op)
{
  uintptr_t budget = 131072;

  while (1) {
    int ret = slottee_lt_wait_value(ptr, target, op);

    slottee_atomic_fetch_add(&wait_calls, 1);
    if (ret == SLOTTEE_LT_WAIT_RESULT_READY)
      return;
    if (ret == SLOTTEE_LT_WAIT_RESULT_BLOCKED)
      slottee_atomic_fetch_add(&wait_blocks, 1);
    else
      slottee_atomic_fetch_add(&failures, 1);

    if (--budget == 0) {
      slottee_atomic_fetch_add(&failures, 1);
      return;
    }
  }
}

static uintptr_t
run_busy_loop(uintptr_t slot_id)
{
  volatile uintptr_t acc =
      SLOTTEE_TIMER_PREEMPT_MAGIC ^ (slot_id << 8);

  for (uintptr_t iter = 0; iter < SLOTTEE_TIMER_PREEMPT_ITERS; iter++) {
    acc += (iter ^ slot_id) + 1;
    acc ^= (acc << 7) ^ (acc >> 3);
  }

  return acc;
}

static int
collect_drained_runtime_stats(struct slottee_lt_runtime_stats* rt_stats)
{
  for (uintptr_t attempt = 0; attempt < 4096; attempt++) {
    if (slottee_lt_collect_stats(rt_stats) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      return -1;
    if (rt_stats->user_context_exits >= SLOTTEE_TIMER_PREEMPT_WORKERS &&
        rt_stats->scheduler_unfinished == 0)
      return 0;
    for (volatile uintptr_t spin = 0; spin < 1024; spin++)
      ;
  }

  return 0;
}

static void
timer_preempt_worker(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t slot_id = (uintptr_t)opaque;
  uintptr_t worker_index =
      slot_id - SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT;

  if (slot_id < SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT ||
      slot_id > SLOTTEE_TIMER_PREEMPT_LAST_WORKER_SLOT) {
    slottee_atomic_fetch_add(&failures, 1);
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&active_workers, 1);
  slottee_atomic_fetch_add(&ready_workers, 1);
  notify_value(&ready_workers);

  worker_checksums[worker_index] = run_busy_loop(slot_id);

  slottee_atomic_fetch_add(&completed_workers, 1);
  slottee_atomic_fetch_sub(&active_workers, 1);
  notify_value(&completed_workers);
  notify_value(&active_workers);
  slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t slot_id;
  struct slottee_lt_runtime_stats rt_stats;

  slottee_atomic_store(&active_workers, 0);
  slottee_atomic_store(&ready_workers, 0);
  slottee_atomic_store(&completed_workers, 0);
  slottee_atomic_store(&failures, 0);
  slottee_atomic_store(&wait_calls, 0);
  slottee_atomic_store(&wait_blocks, 0);
  slottee_atomic_store(&notify_calls, 0);
  slottee_atomic_store(&notify_wakes, 0);
  memset(worker_checksums, 0, sizeof(worker_checksums));

  for (slot_id = SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT;
       slot_id <= SLOTTEE_TIMER_PREEMPT_LAST_WORKER_SLOT; slot_id++) {
    if (slottee_lt_spawn(slot_id, timer_preempt_worker,
            (void*)slot_id) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  wait_until_value(&ready_workers, SLOTTEE_TIMER_PREEMPT_WORKERS,
      SLOTTEE_LT_WAIT_OP_GE);
  wait_until_value(&completed_workers, SLOTTEE_TIMER_PREEMPT_WORKERS,
      SLOTTEE_LT_WAIT_OP_GE);
  wait_until_value(&active_workers, 0, SLOTTEE_LT_WAIT_OP_EQ);

  memset(&rt_stats, 0, sizeof(rt_stats));
  if (collect_drained_runtime_stats(&rt_stats) != 0)
    slottee_atomic_fetch_add(&failures, 1);

  memset(&final_report, 0, sizeof(final_report));
  final_report.magic = SLOTTEE_TIMER_PREEMPT_MAGIC;
  final_report.worker_slots = SLOTTEE_TIMER_PREEMPT_WORKERS;
  final_report.iterations_per_worker = SLOTTEE_TIMER_PREEMPT_ITERS;
  final_report.completed_workers =
      (uintptr_t)slottee_atomic_load(&completed_workers);
  final_report.active_workers = (uintptr_t)slottee_atomic_load(&active_workers);
  final_report.ready_workers = (uintptr_t)slottee_atomic_load(&ready_workers);
  final_report.failures = (uintptr_t)slottee_atomic_load(&failures);
  final_report.wait_calls = (uintptr_t)slottee_atomic_load(&wait_calls);
  final_report.wait_blocks = (uintptr_t)slottee_atomic_load(&wait_blocks);
  final_report.notify_calls = (uintptr_t)slottee_atomic_load(&notify_calls);
  final_report.notify_wakes = (uintptr_t)slottee_atomic_load(&notify_wakes);
  final_report.preempt_count = rt_stats.preempt_count;
  final_report.preempt_yields = rt_stats.preempt_yields;
  final_report.preempt_dispatches = rt_stats.preempt_dispatches;
  final_report.runnable_queue_depth = rt_stats.runnable_queue_depth;
  final_report.wait_queue_depth = rt_stats.wait_queue_depth;
  final_report.scheduler_duplicate_rejects =
      rt_stats.scheduler_duplicate_rejects;
  final_report.scheduler_queue_leaks = rt_stats.scheduler_queue_leaks;
  final_report.scheduler_wait_residue = rt_stats.scheduler_wait_residue;
  final_report.scheduler_unfinished = rt_stats.scheduler_unfinished;
  final_report.fairness_min = rt_stats.fairness_min;
  final_report.fairness_max = rt_stats.fairness_max;
  final_report.fairness_gap = rt_stats.fairness_gap;
  final_report.fairness_checks = rt_stats.fairness_checks;
  final_report.fairness_violations = rt_stats.fairness_violations;
  final_report.timer_wait_stops = rt_stats.timer_wait_stops;
  final_report.user_context_entries = rt_stats.user_context_entries;
  final_report.user_context_exits = rt_stats.user_context_exits;
  final_report.syscall_traps = rt_stats.syscall_traps;
  final_report.exit_traps = rt_stats.exit_traps;
  final_report.stack_entry_ok = rt_stats.stack_entry_ok;
  final_report.stack_exit_ok = rt_stats.stack_exit_ok;
  final_report.tls_entry_ok = rt_stats.tls_entry_ok;
  final_report.tls_exit_ok = rt_stats.tls_exit_ok;
  final_report.tls_exit_mismatch = rt_stats.tls_exit_mismatch;
  for (uintptr_t worker = 0; worker < SLOTTEE_TIMER_PREEMPT_WORKERS; worker++)
    final_report.worker_checksums[worker] = worker_checksums[worker];

  if (final_report.completed_workers != SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.active_workers != 0 ||
      final_report.ready_workers != SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.preempt_count == 0 ||
      final_report.preempt_yields == 0 ||
      final_report.preempt_dispatches == 0 ||
      final_report.runnable_queue_depth != 0 ||
      final_report.wait_queue_depth != 0 ||
      final_report.scheduler_queue_leaks != 0 ||
      final_report.scheduler_wait_residue != 0 ||
      final_report.scheduler_unfinished != 0 ||
      final_report.fairness_checks == 0 ||
      final_report.fairness_violations != 0 ||
      final_report.user_context_entries < SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.user_context_exits < SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.stack_entry_ok < SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.stack_exit_ok < SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.tls_entry_ok < SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.tls_exit_ok < SLOTTEE_TIMER_PREEMPT_WORKERS ||
      final_report.tls_exit_mismatch != 0)
    final_report.failures++;

  if (ocall(OCALL_TIMER_PREEMPT_REPORT, &final_report,
          sizeof(final_report), 0, 0) != 0)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  slottee_return_with_tp(saved_tp, final_report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
