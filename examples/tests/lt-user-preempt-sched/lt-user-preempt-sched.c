#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

/*
 * OS-level preemptive timer scheduler demo (--enter-slot-preempt-sched).
 *
 * Topology:
 *   - eapp_entry (thread 0, first boot): spawns the scheduler LT on a
 *     timer-redirectable LT_USER_OCALL slot, then idles waiting for it.
 *   - preempt_sched_entry (scheduler slot): hands a set of pure busy-loop worker
 *     specs to the Eyrie RT preempt scheduler via slottee_preempt_run(), which
 *     time-slices them entirely in-enclave (timer-driven context switches, no
 *     host-mediated resume), then reports the result.
 *   - preempt_worker: a deterministic busy loop with NO syscalls / cooperative
 *     yields, so the only way control leaves it mid-loop is a timer preemption.
 */

#define OCALL_PREEMPT_SCHED_REPORT 11

static long sched_done;
static long sched_failed;
static uintptr_t worker_checksums[SLOTTEE_PREEMPT_SCHED_WORKERS];
static struct slottee_preempt_sched_report final_report;

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

/*
 * Deterministic per-worker work: a function of the worker index only, so the
 * host can recompute the expected checksum and confirm the worker ran its whole
 * loop to completion despite being preempted mid-flight.
 */
static uintptr_t
preempt_worker_checksum(uintptr_t index)
{
  volatile uintptr_t acc = SLOTTEE_PREEMPT_SCHED_MAGIC ^ (index << 8);

  for (uintptr_t iter = 0; iter < SLOTTEE_PREEMPT_SCHED_ITERS; iter++) {
    acc += (iter ^ index) + 1;
    acc ^= (acc << 7) ^ (acc >> 3);
  }

  return acc;
}

static void
preempt_worker(void* opaque)
{
  uintptr_t index = (uintptr_t)opaque;

  if (index < SLOTTEE_PREEMPT_SCHED_WORKERS)
    worker_checksums[index] = preempt_worker_checksum(index);

  /* Must EXIT (never fall through): the RT exit hook retires this LT and
   * switches into the next runnable worker. */
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void
preempt_sched_entry(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  struct slottee_preempt_spec specs[SLOTTEE_PREEMPT_SCHED_WORKERS];
  struct slottee_preempt_sched_stats stats;
  uintptr_t completed;
  uintptr_t min_preempts = (uintptr_t)-1;

  (void)opaque;

  memset(worker_checksums, 0, sizeof(worker_checksums));
  for (uintptr_t i = 0; i < SLOTTEE_PREEMPT_SCHED_WORKERS; i++) {
    specs[i].fn = (uintptr_t)&preempt_worker;
    specs[i].arg = i;
  }

  /* Blocks here (in the eapp's view): the RT switches away to the workers and
   * only returns once every worker has exited, with a0 = completed count. */
  completed = (uintptr_t)slottee_preempt_run(specs, SLOTTEE_PREEMPT_SCHED_WORKERS);

  memset(&stats, 0, sizeof(stats));
  slottee_preempt_collect_stats(&stats);

  memset(&final_report, 0, sizeof(final_report));
  final_report.magic = SLOTTEE_PREEMPT_SCHED_MAGIC;
  final_report.worker_count = SLOTTEE_PREEMPT_SCHED_WORKERS;
  final_report.iterations_per_worker = SLOTTEE_PREEMPT_SCHED_ITERS;
  final_report.completed_workers = completed;
  final_report.preempt_switches = stats.preempt_switches;
  final_report.preempt_ticks = stats.preempt_ticks;
  final_report.host_yields = stats.host_yields;
  final_report.exit_switches = stats.exit_switches;
  final_report.runnable_queue_depth = stats.runnable_queue_depth;
  final_report.scheduler_queue_leaks = stats.scheduler_queue_leaks;
  final_report.scheduler_wait_residue = stats.scheduler_wait_residue;
  final_report.scheduler_unfinished = stats.scheduler_unfinished;
  final_report.scheduler_duplicate_rejects = stats.scheduler_duplicate_rejects;
  final_report.fairness_min = stats.fairness_min;
  final_report.fairness_max = stats.fairness_max;
  final_report.fairness_gap = stats.fairness_gap;
  final_report.fairness_violations = stats.fairness_violations;

  for (uintptr_t i = 0; i < SLOTTEE_PREEMPT_SCHED_WORKERS; i++) {
    final_report.per_worker_dispatch[i] = stats.per_worker_dispatch[i];
    final_report.per_worker_preempts[i] = stats.per_worker_preempts[i];
    final_report.worker_checksums[i] = worker_checksums[i];
    if (stats.per_worker_preempts[i] < min_preempts)
      min_preempts = stats.per_worker_preempts[i];
  }
  if (min_preempts == (uintptr_t)-1)
    min_preempts = 0;
  final_report.min_preempts = min_preempts;

  if (final_report.completed_workers != SLOTTEE_PREEMPT_SCHED_WORKERS ||
      final_report.host_yields != 0 ||
      final_report.preempt_switches == 0 ||
      final_report.min_preempts == 0 ||
      final_report.runnable_queue_depth != 0 ||
      final_report.scheduler_queue_leaks != 0 ||
      final_report.scheduler_wait_residue != 0 ||
      final_report.scheduler_unfinished != 0 ||
      final_report.scheduler_duplicate_rejects != 0 ||
      final_report.fairness_violations != 0 ||
      stats.active != 0)
    final_report.failures++;

  if (ocall(OCALL_PREEMPT_SCHED_REPORT, &final_report,
          sizeof(final_report), 0, 0) != 0)
    final_report.failures++;

  slottee_atomic_store(&sched_failed, (long)final_report.failures);
  slottee_atomic_store(&sched_done, 1);
  slottee_lt_notify_value(&sched_done);

  slottee_return_with_tp(saved_tp, final_report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t budget = 1u << 20;

  slottee_atomic_store(&sched_done, 0);
  slottee_atomic_store(&sched_failed, 0);

  if (slottee_lt_spawn(SLOTTEE_PREEMPT_SCHED_SCHEDULER_SLOT,
          preempt_sched_entry, 0) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  /* Idle until the host-entered scheduler slot finishes all workers. */
  while (slottee_atomic_load(&sched_done) == 0) {
    int ret = slottee_lt_wait_value(&sched_done, 1, SLOTTEE_LT_WAIT_OP_GE);

    if (ret != SLOTTEE_LT_WAIT_RESULT_READY &&
        ret != SLOTTEE_LT_WAIT_RESULT_BLOCKED) {
      slottee_atomic_fetch_add(&sched_failed, 1);
      break;
    }
    if (--budget == 0) {
      slottee_atomic_fetch_add(&sched_failed, 1);
      break;
    }
  }

  slottee_return_with_tp(saved_tp,
      slottee_atomic_load(&sched_failed) ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
