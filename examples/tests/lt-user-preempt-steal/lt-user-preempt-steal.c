#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

/*
 * 第43阶段：跨 hart 工作窃取/迁移（--enter-slot-preempt-steal）。
 *
 * 复用 multihart 的 2 组 × 2 worker 槽布局，但负载不对称：group0 的 worker 很短、
 * group1 的 worker 很长。group0 的 hart 很快跑完自己的短 worker，其 runnable 队列
 * 变空后会从 group1 偷一个排队中的长 worker 迁到本 hart 跑（PREEMPT_RUN flags 启用
 * 窃取）。于是两个长 worker 能在两个 hart 上并行收尾。
 *
 * 复用 OCALL_PREEMPT_MULTIHART_REPORT(12) 与 multihart report 结构（带 steals）；
 * host 端按 STEAL_MAGIC 区分，并验证 总 completed==总 worker 数、总 steals>0、
 * 每个 worker 的确定性 checksum 与 host 重算一致（按其所属组的 iters）。
 */

#define OCALL_PREEMPT_MULTIHART_REPORT 12

#define PREEMPT_STEAL_TOTAL_WORKERS \
  (SLOTTEE_PREEMPT_MULTIHART_GROUPS * SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP)

static long group_done;
static long group_failed;
static uintptr_t worker_checksums[PREEMPT_STEAL_TOTAL_WORKERS];

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

static uintptr_t
preempt_steal_iters(uintptr_t flat_index)
{
  uintptr_t group = flat_index / SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP;

  return group == 0 ? SLOTTEE_PREEMPT_STEAL_SHORT_ITERS
                    : SLOTTEE_PREEMPT_STEAL_LONG_ITERS;
}

static uintptr_t
preempt_steal_checksum(uintptr_t flat_index)
{
  volatile uintptr_t acc = SLOTTEE_PREEMPT_STEAL_MAGIC ^ (flat_index << 8);
  uintptr_t iters = preempt_steal_iters(flat_index);

  for (uintptr_t iter = 0; iter < iters; iter++) {
    acc += (iter ^ flat_index) + 1;
    acc ^= (acc << 7) ^ (acc >> 3);
  }

  return acc;
}

static void
preempt_worker(void* opaque)
{
  uintptr_t flat = (uintptr_t)opaque;

  if (flat < PREEMPT_STEAL_TOTAL_WORKERS)
    worker_checksums[flat] = preempt_steal_checksum(flat);

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void
preempt_steal_sched_entry(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t group_id = (uintptr_t)opaque;
  struct slottee_preempt_spec specs[SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP];
  struct slottee_preempt_sched_stats stats;
  struct slottee_preempt_multihart_report report;
  uintptr_t completed;
  uintptr_t min_preempts = (uintptr_t)-1;

  for (uintptr_t w = 0; w < SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP; w++) {
    specs[w].fn = (uintptr_t)&preempt_worker;
    specs[w].arg = group_id * SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP + w;
    specs[w].slot = SLOTTEE_PREEMPT_MULTIHART_WORKER_SLOT(group_id, w);
  }

  completed = (uintptr_t)slottee_preempt_run(specs,
      SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP,
      SLOTTEE_PREEMPT_STEAL_BUDGET, SLOTTEE_PREEMPT_STEAL_FLAG);

  memset(&stats, 0, sizeof(stats));
  slottee_preempt_collect_stats(&stats);

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_PREEMPT_STEAL_MAGIC;
  report.group_id = group_id;
  report.scheduler_slot = SLOTTEE_PREEMPT_MULTIHART_SCHED_SLOT(group_id);
  report.worker_count = SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP;
  report.completed_workers = completed;
  report.preempt_switches = stats.preempt_switches;
  report.preempt_ticks = stats.preempt_ticks;
  report.host_yields = stats.host_yields;
  report.exit_switches = stats.exit_switches;
  report.runnable_queue_depth = stats.runnable_queue_depth;
  report.scheduler_queue_leaks = stats.scheduler_queue_leaks;
  report.scheduler_wait_residue = stats.scheduler_wait_residue;
  report.scheduler_unfinished = stats.scheduler_unfinished;
  report.scheduler_duplicate_rejects = stats.scheduler_duplicate_rejects;
  report.fairness_gap = stats.fairness_gap;
  report.fairness_violations = stats.fairness_violations;
  report.steals = stats.steals;
  report.steal_skips = stats.steal_skips;
  for (uintptr_t w = 0; w < SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP; w++) {
    uintptr_t flat = group_id * SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP + w;

    report.per_worker_slot[w] = stats.per_worker_slot[w];
    report.per_worker_dispatch[w] = stats.per_worker_dispatch[w];
    report.per_worker_preempts[w] = stats.per_worker_preempts[w];
    report.worker_checksums[w] = worker_checksums[flat];
    if (stats.per_worker_preempts[w] < min_preempts)
      min_preempts = stats.per_worker_preempts[w];
  }
  if (min_preempts == (uintptr_t)-1)
    min_preempts = 0;
  report.min_preempts = min_preempts;

  /* Per-group sanity only; the cross-group sum/steal verdict is host-side
   * (stealing makes per-group completed uneven by design). */
  if (report.runnable_queue_depth != 0 ||
      report.scheduler_queue_leaks != 0 ||
      report.scheduler_unfinished != 0 ||
      report.scheduler_duplicate_rejects != 0 ||
      report.fairness_violations != 0 ||
      stats.active != 0)
    report.failures++;

  if (ocall(OCALL_PREEMPT_MULTIHART_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;

  slottee_atomic_fetch_add(&group_failed, (long)report.failures);
  slottee_atomic_fetch_add(&group_done, 1);
  slottee_lt_notify_value(&group_done);

  slottee_return_with_tp(saved_tp, report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t budget = 1u << 20;

  slottee_atomic_store(&group_done, 0);
  slottee_atomic_store(&group_failed, 0);
  memset(worker_checksums, 0, sizeof(worker_checksums));

  for (uintptr_t g = 0; g < SLOTTEE_PREEMPT_MULTIHART_GROUPS; g++) {
    if (slottee_lt_spawn(SLOTTEE_PREEMPT_MULTIHART_SCHED_SLOT(g),
            preempt_steal_sched_entry, (void*)g) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  while (slottee_atomic_load(&group_done) < SLOTTEE_PREEMPT_MULTIHART_GROUPS) {
    int ret = slottee_lt_wait_value(&group_done,
        SLOTTEE_PREEMPT_MULTIHART_GROUPS, SLOTTEE_LT_WAIT_OP_GE);

    if (ret != SLOTTEE_LT_WAIT_RESULT_READY &&
        ret != SLOTTEE_LT_WAIT_RESULT_BLOCKED) {
      slottee_atomic_fetch_add(&group_failed, 1);
      break;
    }
    if (--budget == 0) {
      slottee_atomic_fetch_add(&group_failed, 1);
      break;
    }
  }

  slottee_return_with_tp(saved_tp,
      slottee_atomic_load(&group_failed) ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
