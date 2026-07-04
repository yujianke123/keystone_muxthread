#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

/*
 * 第47阶段：3 组 best-victim 验证（--enter-slot-preempt-bestvictim）。
 *
 * 单受害组（第43-46阶段的 2 组 steal 测试）无法证明 try_steal 的"最忙受害组选择"。
 * 这里用 3 个 scheduler 组（各绑一 hart）构造两个 runnable 深度不同的受害组：
 *   group0(thief)  : 1 个 SHORT worker → 很快退出 → 空闲去偷
 *   group1(victimA): 2 个 LONG worker  → 稳定 runnable count=1
 *   group2(victimB): 3 个 LONG worker  → 稳定 runnable count=2（最忙）
 * thief 空闲后应当在 victimA(1)/victimB(2) 中选最忙的 victimB。每组 collect_stats 后把
 * steal_victim_slot/steal_victim_count 填进 BV report OCALL 给 host 断言。
 *
 * 不在此校验 per-worker checksum（迁移保真已由 2 组 steal 测试覆盖）；本测试聚焦"选择
 * 哪个受害组"。worker 仍跑非可消除的累加 busy-loop，host 据 total_completed/queue 一致性
 * 验证全部完成且调度器干净。
 */

#define OCALL_PREEMPT_BV_REPORT 14

static const uintptr_t bv_sched_slot[SLOTTEE_PREEMPT_BV_GROUPS] = {
  SLOTTEE_PREEMPT_BV_SCHED_G0,
  SLOTTEE_PREEMPT_BV_SCHED_G1,
  SLOTTEE_PREEMPT_BV_SCHED_G2,
};
static const uintptr_t bv_worker_count[SLOTTEE_PREEMPT_BV_GROUPS] = {
  SLOTTEE_PREEMPT_BV_WORKERS_G0,
  SLOTTEE_PREEMPT_BV_WORKERS_G1,
  SLOTTEE_PREEMPT_BV_WORKERS_G2,
};
/* flat worker id 的每组基址（= 前面各组 worker 数累加）：g0=0, g1=2, g2=4 */
static const uintptr_t bv_flat_base[SLOTTEE_PREEMPT_BV_GROUPS] = {
  0,
  SLOTTEE_PREEMPT_BV_WORKERS_G0,
  SLOTTEE_PREEMPT_BV_WORKERS_G0 + SLOTTEE_PREEMPT_BV_WORKERS_G1,
};
/* 只有 group0(thief) 开启窃取；victim 组关闭，避免多个欠载组竞争最忙受害组。 */
static const uintptr_t bv_group_flag[SLOTTEE_PREEMPT_BV_GROUPS] = {
  SLOTTEE_PREEMPT_BV_FLAG, 0, 0,
};

static long group_done;
static long group_failed;
static volatile uintptr_t worker_sink[SLOTTEE_PREEMPT_BV_TOTAL_WORKERS];

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
 * group0 = {flat0 SHORT, flat1 MEDIUM}：short 很快退出后 medium 仍在跑、runnable 队列空，
 * 让 group0 作为唯一窃取者持续主动 rebalance 且不至于过早退出；victim 组(flat>=2)全是 LONG，
 * 保持 victimA count=1 / victimB count=2 的稳定失衡窗口。
 */
static uintptr_t
bv_worker_iters(uintptr_t flat_index)
{
  if (flat_index == 0)
    return SLOTTEE_PREEMPT_BV_SHORT_ITERS;
  if (flat_index == 1)
    return SLOTTEE_PREEMPT_BV_MED_ITERS;
  return SLOTTEE_PREEMPT_BV_LONG_ITERS;
}

static void
bv_worker(void* opaque)
{
  uintptr_t flat = (uintptr_t)opaque;
  uintptr_t iters = bv_worker_iters(flat);
  volatile uintptr_t acc = SLOTTEE_PREEMPT_BV_MAGIC ^ (flat << 8);

  for (uintptr_t iter = 0; iter < iters; iter++) {
    acc += (iter ^ flat) + 1;
    acc ^= (acc << 7) ^ (acc >> 3);
  }
  if (flat < SLOTTEE_PREEMPT_BV_TOTAL_WORKERS)
    worker_sink[flat] = acc;

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void
bv_sched_entry(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t group_id = (uintptr_t)opaque;
  uintptr_t wcount = bv_worker_count[group_id];
  uintptr_t base_slot = bv_sched_slot[group_id] + 1;
  struct slottee_preempt_spec specs[SLOTTEE_PREEMPT_BV_MAX_WORKERS];
  struct slottee_preempt_sched_stats stats;
  struct slottee_preempt_bestvictim_report report;
  uintptr_t completed;

  for (uintptr_t w = 0; w < wcount; w++) {
    specs[w].fn = (uintptr_t)&bv_worker;
    specs[w].arg = bv_flat_base[group_id] + w;
    specs[w].slot = base_slot + w;
  }

  completed = (uintptr_t)slottee_preempt_run(specs, wcount,
      SLOTTEE_PREEMPT_BV_BUDGET, bv_group_flag[group_id]);

  memset(&stats, 0, sizeof(stats));
  slottee_preempt_collect_stats(&stats);

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_PREEMPT_BV_MAGIC;
  report.group_id = group_id;
  report.scheduler_slot = bv_sched_slot[group_id];
  report.worker_count = wcount;
  report.completed_workers = completed;
  report.steals = stats.steals;
  report.steal_skips = stats.steal_skips;
  report.rebalances = stats.rebalances;
  report.steal_victim_slot = stats.steal_victim_slot;
  report.steal_victim_count = stats.steal_victim_count;
  report.runnable_queue_depth = stats.runnable_queue_depth;
  report.scheduler_queue_leaks = stats.scheduler_queue_leaks;
  report.scheduler_unfinished = stats.scheduler_unfinished;
  report.scheduler_duplicate_rejects = stats.scheduler_duplicate_rejects;
  report.fairness_violations = stats.fairness_violations;

  if (report.runnable_queue_depth != 0 ||
      report.scheduler_queue_leaks != 0 ||
      report.scheduler_unfinished != 0 ||
      report.scheduler_duplicate_rejects != 0 ||
      report.fairness_violations != 0 ||
      stats.active != 0)
    report.failures++;

  if (ocall(OCALL_PREEMPT_BV_REPORT, &report, sizeof(report), 0, 0) != 0)
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
  memset((void*)worker_sink, 0, sizeof(worker_sink));

  for (uintptr_t g = 0; g < SLOTTEE_PREEMPT_BV_GROUPS; g++) {
    if (slottee_lt_spawn(bv_sched_slot[g], bv_sched_entry, (void*)g) !=
        SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  while (slottee_atomic_load(&group_done) < SLOTTEE_PREEMPT_BV_GROUPS) {
    int ret = slottee_lt_wait_value(&group_done,
        SLOTTEE_PREEMPT_BV_GROUPS, SLOTTEE_LT_WAIT_OP_GE);

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
