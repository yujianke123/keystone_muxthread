#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

/*
 * 第48阶段：复杂多线程程序——并发账本（--enter-slot-ledger）。
 *
 * 8 个 worker LT（2 组 × 4，跨 2 hart，由抢占式调度器时间片轮转）并发地对一个共享 16 账户
 * 账本做大量原子转账：每个 worker 做 TRANSFERS 次「src 账户 -1，dst 账户 +1」，并原子累加
 * 全局转账计数。每笔转账对总额守恒；src/dst 序列对每个 worker 完全确定（仅由 flat 与 j 决定），
 * 故最终每账户余额与总转账数都是交错无关、可由 host 逐笔回放精确重算的。
 *
 * 两层结构：① 每组用 slottee_preempt_run 在自己 hart 上抢占式轮转 4 个 worker；② 主线程
 * （thread0）先初始化账本，再 spawn 2 个 scheduler LT，最后用 LT wait/notify 汇合两组，组装
 * 一份账本 report OCALL 给 host 精确校验。
 */

#define OCALL_LEDGER_REPORT 15

/* 全部 LT 共享同一 eapp 地址空间，下列全局即跨 hart 共享内存。 */
static long ledger_accounts[SLOTTEE_LEDGER_ACCOUNTS];
static long ledger_txn_count;
static long ledger_completed;
static long ledger_switches;
static long ledger_host_yields;
static long group_done;
static long group_failed;

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
 * 确定性 src/dst：仅由 (flat, j) 决定，host 用完全相同的公式逐笔回放。
 * src = flat 的「主账户」（被持续扣款）；dst 在 16 账户间轮转（贷记铺开）。
 * 不同 worker 扣不同主账户 → 各账户最终余额各不相同，使精确匹配校验有意义。
 */
static uintptr_t
ledger_src(uintptr_t flat, long j)
{
  (void)j;
  return flat % SLOTTEE_LEDGER_ACCOUNTS;
}

static uintptr_t
ledger_dst(uintptr_t flat, long j)
{
  return (uintptr_t)((flat * 3 + (uintptr_t)j * 7 + 1) % SLOTTEE_LEDGER_ACCOUNTS);
}

static void
ledger_worker(void* opaque)
{
  uintptr_t flat = (uintptr_t)opaque;

  for (long j = 0; j < SLOTTEE_LEDGER_TRANSFERS; j++) {
    uintptr_t src = ledger_src(flat, j);
    uintptr_t dst = ledger_dst(flat, j);

    slottee_atomic_fetch_sub(&ledger_accounts[src], 1);
    slottee_atomic_fetch_add(&ledger_accounts[dst], 1);
    slottee_atomic_fetch_add(&ledger_txn_count, 1);
  }

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void
ledger_sched_entry(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t group_id = (uintptr_t)opaque;
  struct slottee_preempt_spec specs[SLOTTEE_LEDGER_WORKERS_PER_GROUP];
  struct slottee_preempt_sched_stats stats;
  uintptr_t completed;
  long failures = 0;

  for (uintptr_t w = 0; w < SLOTTEE_LEDGER_WORKERS_PER_GROUP; w++) {
    specs[w].fn = (uintptr_t)&ledger_worker;
    specs[w].arg = group_id * SLOTTEE_LEDGER_WORKERS_PER_GROUP + w;
    specs[w].slot = SLOTTEE_LEDGER_WORKER_SLOT(group_id, w);
  }

  completed = (uintptr_t)slottee_preempt_run(specs,
      SLOTTEE_LEDGER_WORKERS_PER_GROUP, SLOTTEE_LEDGER_BUDGET, 0);

  memset(&stats, 0, sizeof(stats));
  slottee_preempt_collect_stats(&stats);

  /* 调度自检：本组全部 worker 完成、调度器队列一致性干净。 */
  if (completed != SLOTTEE_LEDGER_WORKERS_PER_GROUP ||
      stats.runnable_queue_depth != 0 ||
      stats.scheduler_queue_leaks != 0 ||
      stats.scheduler_unfinished != 0 ||
      stats.scheduler_duplicate_rejects != 0 ||
      stats.fairness_violations != 0 ||
      stats.active != 0)
    failures++;

  slottee_atomic_fetch_add(&ledger_completed, (long)completed);
  slottee_atomic_fetch_add(&ledger_switches, (long)stats.preempt_switches);
  slottee_atomic_fetch_add(&ledger_host_yields, (long)stats.host_yields);
  slottee_atomic_fetch_add(&group_failed, failures);
  slottee_atomic_fetch_add(&group_done, 1);
  slottee_lt_notify_value(&group_done);

  slottee_return_with_tp(saved_tp, failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t budget = 1u << 20;
  struct slottee_ledger_report report;

  /* 先初始化账本，再放出 worker。 */
  for (uintptr_t a = 0; a < SLOTTEE_LEDGER_ACCOUNTS; a++)
    slottee_atomic_store(&ledger_accounts[a], SLOTTEE_LEDGER_INIT);
  slottee_atomic_store(&ledger_txn_count, 0);
  slottee_atomic_store(&ledger_completed, 0);
  slottee_atomic_store(&ledger_switches, 0);
  slottee_atomic_store(&ledger_host_yields, 0);
  slottee_atomic_store(&group_done, 0);
  slottee_atomic_store(&group_failed, 0);

  for (uintptr_t g = 0; g < SLOTTEE_LEDGER_GROUPS; g++) {
    if (slottee_lt_spawn(SLOTTEE_LEDGER_SCHED_SLOT(g), ledger_sched_entry,
            (void*)g) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  /* 用 LT wait/notify 汇合所有 scheduler 组。 */
  while (slottee_atomic_load(&group_done) < SLOTTEE_LEDGER_GROUPS) {
    int ret = slottee_lt_wait_value(&group_done, SLOTTEE_LEDGER_GROUPS,
        SLOTTEE_LT_WAIT_OP_GE);

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

  /* 所有 worker 已退出 → 账本处于最终态，组装精确校验报告。 */
  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_LEDGER_MAGIC;
  report.accounts = SLOTTEE_LEDGER_ACCOUNTS;
  report.workers = SLOTTEE_LEDGER_TOTAL_WORKERS;
  report.transfers_per_worker = (uintptr_t)SLOTTEE_LEDGER_TRANSFERS;
  report.txn_count = slottee_atomic_load(&ledger_txn_count);
  report.completed_workers = slottee_atomic_load(&ledger_completed);
  report.total_switches = slottee_atomic_load(&ledger_switches);
  report.total_host_yields = slottee_atomic_load(&ledger_host_yields);
  report.group_failed = slottee_atomic_load(&group_failed);
  report.total_balance = 0;
  for (uintptr_t a = 0; a < SLOTTEE_LEDGER_ACCOUNTS; a++) {
    long bal = slottee_atomic_load(&ledger_accounts[a]);

    report.balances[a] = bal;
    report.total_balance += bal;
  }
  if (report.group_failed)
    report.failures++;

  if (ocall(OCALL_LEDGER_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;

  slottee_return_with_tp(saved_tp,
      report.failures ? SLOTTEE_LT_USER_ILLEGAL_MAGIC :
      SLOTTEE_LT_USER_OCALL_MAGIC);
}
