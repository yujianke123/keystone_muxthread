#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

/*
 * ParTEE 式单/多线程矩阵乘法对比基准（--enter-slot-matmul）。一次 enclave run 测一个
 * (N, groups) 组合（host 经 config OCALL 指定）：
 *   - groups==0：**真正的 Keystone 单线程基线** —— thread0（enclave 入口线程）直接跑整段
 *     C=A×B kernel，零 slot / 零 LT / 零 PREEMPT_RUN / 零 wait-notify。即 stock Keystone
 *     enclave 单线程执行，rdcycle 紧贴 kernel，不含任何 SlotTEE 调度机制。这是 speedup 的分子。
 *   - groups==1：SlotTEE 单 worker（1 个 worker LT 算整个 C）—— 仅用于量化 SlotTEE 相对
 *     Keystone 基线的单线程调度开销（overhead = (c1-c0)/c0），不进 ParTEE 式三线对比图。
 *   - groups==2/4：SlotTEE 多线程，G 个 worker LT（host pthread 各进一个 scheduler slot、
 *     落在不同 hart）经 PREEMPT_RUN 在 enclave 内并行算 C 的不相交行块。
 * 每个 worker 用 rdcycle 自计其 compute 周期（同 hart delta，避免跨 hart 计数器不同步）；
 * host 对每个 N 取 max-worker-compute 作并行 compute 时间，speedup = compute(Keystone,0)/compute(N,G)。
 * C 由 (i,j) 确定 → 所有 groups 配置结果逐位一致（checksum 相等 + host 重算校验）。
 *
 * 用 PREEMPT_RUN 跑 worker：1 worker/组、budget=0、flags=0 → 计算全程留在 enclave 内
 * （timer 触发时只此一个 runnable，原地保留、零 host 中转），避免长计算被 timer 反复 stop 到
 * host 的往返风暴。Keystone 基线（groups==0）则不进 PREEMPT_RUN，与 stock Keystone 一样
 * 由 SM 在 timer 时 stop 到 host 再 resume（这正是要对标的基线行为）。
 */

#define OCALL_GET_MATMUL_CONFIG 16
#define OCALL_MATMUL_REPORT     17

/* A/B/C 共享于所有 LT（同一 eapp 地址空间）。int32，确定性填充，N<=512 下不溢出。 */
static int A[SLOTTEE_MATMUL_MAXN][SLOTTEE_MATMUL_MAXN];
static int B[SLOTTEE_MATMUL_MAXN][SLOTTEE_MATMUL_MAXN];
static int Bt[SLOTTEE_MATMUL_MAXN][SLOTTEE_MATMUL_MAXN];   /* B 转置：内层循环顺序访问，省 TLB */
static int C[SLOTTEE_MATMUL_MAXN][SLOTTEE_MATMUL_MAXN];

static long cfg_n;          /* 当前矩阵规模 N */
static long cfg_groups;     /* 当前线程数 G */
static long group_done;     /* 已完成的组数（worker AMO 更新，thread0 纯 poll join） */
static long group_failed;
static unsigned long wdur[SLOTTEE_MATMUL_WORKERS];   /* 每 worker 自计 compute 周期 */
static uintptr_t wr0[SLOTTEE_MATMUL_WORKERS];        /* P1 诊断: 每 worker 实际行区间 */
static uintptr_t wr1[SLOTTEE_MATMUL_WORKERS];

static unsigned long
read_cycles(void)
{
  unsigned long c;

  asm volatile("rdcycle %0" : "=r"(c));
  return c;
}

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
matmul_fill(long n)
{
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++) {
      A[i][j] = (int)((i * 7 + j * 3 + 1) & 0x7f);
      B[i][j] = (int)((i * 5 + j * 11 + 2) & 0x7f);
    }
  /* 转置 B：matmul 内层用 Bt[j][k] 顺序访问，与 A[i][k] 同为行优先，避免 QEMU softmmu
   * TLB 在列跨步访问下抖动（与算法等价，C 结果不变）。 */
  for (long k = 0; k < n; k++)
    for (long j = 0; j < n; j++)
      Bt[j][k] = B[k][j];
}

/* 计算 C 的行区间 [r0, r1) × 全部列 [0,n)。C[i][j] = sum_k A[i][k]*B[k][j]，
 * 用 Bt[j][k] 等价实现，内层两操作数均顺序访问。 */
static void
matmul_rows(long r0, long r1, long n)
{
  for (long i = r0; i < r1; i++)
    for (long j = 0; j < n; j++) {
      int s = 0;
      const int* arow = A[i];
      const int* brow = Bt[j];
      for (long k = 0; k < n; k++)
        s += arow[k] * brow[k];
      C[i][j] = s;
    }
}

static uintptr_t
matmul_checksum(long n)
{
  uintptr_t acc = 1469598103u;

  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++) {
      acc ^= (uintptr_t)(unsigned int)C[i][j];
      acc *= 1099511628211u;   /* FNV-1a 64 */
    }
  return acc;
}

/* PREEMPT_RUN worker：算本组行块并自计 compute 周期。 */
static void
matmul_worker(void* opaque)
{
  long g = (long)(uintptr_t)opaque;
  long n;
  long gc;

  /*
   * Acquire fence: this worker LT runs on a DIFFERENT hart than thread0, which
   * filled A/B/Bt then spawned us.  Under QEMU MTTCG (weak memory) thread0's fill
   * stores are not guaranteed visible here without a fence — a stale read makes
   * matmul_rows compute from zero/old A/Bt and silently corrupt this band's C
   * (root cause of the sporadic large-N multi-thread csum failure).  Pair with
   * thread0's release fence after matmul_fill().
   */
  __sync_synchronize();
  n = cfg_n;
  gc = cfg_groups;
  long rows = n / gc;
  long r0 = g * rows;
  long r1 = (g == gc - 1) ? n : (r0 + rows);   /* 末组兜底（n 均能整除 gc，此处稳妥） */
  unsigned long s, e;

  s = read_cycles();
  matmul_rows(r0, r1, n);
  e = read_cycles();
  if (g >= 0 && g < SLOTTEE_MATMUL_WORKERS) {
    wdur[g] = e - s;
    wr0[g] = (uintptr_t)r0;   /* P1 诊断: 回报实际行区间(索引被破坏可见) */
    wr1[g] = (uintptr_t)r1;
  }

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

/* 每组一个 scheduler LT：经 PREEMPT_RUN 跑 1 个 matmul worker（in-enclave，零 host 中转）。 */
static void
matmul_sched_entry(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  long g = (long)(uintptr_t)opaque;
  struct slottee_preempt_spec spec;
  uintptr_t completed;

  /* Acquire fence: this scheduler LT runs on a different hart than thread0 and
   * reads cfg_groups (set by thread0) to size the worker slot.  Pairs with
   * thread0's release fence after matmul_fill(); a stale cfg_groups would build a
   * wrong worker slot. */
  __sync_synchronize();
  spec.fn = (uintptr_t)&matmul_worker;
  spec.arg = (uintptr_t)g;
  spec.slot = SLOTTEE_MATMUL_FIRST_WORKER_SLOT + cfg_groups + g;  /* worker slot 不与 sched slot 冲突 */

  completed = (uintptr_t)slottee_preempt_run(&spec, 1, 0 /*budget*/, 0 /*flags*/);
  if (completed != 1)
    slottee_atomic_fetch_add(&group_failed, 1);

  slottee_atomic_fetch_add(&group_done, 1);
  slottee_lt_notify_value(&group_done);

  slottee_return_with_tp(saved_tp, completed == 1 ?
      SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_ILLEGAL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  struct slottee_matmul_config cfg;
  struct slottee_matmul_combo_report report;
  unsigned long t0, t1;

  memset(&cfg, 0, sizeof(cfg));
  if (ocall(OCALL_GET_MATMUL_CONFIG, 0, 0, &cfg, sizeof(cfg)) != 0 ||
      cfg.magic != SLOTTEE_MATMUL_MAGIC || cfg.n <= 0 ||
      cfg.n > SLOTTEE_MATMUL_MAXN || cfg.groups < 0 ||
      cfg.groups > SLOTTEE_MATMUL_WORKERS)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  cfg_n = cfg.n;
  cfg_groups = cfg.groups;

  matmul_fill(cfg_n);
  /*
   * Release fence: publish cfg_n/cfg_groups + the freshly-filled A/B/Bt to shared
   * enclave memory BEFORE any worker LT (spawned below, running on other harts)
   * can read them.  Pairs with the acquire fence at matmul_worker entry.  Without
   * this, QEMU MTTCG weak memory let a worker read stale A/Bt → wrong C (sporadic
   * large-N multi-thread csum failure).  The Keystone baseline (groups==0) runs on
   * thread0 itself so it is unaffected either way.
   */
  __sync_synchronize();

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_MATMUL_MAGIC;
  report.n = cfg_n;
  report.groups = cfg_groups;

  if (cfg_groups == 0) {
    /* 真正的 Keystone 单线程基线：thread0 直接跑整段 kernel，rdcycle 紧贴 kernel。
     * 零 slot/LT/PREEMPT/wait-notify —— 与 stock Keystone enclave 单线程执行等价。 */
    t0 = read_cycles();
    matmul_rows(0, cfg_n, cfg_n);
    t1 = read_cycles();
    report.wall_cycles = t1 - t0;          /* 基线无 spawn/汇合，wall == compute */
    report.max_compute = t1 - t0;
    report.sum_compute = t1 - t0;
    report.worker_compute[0] = t1 - t0;
    report.checksum = matmul_checksum(cfg_n);
    report.failures = 0;
  } else {
    /* SlotTEE 路径：groups==1 量化单 worker 开销；groups==2/4 跨 hart 并行。 */
    slottee_atomic_store(&group_done, 0);
    slottee_atomic_store(&group_failed, 0);
    memset(wdur, 0, sizeof(wdur));
    memset(wr0, 0, sizeof(wr0));
    memset(wr1, 0, sizeof(wr1));

    t0 = read_cycles();
    /* R4a 批量 spawn：G 个 scheduler slot 的 cap 一次 OCALL 批量导出（原 G 次往返），
     * host 同轮 spawn 全部 worker pthread → 消除 worker 错峰开始（编排 wall 大头）。
     * arg=组内序号 g 由 RT 登记（语义同原 per-slot spawn(slot, fn, g)）。 */
    if (slottee_lt_spawn_seq(SLOTTEE_MATMUL_FIRST_WORKER_SLOT, (uintptr_t)cfg_groups,
            matmul_sched_entry) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

    /* R3: join 预算改时间制（rdcycle）。次数制(原 1<<20 次 poll)在 no-timer 慢
     * poll 节奏(WSL ms 级 sleep 粒度)下 ~17 分钟即假烧穿造成"准活锁"观感；
     * 60e9 cyc 远大于最长 worker(N=512 G1 ~1.4e9)，仍能防真活锁。 */
    {
      const unsigned long join_budget_cyc = 60000000000UL;
      unsigned long join_start = read_cycles();

      while (slottee_atomic_load(&group_done) < cfg_groups) {
        /*
         * P2: timer-independent join——worker 用 AMO 更新 group_done（见
         * matmul_sched_entry），thread0 纯 poll + 轻量让出 host（host_yield 仅
         * stop 到 host 让 resume loop 推进 spawn/续跑，不注册 wait queue、不依赖
         * notify/timer）。由此 N=512 G=2/4 可在 huge-quantum / no-preempt 模式
         * 运行（timer 依赖性对照实验），正常模式行为等价。
         */
        (void)slottee_lt_host_yield();
        if (read_cycles() - join_start > join_budget_cyc) {
          slottee_atomic_fetch_add(&group_failed, 1);
          break;
        }
      }
    }
    t1 = read_cycles();

    report.wall_cycles = t1 - t0;
    report.max_compute = 0;
    report.sum_compute = 0;
    for (long g = 0; g < cfg_groups && g < SLOTTEE_MATMUL_WORKERS; g++) {
      report.worker_compute[g] = wdur[g];
      if (wdur[g] > report.max_compute)
        report.max_compute = wdur[g];
      report.sum_compute += wdur[g];
    }
    report.checksum = matmul_checksum(cfg_n);
    report.failures = (uintptr_t)slottee_atomic_load(&group_failed);
    for (long g = 0; g < cfg_groups && g < SLOTTEE_MATMUL_WORKERS; g++) {
      report.worker_r0[g] = wr0[g];
      report.worker_r1[g] = wr1[g];
    }
  }

  /*
   * P1 现场诊断（周期自检）：A 行周期 128（7*128≡0 mod128 → A[i+128]=A[i]）→
   * 正确的 C 必满足 C[i][j]==C[i&127][j]（i>=128）。任一 band 算错时这里在
   * enclave 内当场定位错误行/列与值模式（零输入/被踩/索引错），随 report 带回
   * host 在 [retry]/[FAIL] 时打印。N>=256 才有参照（diag_valid）；O(N^2) 只读。
   */
  report.diag_valid = (uintptr_t)(cfg_n >= 256);
  report.diag_mismatch_rows = 0;
  if (report.diag_valid) {
    for (long i = 128; i < cfg_n; i++) {
      long bad = 0;
      for (long j = 0; j < cfg_n; j++) {
        if (C[i][j] != C[i & 127][j]) {
          if (!report.diag_mismatch_rows && !bad) {
            report.diag_i = (uintptr_t)i;
            report.diag_j = (uintptr_t)j;
            report.diag_got = (uintptr_t)(unsigned int)C[i][j];
            report.diag_ref = (uintptr_t)(unsigned int)C[i & 127][j];
          }
          bad = 1;
        }
      }
      report.diag_mismatch_rows += (uintptr_t)bad;
    }
  }

  if (ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;

  slottee_return_with_tp(saved_tp,
      report.failures ? SLOTTEE_LT_USER_ILLEGAL_MAGIC :
      SLOTTEE_LT_USER_OCALL_MAGIC);
}
