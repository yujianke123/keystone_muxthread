/*
 * C3 SPLASH-2 LU（无主元分块）in-enclave SlotTEE 版（--enter-slot-lu）。
 * 复用 matmul 的 persistent-worker + AMO barrier 脚手架，但 LU 有块列依赖：driver(thread0)
 * 逐块列 k：对角块串行分解 → 发布该列尾部更新任务(epoch++) → 等 ptask_done==G(barrier) → k+1。
 * worker 常驻自旋，每任务对本行分区做 L 列前代 + 尾部 Schur 补更新，自计 compute 周期。
 * kernel/fill/checksum 与 REE 原生 lu-native.c 逐位一致 → csum 可比、host 可重算校验。
 * 与 REE 原生对照得 LU 的 TEE 开销%。
 */
#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

#ifdef SLOTTEE_BENCH_RDTIME
#define SLOTTEE_RDCYCLE_INSN "rdtime %0"
#else
#define SLOTTEE_RDCYCLE_INSN "rdcycle %0"
#endif

#define OCALL_GET_MATMUL_CONFIG 16
#define OCALL_MATMUL_REPORT     17
#define LU_MAXN 512          /* double[512][512]=2MB；行距与 REE 原生 lu-native 一致(公平对比) */
#define LU_BLOCK 16

static double A[LU_MAXN][LU_MAXN];
static long cfg_n, cfg_groups;
static long group_done, group_failed;
static unsigned long wdur[SLOTTEE_MATMUL_WORKERS];

/* 任务下发（AMO）：driver 每块列发布，worker 消费 */
static long ptask_epoch;    /* +1 发布一个块列任务 */
static long ptask_k;        /* 当前块列起点 k */
static long ptask_done;     /* 本任务完成 worker 数 */

static unsigned long read_cycles(void) {
  unsigned long c; asm volatile(SLOTTEE_RDCYCLE_INSN : "=r"(c)); return c;
}
static uintptr_t slottee_read_tp(void) {
  uintptr_t tp; __asm__ volatile("mv %0, tp" : "=r"(tp)); return tp;
}
static void slottee_return_with_tp(uintptr_t tp, unsigned long value) __attribute__((noreturn));
static void slottee_return_with_tp(uintptr_t tp, unsigned long value) {
  __asm__ volatile("mv tp, %0" :: "r"(tp) : "memory"); EAPP_RETURN(value);
}

static void lu_fill(long n) {
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++)
      A[i][j] = (double)(((i * 7 + j * 3 + 1) & 0x1f) + 1);
  for (long i = 0; i < n; i++)
    A[i][i] += (double)(n * 32);
}

/* 对角块 k 就地 LU（driver 串行）。 */
static void lu_diag(long k, long b, long n) {
  long kk = (k + b > n) ? n : k + b;
  for (long i = k; i < kk; i++) {
    for (long j = k; j < i; j++) {
      double s = A[i][j];
      for (long p = k; p < j; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s / A[j][j];
    }
    for (long j = i; j < kk; j++) {
      double s = A[i][j];
      for (long p = k; p < i; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s;
    }
  }
}

/* 块列 k 的尾部更新：L 列前代(行 kk..n, 列 k..kk) + Schur 补(行 kk..n, 列 kk..n)，
 * 行按 worker g/gc 分区。 */
static void lu_update_rows(long k, long b, long n, long g, long gc) {
  long kk = (k + b > n) ? n : k + b;
  for (long i = kk + g; i < n; i += gc) {
    for (long j = k; j < kk; j++) {           /* L 列前代 */
      double s = A[i][j];
      for (long p = k; p < j; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s / A[j][j];
    }
    for (long j = kk; j < n; j++) {            /* Schur 补 */
      double s = A[i][j];
      for (long p = k; p < kk; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s;
    }
  }
}

static uintptr_t lu_checksum(long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++) {
      long v = (long)(A[i][j] * 1000.0);
      acc ^= (uintptr_t)(unsigned long)v;
      acc *= 1099511628211u;
    }
  return acc;
}

/* 常驻 worker：每块列任务对本行分区更新，累加 compute。 */
static void lu_worker(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  long seen = 0;
  __sync_synchronize();
  for (;;) {
    while (slottee_atomic_load(&ptask_epoch) == seen)
      (void)slottee_lt_host_yield();   /* 并发FP: 自旋让出,避免hart独占+减少FP-save churn */
    seen = slottee_atomic_load(&ptask_epoch);
    __sync_synchronize();                       /* acquire: 对角块(driver)就绪 */
    long k = slottee_atomic_load(&ptask_k);
    if (k < 0) break;                           /* 哨兵退出 */
    long n = cfg_n, gc = cfg_groups;
    unsigned long s = read_cycles();
    lu_update_rows(k, LU_BLOCK, n, g, gc);
    unsigned long e = read_cycles();
    if (g >= 0 && g < SLOTTEE_MATMUL_WORKERS) wdur[g] += e - s;
    __sync_synchronize();                       /* release: 本行块更新可见后再报完成 */
    slottee_atomic_fetch_add(&ptask_done, 1);
  }
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void lu_sched_entry(void* opaque) {
  uintptr_t saved_tp = slottee_read_tp();
  long g = (long)(uintptr_t)opaque;
  struct slottee_preempt_spec spec;
  uintptr_t completed;
  __sync_synchronize();
  spec.fn = (uintptr_t)&lu_worker;
  spec.arg = (uintptr_t)g;
  spec.slot = SLOTTEE_MATMUL_FIRST_WORKER_SLOT + cfg_groups + g;
  completed = (uintptr_t)slottee_preempt_run(&spec, 1, 0, 0);
  if (completed != 1) slottee_atomic_fetch_add(&group_failed, 1);
  slottee_atomic_fetch_add(&group_done, 1);
  slottee_return_with_tp(saved_tp, completed == 1 ?
      SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_ILLEGAL_MAGIC);
}

void EAPP_ENTRY eapp_entry() {
  uintptr_t saved_tp = slottee_read_tp();
  struct slottee_matmul_config cfg;
  struct slottee_matmul_combo_report report;
  unsigned long t0, t1;

  if (ocall(OCALL_GET_MATMUL_CONFIG, 0, 0, &cfg, sizeof(cfg)) != 0 ||
      cfg.magic != SLOTTEE_MATMUL_MAGIC)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  cfg_n = cfg.n; cfg_groups = cfg.groups;
  if (cfg_n > LU_MAXN) cfg_n = LU_MAXN;

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_MATMUL_MAGIC;
  report.n = cfg_n; report.groups = cfg_groups;
  slottee_atomic_store(&group_done, 0);
  slottee_atomic_store(&group_failed, 0);

#ifdef LU_DIAG_NO_FP
  /* 诊断：config OCALL 后、任何 FP 前立即报告 0xDEAD 返回，隔离挂点是否为 FP。 */
  report.checksum = 0xDEAD;
  report.max_compute = 0;
  (void)ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0);
  slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
#endif

  lu_fill(cfg_n);

  if (cfg_groups == 0) {
    /* 基线：driver 单线程全 LU（无 spawn/汇合，wall==compute） */
    __sync_synchronize();
    t0 = read_cycles();
    for (long k = 0; k < cfg_n; k += LU_BLOCK) {
      lu_diag(k, LU_BLOCK, cfg_n);
      lu_update_rows(k, LU_BLOCK, cfg_n, 0, 1);
    }
    t1 = read_cycles();
    report.wall_cycles = report.max_compute = report.sum_compute = t1 - t0;
    report.checksum = lu_checksum(cfg_n);
  } else {
    /* 多线程：spawn G 常驻 worker，driver 逐块列串行对角+并行尾部(barrier) */
    memset(wdur, 0, sizeof(wdur));
    slottee_atomic_store(&ptask_epoch, 0);
    slottee_atomic_store(&ptask_k, -2);
    slottee_atomic_store(&ptask_done, 0);
    __sync_synchronize();
    if (slottee_lt_spawn_seq(SLOTTEE_MATMUL_FIRST_WORKER_SLOT,
            (uintptr_t)cfg_groups, lu_sched_entry) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
    t0 = read_cycles();
    for (long k = 0; k < cfg_n; k += LU_BLOCK) {
      lu_diag(k, LU_BLOCK, cfg_n);              /* 串行对角 */
      slottee_atomic_store(&ptask_done, 0);
      slottee_atomic_store(&ptask_k, k);
      __sync_synchronize();                     /* release: 对角块+k 就绪后发布 */
      slottee_atomic_fetch_add(&ptask_epoch, 1);
      while (slottee_atomic_load(&ptask_done) < cfg_groups)  /* barrier */
        (void)slottee_lt_host_yield();
      __sync_synchronize();                     /* acquire: 本列 worker 更新可见 */
    }
    /* 哨兵退出 worker */
    slottee_atomic_store(&ptask_k, -1);
    __sync_synchronize();
    slottee_atomic_fetch_add(&ptask_epoch, 1);
    t1 = read_cycles();
    report.wall_cycles = t1 - t0;
    for (long g = 0; g < cfg_groups && g < SLOTTEE_MATMUL_WORKERS; g++) {
      report.worker_compute[g] = wdur[g];
      if (wdur[g] > report.max_compute) report.max_compute = wdur[g];
      report.sum_compute += wdur[g];
    }
    report.checksum = lu_checksum(cfg_n);
    /* 等 scheduler LT 收敛 */
    while (slottee_atomic_load(&group_done) < cfg_groups)
      (void)slottee_lt_host_yield();
    report.failures = (uintptr_t)slottee_atomic_load(&group_failed);
  }

  if (ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;
  slottee_return_with_tp(saved_tp, report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
