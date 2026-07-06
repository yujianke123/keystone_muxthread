/*
 * C3 SPLASH-2 Radix(LSD 256 基数,uint32,4 pass)in-enclave SlotTEE 版
 * (--enter-slot-radix)。克隆 lt-user-lu plain-slot 模板。每 pass 两个 epoch:
 * ①worker 本分区局部直方图 → ②driver 串行全局前缀(bucket-major,worker-minor)
 * → worker 稳定 scatter。INT-only(无 FP 面),kernel 与 radix-native.c 逐位一致。
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
#define RDX_MAXN 262144         /* 2 x 1MB uint32 */
#define RADIX 256
#define BENCH_SPIN_LIMIT 20000L

static unsigned int A_a[RDX_MAXN], B_a[RDX_MAXN];
static long cfg_n, cfg_groups;
static long group_done;
static unsigned long wdur[SLOTTEE_MATMUL_WORKERS];
static long ptask_epoch, ptask_k, ptask_done;
static long dbg_deadlock, dbg_done_giveup, dbg_k_giveup, dbg_epoch_giveup;
static long dbg_worker_entered, dbg_worker_stage;
static long hist_a[SLOTTEE_MATMUL_WORKERS][RADIX];
static long goff_a[SLOTTEE_MATMUL_WORKERS][RADIX];

static unsigned long read_cycles(void) {
  unsigned long c; asm volatile(SLOTTEE_RDCYCLE_INSN : "=r"(c)); return c;
}
static void dbg_mark(unsigned long v) {
  register uintptr_t a0 asm("a0") = v;
  register uintptr_t a7 asm("a7") = 1016;
  asm volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
}
static uintptr_t slottee_read_tp(void) {
  uintptr_t tp; __asm__ volatile("mv %0, tp" : "=r"(tp)); return tp;
}
static void slottee_return_with_tp(uintptr_t tp, unsigned long value) __attribute__((noreturn));
static void slottee_return_with_tp(uintptr_t tp, unsigned long value) {
  __asm__ volatile("mv tp, %0" :: "r"(tp) : "memory"); EAPP_RETURN(value);
}

/* ---- 与 host 参考/native 逐字同源 ---- */
static void rdx_fill(unsigned int* arr, long n) {
  unsigned int x = 2463534242u;
  for (long i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; arr[i] = x; }
}
static void rdx_hist_slice(const unsigned int* src, long n, int shift,
    long g, long gc, long* hist) {
  long lo = n * g / gc, hi = n * (g + 1) / gc;
  memset(hist, 0, sizeof(long) * RADIX);
  for (long i = lo; i < hi; i++) hist[(src[i] >> shift) & (RADIX - 1)]++;
}
static void rdx_scatter_slice(const unsigned int* src, unsigned int* dst, long n,
    int shift, long g, long gc, const long* goff) {
  long lo = n * g / gc, hi = n * (g + 1) / gc;
  long off[RADIX];
  for (int b = 0; b < RADIX; b++) off[b] = goff[b];
  for (long i = lo; i < hi; i++) {
    int b = (src[i] >> shift) & (RADIX - 1);
    dst[off[b]++] = src[i];
  }
}
static uintptr_t rdx_checksum(const unsigned int* arr, long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++) { acc ^= arr[i]; acc *= 1099511628211u; }
  return acc;
}
/* ---- 同源段结束 ---- */

/* ptask_k 编码: pass*2+phase(0=hist,1=scatter);src/dst 按 pass 奇偶 */
static void rdx_task(long k, long g, long gc) {
  long pass = k >> 1, phase = k & 1;
  int shift = (int)(pass * 8);
  unsigned int* src = (pass % 2 == 0) ? A_a : B_a;
  unsigned int* dst = (pass % 2 == 0) ? B_a : A_a;
  if (phase == 0) rdx_hist_slice(src, cfg_n, shift, g, gc, hist_a[g]);
  else            rdx_scatter_slice(src, dst, cfg_n, shift, g, gc, goff_a[g]);
}

static void rdx_worker(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  long seen = 0;
  slottee_atomic_store(&dbg_worker_stage, 1);
  dbg_mark(0x311);
  slottee_atomic_fetch_add(&dbg_worker_entered, 1);
  __sync_synchronize();
  for (;;) {
    long wspin = 0;
    while (slottee_atomic_load(&ptask_epoch) == seen) {
      if (++wspin > 2000000000L) { slottee_atomic_store(&dbg_deadlock, 2); break; }
    }
    if (slottee_atomic_load(&dbg_deadlock)) break;
    seen = slottee_atomic_load(&ptask_epoch);
    __sync_synchronize();
    long k = slottee_atomic_load(&ptask_k);
    if (k < 0) break;
    unsigned long s = read_cycles();
    rdx_task(k, g, cfg_groups);
    unsigned long e = read_cycles();
    if (g >= 0 && g < SLOTTEE_MATMUL_WORKERS) wdur[g] += e - s;
    __sync_synchronize();
    slottee_atomic_fetch_add(&ptask_done, 1);
    slottee_atomic_store(&dbg_worker_stage, 6);
  }
  slottee_atomic_fetch_add(&group_done, 1);
  dbg_mark(0x31F);
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void rdx_sched_entry(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  __sync_synchronize();
  rdx_worker((void*)(uintptr_t)g);
}

/* driver: 发布 epoch(k) 并等 done==G(有界) */
static int rdx_publish_and_wait(long k) {
  slottee_atomic_store(&ptask_done, 0);
  slottee_atomic_store(&ptask_k, k);
  __sync_synchronize();
  slottee_atomic_fetch_add(&ptask_epoch, 1);
  long dspin = 0;
  while (slottee_atomic_load(&ptask_done) < cfg_groups) {
    (void)slottee_lt_host_yield();
    if (++dspin > BENCH_SPIN_LIMIT) {
      if (!slottee_atomic_load(&dbg_deadlock)) slottee_atomic_store(&dbg_deadlock, 1);
      dbg_done_giveup = slottee_atomic_load(&ptask_done);
      dbg_k_giveup = k; dbg_epoch_giveup = slottee_atomic_load(&ptask_epoch);
      dbg_mark(0xD500 | (unsigned long)slottee_atomic_load(&dbg_worker_stage));
      return 1;
    }
  }
  __sync_synchronize();
  return 0;
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
  if (cfg_n > RDX_MAXN) cfg_n = RDX_MAXN;

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_MATMUL_MAGIC;
  report.n = cfg_n;
  report.groups = cfg_groups;

  rdx_fill(A_a, cfg_n);

  if (cfg_groups == 0) {
    __sync_synchronize();
    t0 = read_cycles();
    for (long pass = 0; pass < 4; pass++) {
      unsigned int* src = (pass % 2 == 0) ? A_a : B_a;
      unsigned int* dst = (pass % 2 == 0) ? B_a : A_a;
      int shift = (int)(pass * 8);
      rdx_hist_slice(src, cfg_n, shift, 0, 1, hist_a[0]);
      long acc = 0;
      for (int b = 0; b < RADIX; b++) { goff_a[0][b] = acc; acc += hist_a[0][b]; }
      rdx_scatter_slice(src, dst, cfg_n, shift, 0, 1, goff_a[0]);
    }
    t1 = read_cycles();
    report.wall_cycles = report.max_compute = report.sum_compute = t1 - t0;
    report.checksum = rdx_checksum(A_a, cfg_n);   /* 4 pass 后结果在 A */
  } else {
    memset(wdur, 0, sizeof(wdur));
    slottee_atomic_store(&ptask_epoch, 0);
    slottee_atomic_store(&ptask_k, -2);
    slottee_atomic_store(&ptask_done, 0);
    __sync_synchronize();
    if (slottee_lt_spawn_seq(SLOTTEE_MATMUL_FIRST_WORKER_SLOT,
            (uintptr_t)cfg_groups, rdx_sched_entry) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
    dbg_mark(0x3B0);
    t0 = read_cycles();
    for (long pass = 0; pass < 4 && !slottee_atomic_load(&dbg_deadlock); pass++) {
      if (rdx_publish_and_wait(pass * 2)) break;        /* ① 局部直方图 */
      long acc = 0;                                      /* ② 串行全局前缀 */
      for (int b = 0; b < RADIX; b++)
        for (long g = 0; g < cfg_groups; g++) { goff_a[g][b] = acc; acc += hist_a[g][b]; }
      if (rdx_publish_and_wait(pass * 2 + 1)) break;    /* ③ 稳定 scatter */
    }
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
    report.checksum = rdx_checksum(A_a, cfg_n);
    long cspin = 0;
    while (slottee_atomic_load(&group_done) < cfg_groups) {
      (void)slottee_lt_host_yield();
      if (++cspin > BENCH_SPIN_LIMIT) { if (!slottee_atomic_load(&dbg_deadlock)) slottee_atomic_store(&dbg_deadlock, 3); break; }
    }
    if (slottee_atomic_load(&dbg_deadlock)) {
      report.failures = (uintptr_t)(0x0D00 | slottee_atomic_load(&dbg_deadlock));
      report.max_compute = 0;
      report.sum_compute = (uintptr_t)dbg_done_giveup;
      report.wall_cycles = (uintptr_t)((dbg_k_giveup << 20) | (dbg_epoch_giveup & 0xfffff));
      report.worker_compute[0] = (uintptr_t)slottee_atomic_load(&dbg_worker_entered);
      report.worker_compute[1] = (uintptr_t)slottee_atomic_load(&dbg_worker_stage);
    }
  }

  /* 排序性自检(失败计入 failures 低位) */
  if (!report.failures) {
    for (long i = 1; i < cfg_n; i++)
      if (A_a[i-1] > A_a[i]) { report.failures = 0x50; break; }
  }

  if (ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;
  slottee_return_with_tp(saved_tp, report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
