/*
 * C3 SPLASH-2 FFT(radix-2 DIT)in-enclave SlotTEE 版(--enter-slot-fft)。
 * 克隆 lt-user-lu 的 plain-slot worker + AMO epoch 屏障模板(VF2 真机验证机制):
 * driver(thread0) 位反转(串行)→ 逐 stage(len=2..n)发布任务(ptask_k=len,epoch++)
 * → worker 按块分片蝶形(b=g..nblocks step G)→ ptask_done 屏障 → 下一 stage。
 * eapp 无 libm:my_cos/my_sin 为泰勒实现,与 host 参考(test-runner)逐字同源 →
 * 同板同 ISA 同代码 = csum 位精确可校验。kernel 结构与 fft-native.c 一致(仅
 * twiddle 换 my_sincos),cycles 可与 REE 原生对照。
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
#define FFT_MAXN 16384          /* re+im 2x16384x8 = 256KB */
#define BENCH_SPIN_LIMIT 20000L /* driver 有界屏障(2ms backoff≈40s),防挂死 */

static double re_a[FFT_MAXN], im_a[FFT_MAXN];
static long cfg_n, cfg_groups;
static long group_done;
static unsigned long wdur[SLOTTEE_MATMUL_WORKERS];
static long ptask_epoch, ptask_k, ptask_done;
static long dbg_deadlock, dbg_done_giveup, dbg_k_giveup, dbg_epoch_giveup;
static long dbg_worker_entered, dbg_worker_stage;

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

/* ---- 与 host 参考逐字同源的数学/kernel 段(勿单侧改动) ---- */
#define BENCH_PI 3.14159265358979323846
static double my_cos(double x) {           /* x∈(-π,π],泰勒 12 项,Horner */
  double x2 = x * x, s = 1.0;
  for (int i = 24; i >= 2; i -= 2) s = 1.0 - s * x2 / (double)(i * (i - 1));
  return s;
}
static double my_sin(double x) {
  double x2 = x * x, s = 1.0;
  for (int i = 25; i >= 3; i -= 2) s = 1.0 - s * x2 / (double)(i * (i - 1));
  return x * s;
}
static void fft_fill(double* fre, double* fim, long n) {
  for (long i = 0; i < n; i++) { fre[i] = (double)((i * 7 + 3) & 0x3f) - 32.0; fim[i] = 0.0; }
}
static void fft_bit_reverse(double* fre, double* fim, long n) {
  for (long i = 1, j = 0; i < n; i++) {
    long bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      double tr = fre[i]; fre[i] = fre[j]; fre[j] = tr;
      double ti = fim[i]; fim[i] = fim[j]; fim[j] = ti;
    }
  }
}
/* 单个 stage 的块分片蝶形: 块 b = first..nblocks-1 step stride */
static void fft_stage_slice(double* fre, double* fim, long n, long len,
    long first, long stride) {
  double ang = -2.0 * BENCH_PI / (double)len;
  long half = len >> 1, nblocks = n / len;
  for (long b = first; b < nblocks; b += stride) {
    long base = b * len;
    for (long k = 0; k < half; k++) {
      double wr = my_cos(ang * (double)k), wi = my_sin(ang * (double)k);
      double ur = fre[base + k], ui = fim[base + k];
      double vr = fre[base + k + half] * wr - fim[base + k + half] * wi;
      double vi = fre[base + k + half] * wi + fim[base + k + half] * wr;
      fre[base + k] = ur + vr; fim[base + k] = ui + vi;
      fre[base + k + half] = ur - vr; fim[base + k + half] = ui - vi;
    }
  }
}
static uintptr_t fft_checksum(const double* fre, const double* fim, long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++) {
    long v = (long)(fre[i] * 100.0), w = (long)(fim[i] * 100.0);
    acc ^= (uintptr_t)(unsigned long)v; acc *= 1099511628211u;
    acc ^= (uintptr_t)(unsigned long)w; acc *= 1099511628211u;
  }
  return acc;
}
/* ---- 同源段结束 ---- */

/* plain-slot 常驻 worker(VF2: AMO 自旋,绝不 host_yield——preempt 上下文停出真机曾必死) */
static void fft_worker(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  long seen = 0;
  slottee_atomic_store(&dbg_worker_stage, 1);
  dbg_mark(0x301);
  slottee_atomic_fetch_add(&dbg_worker_entered, 1);
  __sync_synchronize();
  for (;;) {
    long wspin = 0;
    while (slottee_atomic_load(&ptask_epoch) == seen) {
      if (++wspin > 2000000000L) { slottee_atomic_store(&dbg_deadlock, 2); break; }
    }
    if (slottee_atomic_load(&dbg_deadlock)) break;
    seen = slottee_atomic_load(&ptask_epoch);
    slottee_atomic_store(&dbg_worker_stage, 3);
    __sync_synchronize();
    long len = slottee_atomic_load(&ptask_k);
    if (len < 0) break;
    long n = cfg_n, gc = cfg_groups;
    unsigned long s = read_cycles();
    fft_stage_slice(re_a, im_a, n, len, g, gc);
    unsigned long e = read_cycles();
    if (g >= 0 && g < SLOTTEE_MATMUL_WORKERS) wdur[g] += e - s;
    __sync_synchronize();
    slottee_atomic_fetch_add(&ptask_done, 1);
    slottee_atomic_store(&dbg_worker_stage, 6);
  }
  slottee_atomic_fetch_add(&group_done, 1);
  dbg_mark(0x30F);
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void fft_sched_entry(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  __sync_synchronize();
  fft_worker((void*)(uintptr_t)g);   /* 不返回 */
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
  if (cfg_n > FFT_MAXN) cfg_n = FFT_MAXN;

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_MATMUL_MAGIC;
  report.n = cfg_n;
  report.groups = cfg_groups;

  fft_fill(re_a, im_a, cfg_n);

  if (cfg_groups == 0) {
    __sync_synchronize();
    t0 = read_cycles();
    fft_bit_reverse(re_a, im_a, cfg_n);
    for (long len = 2; len <= cfg_n; len <<= 1)
      fft_stage_slice(re_a, im_a, cfg_n, len, 0, 1);
    t1 = read_cycles();
    report.wall_cycles = report.max_compute = report.sum_compute = t1 - t0;
    report.checksum = fft_checksum(re_a, im_a, cfg_n);
  } else {
    memset(wdur, 0, sizeof(wdur));
    slottee_atomic_store(&ptask_epoch, 0);
    slottee_atomic_store(&ptask_k, -2);
    slottee_atomic_store(&ptask_done, 0);
    __sync_synchronize();
    if (slottee_lt_spawn_seq(SLOTTEE_MATMUL_FIRST_WORKER_SLOT,
            (uintptr_t)cfg_groups, fft_sched_entry) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
    dbg_mark(0x3A0);
    t0 = read_cycles();
    fft_bit_reverse(re_a, im_a, cfg_n);          /* 串行前置(计时内,与 native 同口径) */
    for (long len = 2; len <= cfg_n; len <<= 1) {
      slottee_atomic_store(&ptask_done, 0);
      slottee_atomic_store(&ptask_k, len);
      __sync_synchronize();                       /* release: stage 参数就绪后发布 */
      slottee_atomic_fetch_add(&ptask_epoch, 1);
      long dspin = 0;
      while (slottee_atomic_load(&ptask_done) < cfg_groups) {   /* barrier */
        (void)slottee_lt_host_yield();
        if (++dspin > BENCH_SPIN_LIMIT) {
          if (!slottee_atomic_load(&dbg_deadlock)) slottee_atomic_store(&dbg_deadlock, 1);
          dbg_done_giveup = slottee_atomic_load(&ptask_done);
          dbg_k_giveup = len; dbg_epoch_giveup = slottee_atomic_load(&ptask_epoch);
          dbg_mark(0xD400 | (unsigned long)slottee_atomic_load(&dbg_worker_stage));
          break;
        }
      }
      if (slottee_atomic_load(&dbg_deadlock)) break;
      __sync_synchronize();                       /* acquire: 本 stage worker 写可见 */
    }
    slottee_atomic_store(&ptask_k, -1);           /* 哨兵退出 */
    __sync_synchronize();
    slottee_atomic_fetch_add(&ptask_epoch, 1);
    t1 = read_cycles();
    report.wall_cycles = t1 - t0;
    for (long g = 0; g < cfg_groups && g < SLOTTEE_MATMUL_WORKERS; g++) {
      report.worker_compute[g] = wdur[g];
      if (wdur[g] > report.max_compute) report.max_compute = wdur[g];
      report.sum_compute += wdur[g];
    }
    report.checksum = fft_checksum(re_a, im_a, cfg_n);
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

  if (ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;
  slottee_return_with_tp(saved_tp, report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
