/*
 * C4 ML 推理(MLP,double FP)in-enclave SlotTEE 版(--enter-slot-mlp)。
 * 3 层全连接 H→H→H→64 + bias + ReLU,batch 32,确定性 xorshift 权重;R=8 次
 * 前向(吞吐口径)。克隆 lt-user-lu plain-slot 模板:每层一个 epoch,worker 按
 * 输出神经元分片(o=g..out step G)。隐层宽 H=cfg.n(128/256)。纯 mul/add/max
 * (ReLU),无 libm。csum=最终输出 x1000 量化 FNV(host 参考同源重算)。
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
#define MLP_MAXH   256
#define MLP_OUT    64
#define MLP_BATCH  32
#define MLP_REPEAT 8
#define BENCH_SPIN_LIMIT 20000L

static double W1[MLP_MAXH][MLP_MAXH], W2[MLP_MAXH][MLP_MAXH], W3[MLP_MAXH][MLP_OUT];
static double B1[MLP_MAXH], B2[MLP_MAXH], B3[MLP_OUT];
static double X[MLP_BATCH][MLP_MAXH], H1a[MLP_BATCH][MLP_MAXH],
              H2a[MLP_BATCH][MLP_MAXH], OUT[MLP_BATCH][MLP_OUT];
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

/* ---- 与 host 参考逐字同源 ---- */
static unsigned int mlp_rng_state;
static double mlp_rng(void) {          /* [-0.03125, 0.03125) 确定性权重 */
  unsigned int x = mlp_rng_state;
  x ^= x << 13; x ^= x >> 17; x ^= x << 5;
  mlp_rng_state = x;
  return ((double)(x & 0xffff) - 32768.0) / 1048576.0;
}
static void mlp_fill(long h) {
  mlp_rng_state = 88172645u;
  for (long i = 0; i < h; i++) for (long j = 0; j < h; j++) W1[i][j] = mlp_rng();
  for (long i = 0; i < h; i++) for (long j = 0; j < h; j++) W2[i][j] = mlp_rng();
  for (long i = 0; i < h; i++) for (long j = 0; j < MLP_OUT; j++) W3[i][j] = mlp_rng();
  for (long j = 0; j < h; j++) { B1[j] = mlp_rng(); B2[j] = mlp_rng(); }
  for (long j = 0; j < MLP_OUT; j++) B3[j] = mlp_rng();
  for (long b = 0; b < MLP_BATCH; b++)
    for (long i = 0; i < h; i++) X[b][i] = mlp_rng() * 8.0;
}
/* 层前向的输出神经元分片: o = first..out-1 step stride */
static void mlp_layer_slice(const double in[][MLP_MAXH], long in_dim,
    double* out_base, long out_stride, long out_dim,
    const double* w_base, long w_stride, const double* bias,
    long first, long stride) {
  for (long o = first; o < out_dim; o += stride) {
    for (long b = 0; b < MLP_BATCH; b++) {
      double s = bias[o];
      for (long i = 0; i < in_dim; i++) s += in[b][i] * w_base[i * w_stride + o];
      out_base[b * out_stride + o] = s > 0.0 ? s : 0.0;   /* ReLU */
    }
  }
}
static void mlp_do_layer(long layer, long h, long first, long stride) {
  if (layer == 0)
    mlp_layer_slice(X, h, &H1a[0][0], MLP_MAXH, h, &W1[0][0], MLP_MAXH, B1, first, stride);
  else if (layer == 1)
    mlp_layer_slice(H1a, h, &H2a[0][0], MLP_MAXH, h, &W2[0][0], MLP_MAXH, B2, first, stride);
  else
    mlp_layer_slice(H2a, h, &OUT[0][0], MLP_OUT, MLP_OUT, &W3[0][0], MLP_OUT, B3, first, stride);
}
static uintptr_t mlp_checksum(void) {
  uintptr_t acc = 1469598103u;
  for (long b = 0; b < MLP_BATCH; b++)
    for (long j = 0; j < MLP_OUT; j++) {
      long v = (long)(OUT[b][j] * 1000.0);
      acc ^= (uintptr_t)(unsigned long)v; acc *= 1099511628211u;
    }
  return acc;
}
/* ---- 同源段结束 ---- */

static void mlp_worker(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  long seen = 0;
  slottee_atomic_store(&dbg_worker_stage, 1);
  dbg_mark(0x321);
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
    mlp_do_layer(k % 3, cfg_n, g, cfg_groups);
    unsigned long e = read_cycles();
    if (g >= 0 && g < SLOTTEE_MATMUL_WORKERS) wdur[g] += e - s;
    __sync_synchronize();
    slottee_atomic_fetch_add(&ptask_done, 1);
    slottee_atomic_store(&dbg_worker_stage, 6);
  }
  slottee_atomic_fetch_add(&group_done, 1);
  dbg_mark(0x32F);
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void mlp_sched_entry(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  __sync_synchronize();
  mlp_worker((void*)(uintptr_t)g);
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
  if (cfg_n > MLP_MAXH) cfg_n = MLP_MAXH;

  memset(&report, 0, sizeof(report));
  report.magic = SLOTTEE_MATMUL_MAGIC;
  report.n = cfg_n;
  report.groups = cfg_groups;

  mlp_fill(cfg_n);

  if (cfg_groups == 0) {
    __sync_synchronize();
    t0 = read_cycles();
    for (long r = 0; r < MLP_REPEAT; r++)
      for (long layer = 0; layer < 3; layer++)
        mlp_do_layer(layer, cfg_n, 0, 1);
    t1 = read_cycles();
    report.wall_cycles = report.max_compute = report.sum_compute = t1 - t0;
    report.checksum = mlp_checksum();
  } else {
    memset(wdur, 0, sizeof(wdur));
    slottee_atomic_store(&ptask_epoch, 0);
    slottee_atomic_store(&ptask_k, -2);
    slottee_atomic_store(&ptask_done, 0);
    __sync_synchronize();
    if (slottee_lt_spawn_seq(SLOTTEE_MATMUL_FIRST_WORKER_SLOT,
            (uintptr_t)cfg_groups, mlp_sched_entry) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
    dbg_mark(0x3C0);
    t0 = read_cycles();
    for (long r = 0; r < MLP_REPEAT && !slottee_atomic_load(&dbg_deadlock); r++) {
      for (long layer = 0; layer < 3; layer++) {
        slottee_atomic_store(&ptask_done, 0);
        slottee_atomic_store(&ptask_k, r * 3 + layer);
        __sync_synchronize();
        slottee_atomic_fetch_add(&ptask_epoch, 1);
        long dspin = 0;
        while (slottee_atomic_load(&ptask_done) < cfg_groups) {
          (void)slottee_lt_host_yield();
          if (++dspin > BENCH_SPIN_LIMIT) {
            if (!slottee_atomic_load(&dbg_deadlock)) slottee_atomic_store(&dbg_deadlock, 1);
            dbg_done_giveup = slottee_atomic_load(&ptask_done);
            dbg_k_giveup = r * 3 + layer;
            dbg_epoch_giveup = slottee_atomic_load(&ptask_epoch);
            dbg_mark(0xD600 | (unsigned long)slottee_atomic_load(&dbg_worker_stage));
            break;
          }
        }
        if (slottee_atomic_load(&dbg_deadlock)) break;
        __sync_synchronize();
      }
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
    report.checksum = mlp_checksum();
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
