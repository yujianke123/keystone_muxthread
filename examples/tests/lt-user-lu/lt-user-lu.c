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

/* 死锁诊断（有界屏障 self-check）：把永久挂变成可上报的状态 */
#define LU_SPIN_LIMIT 20000L   /* 有界屏障上限: 按 2ms backoff ≈40s;防挂死非性能参数 */
static long dbg_worker_entered; /* lu_worker LT 是否启动过(进入次数) */
static long dbg_worker_ran;    /* 所有 worker 完成 update 的总次数 */
static long dbg_deadlock;      /* 0=无 1=driver屏障放弃 2=worker等epoch放弃 */
static long dbg_done_giveup;   /* driver 放弃时 ptask_done */
static long dbg_k_giveup;      /* driver 放弃时 k */
static long dbg_epoch_giveup;  /* driver 放弃时 ptask_epoch */
static long dbg_worker_stage;  /* worker 进度标记: 1=入口 2=fetch_add后 3=见epoch 4=FP更新前 5=FP更新后 6=done++后 */
static long dbg_sched_stage;   /* sched-LT 进度(纯AMO,不靠ecall): 1=preempt_run返回 2=mark后 3=return前 */

static unsigned long read_cycles(void) {
  unsigned long c; asm volatile(SLOTTEE_RDCYCLE_INSN : "=r"(c)); return c;
}
/* 诊断: 直打串口的 RT DBG_MARK(syscall 1016)——绕开 host/ssh/文件,板崩前可见 */
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
  long marked = 0;
  slottee_atomic_store(&dbg_worker_stage, 1);         /* 诊断: 进入 lu_worker */
  dbg_mark(0x101);
  slottee_atomic_fetch_add(&dbg_worker_entered, 1);   /* 诊断: worker LT 已启动 */
  __sync_synchronize();
  slottee_atomic_store(&dbg_worker_stage, 2);         /* 诊断: 原子操作可用 */
  dbg_mark(0x102);
  for (;;) {
    long wspin = 0;
    while (slottee_atomic_load(&ptask_epoch) == seen) {
      /*
       * VF2: worker 等待用纯 AMO 自旋,绝不 host_yield——preempt-worker 上下文的
       * 首次 host_yield stop/resume 在真机必死(hart 俘获+timer 停摆,SM 级根因待查;
       * 括号标记实测 0x110 后 0x120 永不返回)。QEMU 上 worker 从不走 yield 路径
       * (epoch 总已就绪),matmul INT worker 同为 compute-bound——此即同型模式。
       * 代价: 等待期独占本 hart;epoch 间隔 ms 级,俘获远短于 RCU stall 阈值(21s)。
       */
      if (++wspin > 2000000000L) { slottee_atomic_store(&dbg_deadlock, 2); break; }
    }
    if (slottee_atomic_load(&dbg_deadlock)) break;   /* 死锁诊断退出 */
    seen = slottee_atomic_load(&ptask_epoch);
    slottee_atomic_store(&dbg_worker_stage, 3);       /* 诊断: 见到 epoch */
    __sync_synchronize();                       /* acquire: 对角块(driver)就绪 */
    long k = slottee_atomic_load(&ptask_k);
    if (k < 0) break;                           /* 哨兵退出 */
    long n = cfg_n, gc = cfg_groups;
    slottee_atomic_store(&dbg_worker_stage, 4);       /* 诊断: FP 更新前 */
    if (!marked) dbg_mark(0x104);
    unsigned long s = read_cycles();
    lu_update_rows(k, LU_BLOCK, n, g, gc);
    unsigned long e = read_cycles();
    slottee_atomic_store(&dbg_worker_stage, 5);       /* 诊断: FP 更新后 */
    if (!marked) { dbg_mark(0x105); marked = 1; }
    if (g >= 0 && g < SLOTTEE_MATMUL_WORKERS) wdur[g] += e - s;
    slottee_atomic_fetch_add(&dbg_worker_ran, 1);
    __sync_synchronize();                       /* release: 本行块更新可见后再报完成 */
    slottee_atomic_fetch_add(&ptask_done, 1);
    slottee_atomic_store(&dbg_worker_stage, 6);       /* 诊断: done++ 完成 */
  }
  slottee_atomic_fetch_add(&group_done, 1);           /* driver 收敛屏障计数 */
  dbg_mark(0x10F);                                    /* 诊断: worker 退出 */
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

static void lu_sched_entry(void* opaque) {
  long g = (long)(uintptr_t)opaque;
  /*
   * VF2: worker 直接作为本 slot 的 plain LT_USER_OCALL 体运行,不再经
   * slottee_preempt_run——preempt-group 的 exit-switch(*ctx=scheduler_ctx 帧
   * 恢复→sret)在真机无声楔死(hart 俘获/timer 停摆;sched_stage=0 实证 U-mode
   * 一条指令未送达,NIF/PF 全静默=非故障而是 RT trap-exit 楔死)。plain slot 的
   * enter→U 计算→EXIT 全链路真机久经验证(lt-scheduler/policy/matmul)。
   * 语义: worker 仍是 slot 隔离的并行 LT;仅不在 enclave 内抢占调度器之下
   * (VF2 in-runtime 切换本就不可用,与 D3 结论一致,论文如实标注)。
   */
  __sync_synchronize();
  slottee_atomic_store(&dbg_sched_stage, 1);
  lu_worker((void*)(uintptr_t)g);             /* 不返回(EAPP_RETURN) */
}

/*
 * FP 保存正确性探针（cfg_groups==99 触发）。写已知哨兵到 f0-f31，纯 int 自旋 ~5000万周期
 * （>> quantum，跨很多次定时器抢占），再读回比对——中间无 C 代码，f0-f31 只可能被"损坏的
 * 抢占 FP save/restore"改变。确定性(长自旋必被抢占)，隔离 LU 噪声，直接判定 FP 跨抢占保存。
 * 报告：checksum=损坏寄存器数(0=保存正确);max_compute=首个损坏索引;sum_compute/wall_cycles=
 * 首损的 got/期望位模式;n=32。
 */
static double fp_sent[32], fp_got[32];
static void fp_sentinel_test(struct slottee_matmul_combo_report* report) {
  for (int i = 0; i < 32; i++) { fp_sent[i] = (double)(i * 131 + 7) + 0.5; fp_got[i] = -1.0; }
  __sync_synchronize();
  __asm__ volatile(
    "fld  f0,  0*8(%[s])\n  fld  f1,  1*8(%[s])\n  fld  f2,  2*8(%[s])\n  fld  f3,  3*8(%[s])\n"
    "fld  f4,  4*8(%[s])\n  fld  f5,  5*8(%[s])\n  fld  f6,  6*8(%[s])\n  fld  f7,  7*8(%[s])\n"
    "fld  f8,  8*8(%[s])\n  fld  f9,  9*8(%[s])\n  fld  f10,10*8(%[s])\n  fld  f11,11*8(%[s])\n"
    "fld  f12,12*8(%[s])\n  fld  f13,13*8(%[s])\n  fld  f14,14*8(%[s])\n  fld  f15,15*8(%[s])\n"
    "fld  f16,16*8(%[s])\n  fld  f17,17*8(%[s])\n  fld  f18,18*8(%[s])\n  fld  f19,19*8(%[s])\n"
    "fld  f20,20*8(%[s])\n  fld  f21,21*8(%[s])\n  fld  f22,22*8(%[s])\n  fld  f23,23*8(%[s])\n"
    "fld  f24,24*8(%[s])\n  fld  f25,25*8(%[s])\n  fld  f26,26*8(%[s])\n  fld  f27,27*8(%[s])\n"
    "fld  f28,28*8(%[s])\n  fld  f29,29*8(%[s])\n  fld  f30,30*8(%[s])\n  fld  f31,31*8(%[s])\n"
    "li   t2, 50000000\n"
    "1:\n  addi t2, t2, -1\n  bnez t2, 1b\n"
    "fsd  f0,  0*8(%[g])\n  fsd  f1,  1*8(%[g])\n  fsd  f2,  2*8(%[g])\n  fsd  f3,  3*8(%[g])\n"
    "fsd  f4,  4*8(%[g])\n  fsd  f5,  5*8(%[g])\n  fsd  f6,  6*8(%[g])\n  fsd  f7,  7*8(%[g])\n"
    "fsd  f8,  8*8(%[g])\n  fsd  f9,  9*8(%[g])\n  fsd  f10,10*8(%[g])\n  fsd  f11,11*8(%[g])\n"
    "fsd  f12,12*8(%[g])\n  fsd  f13,13*8(%[g])\n  fsd  f14,14*8(%[g])\n  fsd  f15,15*8(%[g])\n"
    "fsd  f16,16*8(%[g])\n  fsd  f17,17*8(%[g])\n  fsd  f18,18*8(%[g])\n  fsd  f19,19*8(%[g])\n"
    "fsd  f20,20*8(%[g])\n  fsd  f21,21*8(%[g])\n  fsd  f22,22*8(%[g])\n  fsd  f23,23*8(%[g])\n"
    "fsd  f24,24*8(%[g])\n  fsd  f25,25*8(%[g])\n  fsd  f26,26*8(%[g])\n  fsd  f27,27*8(%[g])\n"
    "fsd  f28,28*8(%[g])\n  fsd  f29,29*8(%[g])\n  fsd  f30,30*8(%[g])\n  fsd  f31,31*8(%[g])\n"
    :
    : [s] "r" (fp_sent), [g] "r" (fp_got)
    : "t2", "memory",
      "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12","f13","f14","f15",
      "f16","f17","f18","f19","f20","f21","f22","f23","f24","f25","f26","f27","f28","f29","f30","f31");
  __sync_synchronize();
  long bad_idle = 0, firstbad_idle = -1;
  for (int i = 0; i < 32; i++)
    if (fp_got[i] != fp_sent[i]) { bad_idle++; if (firstbad_idle < 0) firstbad_idle = i; }

  /*
   * 主动 FP 相：模拟 LU 的持续 FP 使用。v[i]=v[i]*2.0*0.5 净恒等且 FP 精确（2 的幂），
   * 每轮后 v[i] 应恒==(i+1)。volatile 防优化成 no-op。跨很多次抢占；若活跃 FP 在抢占下
   * 被腐蚀，v[i] 偏离。elapsed rdtime 证明确有抢占（>> quantum）。
   */
  static volatile double v[16];
  for (int i = 0; i < 16; i++) v[i] = (double)(i + 1);
  unsigned long ts = read_cycles();
  for (long k = 0; k < 20000000L; k++)
    for (int i = 0; i < 16; i++) { v[i] = v[i] * 2.0; v[i] = v[i] * 0.5; }
  unsigned long te = read_cycles();
  long bad_act = 0, firstbad_act = -1;
  for (int i = 0; i < 16; i++)
    if (v[i] != (double)(i + 1)) { bad_act++; if (firstbad_act < 0) firstbad_act = i; }

  report->checksum = (uintptr_t)bad_act;              /* 主信号: 活跃 FP 跨抢占损坏数 */
  report->max_compute = (uintptr_t)bad_idle;          /* idle 持有 FP 损坏数 */
  report->sum_compute = (uintptr_t)(te - ts);         /* 主动相 elapsed rdtime(证抢占) */
  report->wall_cycles = firstbad_act >= 0 ? *(unsigned long*)&v[firstbad_act] : 0;
  report->failures = (uintptr_t)((firstbad_act << 8) | (firstbad_idle & 0xff));
  report->n = 32; report->groups = 99;
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

  if (cfg.n == 999) {                  /* FP 保存正确性探针（魔数 N==999, G=0 单进入） */
    fp_sentinel_test(&report);
    (void)ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0);
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
  }

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
    dbg_mark(0x2A0);                            /* 诊断: driver spawn 完成 */
    t0 = read_cycles();
    for (long k = 0; k < cfg_n; k += LU_BLOCK) {
      lu_diag(k, LU_BLOCK, cfg_n);              /* 串行对角 */
      slottee_atomic_store(&ptask_done, 0);
      slottee_atomic_store(&ptask_k, k);
      __sync_synchronize();                     /* release: 对角块+k 就绪后发布 */
      slottee_atomic_fetch_add(&ptask_epoch, 1);
      if (k == 0) dbg_mark(0x2E0);              /* 诊断: 首个 epoch 已发布 */
      long dspin = 0;
      while (slottee_atomic_load(&ptask_done) < cfg_groups) {  /* barrier */
        (void)slottee_lt_host_yield();
        if (++dspin > LU_SPIN_LIMIT) {          /* 死锁诊断: driver 屏障放弃 */
          if (!slottee_atomic_load(&dbg_deadlock)) slottee_atomic_store(&dbg_deadlock, 1);
          dbg_done_giveup = slottee_atomic_load(&ptask_done);
          dbg_k_giveup = k;
          dbg_epoch_giveup = slottee_atomic_load(&ptask_epoch);
          /* 诊断: 屏障放弃时把 stage/done 直接打到串口 */
          dbg_mark(0xD100 | (unsigned long)slottee_atomic_load(&dbg_worker_stage));
          dbg_mark(0xD200 | (unsigned long)dbg_done_giveup);
          dbg_mark(0xD300 | (unsigned long)slottee_atomic_load(&dbg_worker_entered));
          break;
        }
      }
      if (slottee_atomic_load(&dbg_deadlock)) break;   /* 跳出块列循环 */
      __sync_synchronize();                     /* acquire: 本列 worker 更新可见 */
      if (k == 0) dbg_mark(0x2E1);              /* 诊断: 首个屏障通过 */
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
    /* 等 scheduler LT 收敛（有界） */
    long cspin = 0;
    while (slottee_atomic_load(&group_done) < cfg_groups) {
      (void)slottee_lt_host_yield();
      if (++cspin > LU_SPIN_LIMIT) {
        if (!slottee_atomic_load(&dbg_deadlock)) slottee_atomic_store(&dbg_deadlock, 3);
        /* 诊断: driver 中继上报 sched-LT 的纯AMO进度(区分 sret未送达 vs ecall死) */
        dbg_mark(0xE100 | (unsigned long)slottee_atomic_load(&dbg_sched_stage));
        dbg_mark(0xE200 | (unsigned long)slottee_atomic_load(&dbg_worker_stage));
        break;
      }
    }
    report.failures = (uintptr_t)slottee_atomic_load(&group_failed);
    /* 死锁诊断编入报告：failures 高位=dbg_deadlock侧; 复用空闲字段 */
    if (slottee_atomic_load(&dbg_deadlock)) {
      report.failures = (uintptr_t)(0x0D00 | slottee_atomic_load(&dbg_deadlock));  /* 0xD0N 标记死锁 side=N */
      report.max_compute = (uintptr_t)slottee_atomic_load(&dbg_worker_ran);        /* worker 完成 update 总次数 */
      report.sum_compute = (uintptr_t)dbg_done_giveup;                             /* driver 放弃时 ptask_done */
      report.wall_cycles = (uintptr_t)((dbg_k_giveup << 20) | (dbg_epoch_giveup & 0xfffff));
      report.worker_compute[0] = (uintptr_t)slottee_atomic_load(&dbg_worker_entered); /* worker LT 启动次数 */
      report.worker_compute[1] = (uintptr_t)slottee_atomic_load(&dbg_worker_stage);   /* worker 进度标记 */
    }
  }

  if (ocall(OCALL_MATMUL_REPORT, &report, sizeof(report), 0, 0) != 0)
    report.failures++;
  slottee_return_with_tp(saved_tp, report.failures ?
      SLOTTEE_LT_USER_ILLEGAL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
