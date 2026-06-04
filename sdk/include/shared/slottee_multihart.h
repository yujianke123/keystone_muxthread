#ifndef __SLOTTEE_MULTIHART_H__
#define __SLOTTEE_MULTIHART_H__

#include <stdint.h>

#define SLOTTEE_MULTIHART_TICKET_WINDOWS     3
#define SLOTTEE_MULTIHART_TICKET_TOTAL       20
#define SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS 7
#define SLOTTEE_MULTIHART_TICKET_MAX_TOTAL   64
#define SLOTTEE_MULTIHART_TICKET_MAGIC       0x51513737
#define SLOTTEE_MULTIHART_TICKET_CONFIG_MAGIC 0x51513838
#define SLOTTEE_EDGECALL_STRESS_MAGIC        0x51513939
#define SLOTTEE_TIMER_PREEMPT_MAGIC          0x51513a3a
#define SLOTTEE_EDGECALL_STRESS_FIRST_WORKER_SLOT 2
#define SLOTTEE_EDGECALL_STRESS_WORKERS      3
#define SLOTTEE_EDGECALL_STRESS_ITERS        100
#define SLOTTEE_EDGECALL_STRESS_LAST_WORKER_SLOT \
  (SLOTTEE_EDGECALL_STRESS_FIRST_WORKER_SLOT + \
   SLOTTEE_EDGECALL_STRESS_WORKERS - 1)
#define SLOTTEE_MULTIHART_FAIRNESS_POLICY_RR 1
#define SLOTTEE_MULTIHART_JOIN_MODE_SPIN     0
#define SLOTTEE_MULTIHART_JOIN_MODE_WAIT     1
#define SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT 2
#define SLOTTEE_TIMER_PREEMPT_WORKERS        3
#define SLOTTEE_TIMER_PREEMPT_LAST_WORKER_SLOT \
  (SLOTTEE_TIMER_PREEMPT_FIRST_WORKER_SLOT + \
   SLOTTEE_TIMER_PREEMPT_WORKERS - 1)
#define SLOTTEE_TIMER_PREEMPT_ITERS          8000000UL
#define SLOTTEE_PREEMPT_SCHED_MAGIC          0x51513b3b
#define SLOTTEE_PREEMPT_SCHED_SCHEDULER_SLOT 2
#define SLOTTEE_PREEMPT_SCHED_WORKERS        3
#define SLOTTEE_PREEMPT_SCHED_FIRST_WORKER_SLOT 3
#define SLOTTEE_PREEMPT_SCHED_LAST_WORKER_SLOT \
  (SLOTTEE_PREEMPT_SCHED_FIRST_WORKER_SLOT + SLOTTEE_PREEMPT_SCHED_WORKERS - 1)
#define SLOTTEE_PREEMPT_SCHED_ITERS          3000000UL

/* 第42阶段：跨 hart 并行抢占式调度（两级：in-runtime 抢占 + host 协作安全阀）。
 * 2 个 scheduler 组各在自己 hart 上调度自己的 worker 子集；槽位 disjoint：
 * group g: scheduler slot = 1 + g*3, worker slots = {2+g*3 .. } —— 即
 * group0 sched=1 workers=2,3；group1 sched=4 workers=5,6。 */
#define SLOTTEE_PREEMPT_MULTIHART_MAGIC      0x51513c3c
#define SLOTTEE_PREEMPT_MULTIHART_GROUPS     2
#define SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP 2
#define SLOTTEE_PREEMPT_MULTIHART_SCHED_SLOT(g)     (1 + (g) * 3)
#define SLOTTEE_PREEMPT_MULTIHART_WORKER_SLOT(g, w) (2 + (g) * 3 + (w))
#define SLOTTEE_PREEMPT_MULTIHART_ITERS      1500000UL
#define SLOTTEE_PREEMPT_MULTIHART_BUDGET     4

/* 第43阶段：跨 hart 工作窃取/迁移。复用 multihart 槽布局（2 组×2 worker），但
 * group0 worker 短、group1 worker 长 → group0 hart 先空闲，窃取 group1 的排队 worker
 * 迁到本 hart 跑。PREEMPT_RUN flags bit0 启用窃取。 */
#define SLOTTEE_PREEMPT_STEAL_MAGIC          0x51513d3d
#define SLOTTEE_PREEMPT_STEAL_FINAL_MAGIC    0x51513e3e
#define SLOTTEE_PREEMPT_STEAL_FLAG           1u
#define SLOTTEE_PREEMPT_STEAL_SHORT_ITERS    200000UL
#define SLOTTEE_PREEMPT_STEAL_MED_ITERS      1500000UL
#define SLOTTEE_PREEMPT_STEAL_LONG_ITERS     3000000UL
#define SLOTTEE_PREEMPT_STEAL_BUDGET         8
#define SLOTTEE_PREEMPT_STEAL_TOTAL_WORKERS \
  (SLOTTEE_PREEMPT_MULTIHART_GROUPS * SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP)

/*
 * Consolidated steal verdict, OCALLed once by the eapp MAIN thread AFTER every
 * group has finished (group_done == GROUPS, so every worker — including any that
 * migrated across harts — has run to completion and written its checksum).  This
 * decouples checksum verification from the per-group reports, which a LENDING
 * group emits BEFORE a worker it lent out finishes on the borrowing hart (its
 * checksum slot would still be stale there).  The host verifies all worker
 * checksums from here regardless of where/when each worker actually ran.
 */
struct slottee_preempt_steal_final {
  uintptr_t magic;
  uintptr_t total_workers;
  uintptr_t failures;
  uintptr_t worker_checksums[SLOTTEE_PREEMPT_STEAL_TOTAL_WORKERS];
};

/*
 * 第47阶段：3 组 best-victim 验证（--enter-slot-preempt-bestvictim）。
 * 单受害组（2 组）无法证明"最忙受害组选择"——本测试用 3 个 scheduler 组（各绑一 hart）
 * 构造两个 queue 深度不同的受害组，且**只有 group0 开启窃取**（victim 组关闭，避免多个
 * 欠载组都去抢最忙受害组、谁先抢到不确定的竞争）：
 *   group0(thief, STEAL on) : sched=1, 2 worker {short(2), medium(3)} → short 退出后 medium
 *                             仍在跑而 runnable 队列空 → 持续主动 rebalance；唯一窃取者
 *   group1(victimA,STEAL off): sched=4, 2 LONG worker(slot 5,6)        → 稳定 runnable count=1
 *   group2(victimB,STEAL off): sched=7, 3 LONG worker(slot 8,9,10)     → 稳定 runnable count=2（最忙）
 * 只有 group0 会偷，它每次评估都同时看到 victimA(count=1) 与 victimB(count=2)，必选最忙的
 * victimB。每组 report 里 group0 的 steal_victim_slot/steal_victim_count 即 best-victim 证据
 * （记录该组偷过的最忙受害组）。需要 slot 直到 10，故依赖 SLOTTEE_MAX_SLOTS >= 11。
 */
#define SLOTTEE_PREEMPT_BV_MAGIC          0x51513f3f
#define SLOTTEE_PREEMPT_BV_GROUPS         3
#define SLOTTEE_PREEMPT_BV_MAX_WORKERS    3
#define SLOTTEE_PREEMPT_BV_TOTAL_WORKERS  7            /* 2 + 2 + 3 */
#define SLOTTEE_PREEMPT_BV_BUDGET         8
#define SLOTTEE_PREEMPT_BV_SHORT_ITERS    200000UL
#define SLOTTEE_PREEMPT_BV_MED_ITERS      1500000UL
#define SLOTTEE_PREEMPT_BV_LONG_ITERS     3000000UL
#define SLOTTEE_PREEMPT_BV_FLAG           1u           /* enable steal (= SLOTTEE_PREEMPT_FLAG_STEAL) */
/* 不对称布局：每组 {scheduler slot, worker 数}；worker slot = sched+1+w。 */
#define SLOTTEE_PREEMPT_BV_SCHED_G0       1
#define SLOTTEE_PREEMPT_BV_SCHED_G1       4
#define SLOTTEE_PREEMPT_BV_SCHED_G2       7
#define SLOTTEE_PREEMPT_BV_WORKERS_G0     2
#define SLOTTEE_PREEMPT_BV_WORKERS_G1     2
#define SLOTTEE_PREEMPT_BV_WORKERS_G2     3
/* thief(group0) 应当偷中的最忙受害组 = victimB(group2)，其 runnable count 应为 2。 */
#define SLOTTEE_PREEMPT_BV_EXPECT_VICTIM_SLOT  SLOTTEE_PREEMPT_BV_SCHED_G2
#define SLOTTEE_PREEMPT_BV_EXPECT_VICTIM_COUNT 2

/* 每组 OCALL 一份；host 据 group0(thief) 的 steal_victim_* 断言 best-victim。 */
struct slottee_preempt_bestvictim_report {
  uintptr_t magic;
  uintptr_t group_id;
  uintptr_t scheduler_slot;
  uintptr_t worker_count;
  uintptr_t completed_workers;
  uintptr_t steals;
  uintptr_t steal_skips;
  uintptr_t rebalances;
  uintptr_t steal_victim_slot;
  uintptr_t steal_victim_count;
  uintptr_t runnable_queue_depth;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_unfinished;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t fairness_violations;
  uintptr_t failures;
};

/*
 * 第48阶段：复杂多线程程序——并发账本（--enter-slot-ledger）。
 * 8 个 worker LT（2 组 × 4，跨 2 hart，在抢占式调度器下时间片轮转）并发地对一个共享的
 * 16 账户账本做大量原子转账（每个 worker 做 TRANSFERS 次 src→dst 的 -1/+1）。每笔转账
 * 对总额是守恒的；且 src/dst 序列对每个 worker 完全确定，故最终每个账户余额与转账总数都是
 * 交错无关、可由 host 逐笔回放精确重算的。host 校验：每账户余额精确匹配 + 总额守恒 +
 * 原子转账计数 == 总 worker × TRANSFERS + 抢占确实发生(switches>0)。这同时压测：LT 生成、
 * 抢占式多 hart 调度、跨 hart 共享内存原子一致性、wait/notify 汇合。
 */
#define SLOTTEE_LEDGER_MAGIC              0x51514040
#define SLOTTEE_LEDGER_GROUPS            2
#define SLOTTEE_LEDGER_WORKERS_PER_GROUP 4
#define SLOTTEE_LEDGER_TOTAL_WORKERS \
  (SLOTTEE_LEDGER_GROUPS * SLOTTEE_LEDGER_WORKERS_PER_GROUP)   /* 8 */
#define SLOTTEE_LEDGER_ACCOUNTS          16
#define SLOTTEE_LEDGER_INIT              4096L
#define SLOTTEE_LEDGER_TRANSFERS         50000L   /* 每 worker 的转账笔数 */
#define SLOTTEE_LEDGER_BUDGET            8        /* host 协作安全阀 */
/* 槽位布局（GROUPS=2, WPG=4，需到 slot 10）：sched=1+g*5, worker=sched+1+w。 */
#define SLOTTEE_LEDGER_SCHED_SLOT(g) \
  (1 + (g) * (SLOTTEE_LEDGER_WORKERS_PER_GROUP + 1))
#define SLOTTEE_LEDGER_WORKER_SLOT(g, w) \
  (SLOTTEE_LEDGER_SCHED_SLOT(g) + 1 + (w))

/* 主线程在所有组完成后 OCALL 一份；host 据此精确校验账本最终状态。 */
struct slottee_ledger_report {
  uintptr_t magic;
  uintptr_t accounts;
  uintptr_t workers;
  uintptr_t transfers_per_worker;
  long txn_count;            /* 观测到的原子转账计数 */
  long total_balance;        /* 观测到的账户余额之和（应恒 = accounts*INIT）*/
  long completed_workers;    /* 各组汇报的已完成 worker 数之和 */
  long total_switches;       /* 抢占切换总数（>0 证明发生了抢占交错）*/
  long total_host_yields;    /* host 协作安全阀触发次数 */
  long group_failed;         /* 0 = 各组调度自检（队列一致性等）全过 */
  long balances[SLOTTEE_LEDGER_ACCOUNTS];
  uintptr_t failures;
};

/*
 * ParTEE 式单线程(Keystone) vs 多线程(SlotTEE) 矩阵乘法对比基准（--enter-slot-matmul）。
 * 对每个矩阵规模 N ∈ {16,32,64,128,256,512}，测三种配置的执行周期：
 *   - single：主线程（thread0，普通 enclave 线程，不经 SlotTEE 调度器）直接算整个 C=A×B
 *             —— 即 Keystone 单线程能力的基线；
 *   - P2/P4：SlotTEE 用 2/4 个 worker LT（host pthread 各进一个 slot，落在不同 hart）并行算
 *             C 的不相交行块 —— SlotTEE 多线程能力。
 * 每个 worker 用 rdcycle 自计其 compute 周期；主线程用 rdcycle 量 release→all-done 的 wall。
 * speedup = single / multi；sync% = (wall - max_worker_compute)/wall。C 由 (i,j) 确定 → 三种
 * 配置结果逐位一致（checksum 相等即并行未破坏正确性，host 另行重算校验）。对应 ParTEE Fig.4。
 */
#define SLOTTEE_MATMUL_MAGIC          0x51514141
#define SLOTTEE_MATMUL_NSIZES         6
#define SLOTTEE_MATMUL_MAXN           512
#define SLOTTEE_MATMUL_WORKERS        4        /* 最大线程数 G；scheduler slot 1..G、worker slot 1+G..2G */
#define SLOTTEE_MATMUL_FIRST_WORKER_SLOT 1

/* host → eapp：每次 enclave run 测一个 (N, groups) 组合。 */
struct slottee_matmul_config {
  uintptr_t magic;
  long n;        /* 矩阵规模 N */
  long groups;   /* 线程数 G（1=单线程基线，2/4=SlotTEE 多线程） */
};

/* eapp → host：单组合报告。host 把 18 个组合聚合成 speedup/sync% 表 + 绘图。 */
struct slottee_matmul_combo_report {
  uintptr_t magic;
  long n;
  long groups;
  unsigned long wall_cycles;                          /* 主线程 spawn→all-done（含一次性开销） */
  unsigned long max_compute;                          /* max worker compute（并行 compute 时间） */
  unsigned long sum_compute;                          /* sum worker compute（总计算量） */
  unsigned long worker_compute[SLOTTEE_MATMUL_WORKERS];
  uintptr_t checksum;                                 /* C 校验和（所有 G 应相等，host 重算校验） */
  uintptr_t failures;
};

/* 跨 hart 撤销 rendezvous IPI 演示（--enter-slot-revoke-ipi）。 */
#define SLOTTEE_REVOKE_IPI_SCHED_SLOT    1
#define SLOTTEE_REVOKE_IPI_WORKER_SLOT   2
#define SLOTTEE_REVOKE_IPI_WORKER_ITERS  200000000UL   /* 长 in-enclave 计算；with-IPI 撤销会中断它，
                                                         * without-IPI(对照) 需等它整段跑完才能撤销。
                                                         * 取 2e8 使 miss 尝试也快速结束、外层可重试到命中 */

struct slottee_multihart_ticket_config {
  uintptr_t magic;
  uintptr_t windows;
  uintptr_t total_tickets;
  uintptr_t join_mode;
  uintptr_t wait_budget;
};

struct slottee_multihart_ticket_report {
  uintptr_t magic;
  uintptr_t configured_windows;
  uintptr_t max_windows;
  uintptr_t total_tickets;
  uintptr_t join_mode;
  uintptr_t wait_calls;
  uintptr_t wait_blocks;
  uintptr_t wait_wakeups;
  uintptr_t wait_notify_misses;
  uintptr_t runnable_queue_depth;
  uintptr_t wait_queue_depth;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_wait_residue;
  uintptr_t scheduler_unfinished;
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t user_context_entries;
  uintptr_t user_context_exits;
  uintptr_t syscall_traps;
  uintptr_t ocall_traps;
  uintptr_t ocall_resumes;
  uintptr_t exit_traps;
  uintptr_t timer_wait_stops;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t tls_resume_ok;
  uintptr_t ready_windows;
  uintptr_t nonzero_windows;
  uintptr_t min_sold;
  uintptr_t max_sold;
  uintptr_t fairness_gap;
  uintptr_t fairness_policy;
  uintptr_t fairness_budget;
  uintptr_t fairness_policy_ok;
  uintptr_t dominant_window;
  uintptr_t total_sold;
  uintptr_t remaining_tickets;
  uintptr_t active_workers;
  uintptr_t failures;
  uintptr_t hart_id[SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS];
  uintptr_t sold[SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS];
};

struct slottee_edgecall_stress_payload {
  uintptr_t slot_id;
  uintptr_t iter;
  uintptr_t marker;
  uintptr_t checksum;
};

struct slottee_edgecall_stress_report {
  uintptr_t magic;
  uintptr_t worker_slots;
  uintptr_t per_lt_iters;
  uintptr_t expected_worker_ocalls;
  uintptr_t total_ocalls;
  uintptr_t worker_ocalls;
  uintptr_t main_ocalls;
  uintptr_t failures;
  uintptr_t context_corruption_count;
  uintptr_t ready_workers;
  uintptr_t active_workers;
  uintptr_t wait_calls;
  uintptr_t wait_blocks;
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t ocall_traps;
  uintptr_t ocall_resumes;
};

struct slottee_timer_preempt_report {
  uintptr_t magic;
  uintptr_t worker_slots;
  uintptr_t iterations_per_worker;
  uintptr_t completed_workers;
  uintptr_t active_workers;
  uintptr_t ready_workers;
  uintptr_t failures;
  uintptr_t wait_calls;
  uintptr_t wait_blocks;
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
  uintptr_t preempt_count;
  uintptr_t preempt_yields;
  uintptr_t preempt_dispatches;
  uintptr_t runnable_queue_depth;
  uintptr_t wait_queue_depth;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_wait_residue;
  uintptr_t scheduler_unfinished;
  uintptr_t fairness_min;
  uintptr_t fairness_max;
  uintptr_t fairness_gap;
  uintptr_t fairness_checks;
  uintptr_t fairness_violations;
  uintptr_t timer_wait_stops;
  uintptr_t user_context_entries;
  uintptr_t user_context_exits;
  uintptr_t syscall_traps;
  uintptr_t exit_traps;
  uintptr_t stack_entry_ok;
  uintptr_t stack_exit_ok;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t worker_checksums[SLOTTEE_TIMER_PREEMPT_WORKERS];
};

/*
 * Report for the OS-level preemptive timer scheduler (--enter-slot-preempt-sched).
 * The eapp scheduler thread assembles it from RT scheduler stats plus the shared
 * worker checksums and OCALLs it to the host for verdict.
 */
struct slottee_preempt_sched_report {
  uintptr_t magic;
  uintptr_t worker_count;
  uintptr_t iterations_per_worker;
  uintptr_t completed_workers;
  uintptr_t preempt_switches;
  uintptr_t preempt_ticks;
  uintptr_t host_yields;
  uintptr_t exit_switches;
  uintptr_t runnable_queue_depth;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_wait_residue;
  uintptr_t scheduler_unfinished;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t fairness_min;
  uintptr_t fairness_max;
  uintptr_t fairness_gap;
  uintptr_t fairness_violations;
  uintptr_t min_preempts;
  uintptr_t failures;
  uintptr_t per_worker_dispatch[SLOTTEE_PREEMPT_SCHED_WORKERS];
  uintptr_t per_worker_preempts[SLOTTEE_PREEMPT_SCHED_WORKERS];
  uintptr_t worker_checksums[SLOTTEE_PREEMPT_SCHED_WORKERS];
};

/* 第42阶段 per-group 报告：每个 scheduler 组 OCALL 一份（带 group_id）。
 * 跨 hart 证据由 host 侧比较两组 scheduler pthread 的 bound_hart 给出。 */
struct slottee_preempt_multihart_report {
  uintptr_t magic;
  uintptr_t group_id;
  uintptr_t scheduler_slot;
  uintptr_t worker_count;
  uintptr_t completed_workers;
  uintptr_t preempt_switches;
  uintptr_t preempt_ticks;
  uintptr_t host_yields;
  uintptr_t exit_switches;
  uintptr_t runnable_queue_depth;
  uintptr_t scheduler_queue_leaks;
  uintptr_t scheduler_wait_residue;
  uintptr_t scheduler_unfinished;
  uintptr_t scheduler_duplicate_rejects;
  uintptr_t min_preempts;
  uintptr_t fairness_gap;
  uintptr_t fairness_violations;
  uintptr_t steals;
  uintptr_t steal_skips;
  uintptr_t rebalances;
  uintptr_t failures;
  uintptr_t per_worker_slot[SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP];
  uintptr_t per_worker_dispatch[SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP];
  uintptr_t per_worker_preempts[SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP];
  uintptr_t worker_checksums[SLOTTEE_PREEMPT_MULTIHART_WORKERS_PER_GROUP];
};

#endif
