#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

/*
 * 跨 hart 撤销 rendezvous IPI 演示（--enter-slot-revoke-ipi）。
 *
 * host 进入 scheduler slot（落在某 hart Y），该 slot 用 PREEMPT_RUN(budget=0) 跑一个**极长的
 * in-enclave busy-loop worker**——计算全程留在 enclave 内、不触 host boundary，故 slot 1 的 lease
 * active_hart 持续 = hart Y。与此同时 host（thread0 所在 hart）对 slot 1 调 markRevoke：
 *   - 旧实现：只置 revoke_pending，等 hart Y 的下一次自然 boundary——但该 worker 在 PREEMPT_RUN 下
 *     永不停到 host，撤销要等到 worker 跑完 (≈ REVOKE_IPI_WORKER_ITERS 全程) 才生效；
 *   - 新实现：SM 立刻给 hart Y 发软件 IPI，hart Y 陷入 IRQ_M_SOFT、stop_enclave 完成撤销——撤销在
 *     IPI 投递级别生效，worker 被强制中断。
 * host 测「markRevoke → worker pthread 返回(被中断)」的墙钟，即撤销延迟；并与 worker 全程计算时间
 * （= 无 IPI 时撤销最坏要等的时长）对比。RT 内的 AMO 调度同步不变。
 */

static long enclave_alive;       /* thread0 等待标志（host 通过 destroy 结束）*/

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

/* 极长 in-enclave busy loop：无 syscall/ocall，唯一被切走途径是 timer（in-enclave 抢占，零中转）。
 * 正常情况下跑完需很久；本测试预期它被撤销 IPI 强制中断而**跑不完**。 */
static void
revoke_ipi_worker(void* opaque)
{
  volatile unsigned long acc = 0x1234567;
  (void)opaque;

  for (unsigned long i = 0; i < SLOTTEE_REVOKE_IPI_WORKER_ITERS; i++) {
    acc += (i ^ acc) + 1;
    acc ^= (acc << 7) ^ (acc >> 3);
  }
  EAPP_RETURN(acc);   /* 若真跑完（未被撤销）才会到这；本测试预期不会 */
}

static void
revoke_ipi_sched_entry(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  struct slottee_preempt_spec spec;
  (void)opaque;

  spec.fn = (uintptr_t)&revoke_ipi_worker;
  spec.arg = 0;
  spec.slot = SLOTTEE_REVOKE_IPI_WORKER_SLOT;

  /* 跑长 worker；若被撤销 IPI 强制 stop，这次 PREEMPT_RUN 在 enclave 内被中断、本 LT 随 slot 撤销
   * 退出，不会执行到下一行。 */
  (void)slottee_preempt_run(&spec, 1, 0 /*budget=0：in-enclave，不触 host boundary*/, 0);

  slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t budget = 1u << 28;

  slottee_atomic_store(&enclave_alive, 0);

  if (slottee_lt_spawn(SLOTTEE_REVOKE_IPI_SCHED_SLOT, revoke_ipi_sched_entry, 0) !=
      SBI_ERR_SM_ENCLAVE_SUCCESS)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  /* thread0 待命，直到 host 撤销/销毁。enclave_alive 永不置位，靠 budget 兜底退出。 */
  while (slottee_atomic_load(&enclave_alive) == 0) {
    (void)slottee_lt_wait_value(&enclave_alive, 1, SLOTTEE_LT_WAIT_OP_GE);
    if (--budget == 0)
      break;
  }

  slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
}
