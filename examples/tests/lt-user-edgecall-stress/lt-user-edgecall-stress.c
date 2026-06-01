#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

#define OCALL_EDGECALL_STRESS_ECHO 8
#define OCALL_EDGECALL_STRESS_REPORT 9
#define SLOTTEE_EDGECALL_STRESS_MAIN_SLOT 0
#define SLOTTEE_EDGECALL_STRESS_STACK_MARKER 0x5151454447454341UL
#define SLOTTEE_EDGECALL_STRESS_TP_MARKER 0x5151454447454354UL

static long ready_workers;
static long active_workers;
static long total_ocalls;
static long worker_ocalls;
static long main_ocalls;
static long failures;
static long context_corruption_count;
static long wait_errors;
static long wait_calls;
static long wait_blocks;
static long notify_calls;
static long notify_wakes;
static struct slottee_edgecall_stress_report final_report;

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

static uintptr_t
edgecall_stress_checksum(uintptr_t slot_id, uintptr_t iter, uintptr_t marker)
{
  return marker ^ (slot_id << 16) ^ iter ^ SLOTTEE_EDGECALL_STRESS_MAGIC;
}

static void
notify_value(const long* ptr)
{
  int ret = slottee_lt_notify_value(ptr);

  slottee_atomic_fetch_add(&notify_calls, 1);
  if (ret == SLOTTEE_LT_NOTIFY_RESULT_WOKE)
    slottee_atomic_fetch_add(&notify_wakes, 1);
}

static void
wait_until_value(const long* ptr, long target, uintptr_t op)
{
  uintptr_t budget = 65536;

  while (1) {
    int ret = slottee_lt_wait_value(ptr, target, op);

    slottee_atomic_fetch_add(&wait_calls, 1);
    if (ret == SLOTTEE_LT_WAIT_RESULT_READY)
      return;
    if (ret == SLOTTEE_LT_WAIT_RESULT_BLOCKED)
      slottee_atomic_fetch_add(&wait_blocks, 1);
    else
      slottee_atomic_fetch_add(&wait_errors, 1);

    if (--budget == 0) {
      slottee_atomic_fetch_add(&failures, 1);
      return;
    }
  }
}

static void
record_context_corruption(volatile unsigned long* stack_marker,
    uintptr_t expected_tp, uintptr_t expected_stack_marker)
{
  if (*stack_marker != expected_stack_marker ||
      slottee_read_tp() != expected_tp)
    slottee_atomic_fetch_add(&context_corruption_count, 1);
}

static void
run_echo_loop(uintptr_t slot_id, uintptr_t worker)
{
  volatile unsigned long stack_marker =
      SLOTTEE_EDGECALL_STRESS_STACK_MARKER ^ slot_id;
  uintptr_t tp_marker = slottee_read_tp();

  for (uintptr_t iter = 0; iter < SLOTTEE_EDGECALL_STRESS_ITERS; iter++) {
    struct slottee_edgecall_stress_payload payload;
    struct slottee_edgecall_stress_payload echoed;
    uintptr_t marker =
        SLOTTEE_EDGECALL_STRESS_TP_MARKER ^ (slot_id << 8) ^ iter;

    memset(&payload, 0, sizeof(payload));
    memset(&echoed, 0, sizeof(echoed));
    payload.slot_id = slot_id;
    payload.iter = iter;
    payload.marker = marker;
    payload.checksum = edgecall_stress_checksum(slot_id, iter, marker);

    if (ocall(OCALL_EDGECALL_STRESS_ECHO, &payload, sizeof(payload),
            &echoed, sizeof(echoed)) != 0) {
      slottee_atomic_fetch_add(&failures, 1);
      continue;
    }

    if (echoed.slot_id != payload.slot_id ||
        echoed.iter != payload.iter ||
        echoed.marker != payload.marker ||
        echoed.checksum != payload.checksum)
      slottee_atomic_fetch_add(&failures, 1);

    record_context_corruption(&stack_marker, tp_marker,
        SLOTTEE_EDGECALL_STRESS_STACK_MARKER ^ slot_id);
    slottee_atomic_fetch_add(&total_ocalls, 1);
    if (worker)
      slottee_atomic_fetch_add(&worker_ocalls, 1);
    else
      slottee_atomic_fetch_add(&main_ocalls, 1);
  }
}

static void
edgecall_stress_worker(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t slot_id = (uintptr_t)opaque;

  if (slot_id < SLOTTEE_EDGECALL_STRESS_FIRST_WORKER_SLOT ||
      slot_id > SLOTTEE_EDGECALL_STRESS_LAST_WORKER_SLOT) {
    slottee_atomic_fetch_add(&failures, 1);
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&active_workers, 1);
  slottee_atomic_fetch_add(&ready_workers, 1);
  notify_value(&ready_workers);
  wait_until_value(&ready_workers, SLOTTEE_EDGECALL_STRESS_WORKERS + 1,
      SLOTTEE_LT_WAIT_OP_GE);
  run_echo_loop(slot_id, 1);
  slottee_atomic_fetch_sub(&active_workers, 1);
  notify_value(&active_workers);
  slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t slot_id;
  struct slottee_lt_runtime_stats rt_stats;

  slottee_atomic_store(&ready_workers, 0);
  slottee_atomic_store(&active_workers, 0);
  slottee_atomic_store(&total_ocalls, 0);
  slottee_atomic_store(&worker_ocalls, 0);
  slottee_atomic_store(&main_ocalls, 0);
  slottee_atomic_store(&failures, 0);
  slottee_atomic_store(&context_corruption_count, 0);
  slottee_atomic_store(&wait_errors, 0);
  slottee_atomic_store(&wait_calls, 0);
  slottee_atomic_store(&wait_blocks, 0);
  slottee_atomic_store(&notify_calls, 0);
  slottee_atomic_store(&notify_wakes, 0);

  for (slot_id = SLOTTEE_EDGECALL_STRESS_FIRST_WORKER_SLOT;
       slot_id <= SLOTTEE_EDGECALL_STRESS_LAST_WORKER_SLOT; slot_id++) {
    if (slottee_lt_spawn(slot_id, edgecall_stress_worker,
            (void*)slot_id) != SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&ready_workers, 1);
  notify_value(&ready_workers);
  wait_until_value(&ready_workers, SLOTTEE_EDGECALL_STRESS_WORKERS + 1,
      SLOTTEE_LT_WAIT_OP_GE);
  run_echo_loop(SLOTTEE_EDGECALL_STRESS_MAIN_SLOT, 0);
  wait_until_value(&active_workers, 0, SLOTTEE_LT_WAIT_OP_EQ);

  memset(&rt_stats, 0, sizeof(rt_stats));
  if (slottee_lt_collect_stats(&rt_stats) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    slottee_atomic_fetch_add(&failures, 1);

  memset(&final_report, 0, sizeof(final_report));
  final_report.magic = SLOTTEE_EDGECALL_STRESS_MAGIC;
  final_report.worker_slots = SLOTTEE_EDGECALL_STRESS_WORKERS;
  final_report.per_lt_iters = SLOTTEE_EDGECALL_STRESS_ITERS;
  final_report.expected_worker_ocalls =
      SLOTTEE_EDGECALL_STRESS_WORKERS * SLOTTEE_EDGECALL_STRESS_ITERS;
  final_report.total_ocalls = (uintptr_t)slottee_atomic_load(&total_ocalls);
  final_report.worker_ocalls = (uintptr_t)slottee_atomic_load(&worker_ocalls);
  final_report.main_ocalls = (uintptr_t)slottee_atomic_load(&main_ocalls);
  final_report.failures = (uintptr_t)slottee_atomic_load(&failures);
  final_report.context_corruption_count =
      (uintptr_t)slottee_atomic_load(&context_corruption_count);
  final_report.ready_workers = (uintptr_t)slottee_atomic_load(&ready_workers);
  final_report.active_workers = (uintptr_t)slottee_atomic_load(&active_workers);
  final_report.wait_calls = (uintptr_t)slottee_atomic_load(&wait_calls);
  final_report.wait_blocks = (uintptr_t)slottee_atomic_load(&wait_blocks);
  final_report.notify_calls = (uintptr_t)slottee_atomic_load(&notify_calls);
  final_report.notify_wakes = (uintptr_t)slottee_atomic_load(&notify_wakes);
  final_report.tls_entry_ok = rt_stats.tls_entry_ok;
  final_report.tls_exit_ok = rt_stats.tls_exit_ok;
  final_report.tls_exit_mismatch = rt_stats.tls_exit_mismatch;
  final_report.stack_entry_ok = rt_stats.stack_entry_ok;
  final_report.stack_exit_ok = rt_stats.stack_exit_ok;
  final_report.ocall_traps = rt_stats.ocall_traps;
  final_report.ocall_resumes = rt_stats.ocall_resumes;

  if (final_report.worker_ocalls < final_report.expected_worker_ocalls ||
      final_report.total_ocalls < final_report.expected_worker_ocalls ||
      final_report.main_ocalls != SLOTTEE_EDGECALL_STRESS_ITERS ||
      final_report.ready_workers != SLOTTEE_EDGECALL_STRESS_WORKERS + 1 ||
      final_report.active_workers != 0 ||
      final_report.tls_exit_mismatch != 0 ||
      final_report.context_corruption_count != 0 ||
      slottee_atomic_load(&wait_errors) != 0 ||
      final_report.failures != 0)
    final_report.failures++;

  if (ocall(OCALL_EDGECALL_STRESS_REPORT, &final_report,
          sizeof(final_report), 0, 0) != 0)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  slottee_return_with_tp(saved_tp, final_report.failures == 0 ?
      SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_ILLEGAL_MAGIC);
}
