#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"
#include <string.h>

#define OCALL_REPORT_MULTIHART_TICKET 6
#define OCALL_GET_MULTIHART_TICKET_CONFIG 7

static long remaining_tickets;
static long active_workers;
static long ready_windows;
static long failures;
static long wait_calls;
static long wait_blocks;
static long notify_calls;
static long notify_wakes;
static uintptr_t configured_windows;
static uintptr_t configured_total_tickets;
static uintptr_t configured_join_mode;
static uintptr_t configured_wait_budget;
static long sold[SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS];
static struct slottee_multihart_ticket_report final_report;

static void
ticket_worker(void* opaque);

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
notify_value(const long* ptr)
{
  int ret = slottee_lt_notify_value(ptr);

  slottee_atomic_fetch_add(&notify_calls, 1);
  if (ret == SLOTTEE_LT_NOTIFY_RESULT_WOKE)
    slottee_atomic_fetch_add(&notify_wakes, 1);
}

static int
load_ticket_config(void)
{
  struct slottee_multihart_ticket_config config;

  config.magic = 0;
  config.windows = SLOTTEE_MULTIHART_TICKET_WINDOWS;
  config.total_tickets = SLOTTEE_MULTIHART_TICKET_TOTAL;
  config.join_mode = SLOTTEE_MULTIHART_JOIN_MODE_WAIT;
  config.wait_budget = 4096;

  if (ocall(OCALL_GET_MULTIHART_TICKET_CONFIG, 0, 0,
          &config, sizeof(config)) != 0)
    return -1;

  if (config.magic != SLOTTEE_MULTIHART_TICKET_CONFIG_MAGIC)
    return -1;
  if (config.windows < 2 ||
      config.windows > SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS)
    return -1;
  if (config.total_tickets < config.windows ||
      config.total_tickets > SLOTTEE_MULTIHART_TICKET_MAX_TOTAL)
    return -1;
  if (config.join_mode != SLOTTEE_MULTIHART_JOIN_MODE_SPIN &&
      config.join_mode != SLOTTEE_MULTIHART_JOIN_MODE_WAIT)
    return -1;

  configured_windows = config.windows;
  configured_total_tickets = config.total_tickets;
  configured_join_mode = config.join_mode;
  configured_wait_budget = config.wait_budget ? config.wait_budget : 1;
  return 0;
}

static void
wait_until_value(const long* ptr, long target, uintptr_t op)
{
  uintptr_t budget = configured_wait_budget;

  while (1) {
    if (configured_join_mode == SLOTTEE_MULTIHART_JOIN_MODE_WAIT) {
      int ret = slottee_lt_wait_value(ptr, target, op);
      slottee_atomic_fetch_add(&wait_calls, 1);
      if (ret == SLOTTEE_LT_WAIT_RESULT_READY)
        return;
      if (ret == SLOTTEE_LT_WAIT_RESULT_BLOCKED)
        slottee_atomic_fetch_add(&wait_blocks, 1);
      else
        slottee_atomic_fetch_add(&failures, 1);
    } else {
      long value = slottee_atomic_load(ptr);

      if ((op == SLOTTEE_LT_WAIT_OP_EQ && value == target) ||
          (op == SLOTTEE_LT_WAIT_OP_GE && value >= target))
        return;
      __asm__ volatile("nop");
    }

    if (--budget == 0) {
      slottee_atomic_fetch_add(&failures, 1);
      return;
    }
  }
}

static void
ticket_window(uintptr_t window)
{
  slottee_atomic_fetch_add(&sold[window], 1);

  while (1) {
    long before = slottee_atomic_fetch_sub(&remaining_tickets, 1);

    if (before > 0) {
      slottee_atomic_fetch_add(&sold[window], 1);
      continue;
    }

    slottee_atomic_fetch_add(&remaining_tickets, 1);
    break;
  }
}

static void
ticket_worker(void* opaque)
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t window = (uintptr_t)opaque;

  if (window >= configured_windows) {
    slottee_atomic_fetch_add(&failures, 1);
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&active_workers, 1);
  slottee_atomic_fetch_add(&ready_windows, 1);
  notify_value(&ready_windows);
  ticket_window(window);
  slottee_atomic_fetch_sub(&active_workers, 1);
  notify_value(&active_workers);
  slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t saved_tp = slottee_read_tp();
  uintptr_t window;

  configured_windows = SLOTTEE_MULTIHART_TICKET_WINDOWS;
  configured_total_tickets = SLOTTEE_MULTIHART_TICKET_TOTAL;
  configured_join_mode = SLOTTEE_MULTIHART_JOIN_MODE_WAIT;
  configured_wait_budget = 4096;

  if (load_ticket_config() != 0)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  slottee_atomic_store(&remaining_tickets,
      (long)(configured_total_tickets - configured_windows));
  slottee_atomic_store(&active_workers, 0);
  slottee_atomic_store(&ready_windows, 0);
  slottee_atomic_store(&failures, 0);
  slottee_atomic_store(&wait_calls, 0);
  slottee_atomic_store(&wait_blocks, 0);
  slottee_atomic_store(&notify_calls, 0);
  slottee_atomic_store(&notify_wakes, 0);
  for (window = 0; window < SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS; window++)
    slottee_atomic_store(&sold[window], 0);

  for (window = 1; window < configured_windows; window++) {
    uintptr_t slot_id = window + 1;

    if (slottee_lt_spawn(slot_id, ticket_worker, (void*)window) !=
        SBI_ERR_SM_ENCLAVE_SUCCESS)
      slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&active_workers, 1);
  slottee_atomic_fetch_add(&ready_windows, 1);
  notify_value(&ready_windows);
  wait_until_value(&ready_windows, (long)configured_windows,
      SLOTTEE_LT_WAIT_OP_GE);

  if (slottee_atomic_load(&failures) == 0)
    ticket_window(0);
  slottee_atomic_fetch_sub(&active_workers, 1);
  notify_value(&active_workers);

  wait_until_value(&active_workers, 0, SLOTTEE_LT_WAIT_OP_EQ);

  struct slottee_lt_runtime_stats rt_stats;
  memset(&rt_stats, 0, sizeof(rt_stats));
  if (slottee_lt_collect_stats(&rt_stats) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    slottee_atomic_fetch_add(&failures, 1);

  final_report.magic = SLOTTEE_MULTIHART_TICKET_MAGIC;
  final_report.configured_windows = configured_windows;
  final_report.max_windows = SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS;
  final_report.total_tickets = configured_total_tickets;
  final_report.join_mode = configured_join_mode;
  final_report.wait_calls = (uintptr_t)slottee_atomic_load(&wait_calls);
  final_report.wait_blocks = (uintptr_t)slottee_atomic_load(&wait_blocks);
  final_report.wait_wakeups = rt_stats.wait_wakeups;
  final_report.wait_notify_misses = rt_stats.notify_misses;
  final_report.notify_calls = (uintptr_t)slottee_atomic_load(&notify_calls);
  final_report.notify_wakes = (uintptr_t)slottee_atomic_load(&notify_wakes);
  final_report.tls_entry_ok = rt_stats.tls_entry_ok;
  final_report.tls_exit_ok = rt_stats.tls_exit_ok;
  final_report.tls_exit_mismatch = rt_stats.tls_exit_mismatch;
  final_report.ready_windows = (uintptr_t)slottee_atomic_load(&ready_windows);
  final_report.total_sold = 0;
  final_report.nonzero_windows = 0;
  final_report.min_sold = (uintptr_t)-1;
  final_report.max_sold = 0;
  final_report.dominant_window = 0;
  for (window = 0; window < SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS; window++) {
    final_report.sold[window] = (uintptr_t)slottee_atomic_load(&sold[window]);
    if (window < configured_windows) {
      final_report.total_sold += final_report.sold[window];
      if (final_report.sold[window] != 0)
        final_report.nonzero_windows++;
      if (final_report.sold[window] < final_report.min_sold)
        final_report.min_sold = final_report.sold[window];
      if (final_report.sold[window] > final_report.max_sold) {
        final_report.max_sold = final_report.sold[window];
        final_report.dominant_window = window + 1;
      }
    }
  }
  if (final_report.min_sold == (uintptr_t)-1)
    final_report.min_sold = 0;
  final_report.fairness_gap =
      final_report.max_sold >= final_report.min_sold ?
      final_report.max_sold - final_report.min_sold : 0;
  final_report.remaining_tickets =
      (uintptr_t)slottee_atomic_load(&remaining_tickets);
  final_report.active_workers = (uintptr_t)slottee_atomic_load(&active_workers);
  final_report.failures = (uintptr_t)slottee_atomic_load(&failures);

  if (final_report.total_sold != configured_total_tickets ||
      final_report.remaining_tickets != 0 ||
      final_report.active_workers != 0 ||
      final_report.failures != 0 ||
      final_report.ready_windows != configured_windows ||
      final_report.nonzero_windows != configured_windows ||
      final_report.tls_entry_ok < configured_windows - 1 ||
      final_report.tls_exit_ok < configured_windows - 1 ||
      final_report.tls_exit_mismatch != 0 ||
      (configured_join_mode == SLOTTEE_MULTIHART_JOIN_MODE_WAIT &&
       (final_report.wait_calls == 0 || final_report.wait_blocks == 0 ||
        final_report.wait_wakeups == 0 || final_report.notify_calls == 0 ||
        final_report.notify_wakes == 0)))
    final_report.failures++;
  for (window = 0; window < configured_windows; window++) {
    if (final_report.sold[window] == 0)
      final_report.failures++;
  }

  if (ocall(OCALL_REPORT_MULTIHART_TICKET, &final_report,
          sizeof(final_report), 0, 0) != 0)
    slottee_return_with_tp(saved_tp, SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  slottee_return_with_tp(saved_tp, final_report.failures == 0 ?
      SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_ILLEGAL_MAGIC);
}
