#include "app/eapp_utils.h"
#include "app/slottee_atomic.h"
#include "app/syscall.h"
#include "shared/slottee_multihart.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"

#define OCALL_REPORT_MULTIHART_TICKET 6
#define SLOTTEE_MULTIHART_WORKER_SLOTS 2

static long remaining_tickets;
static long active_workers;
static long ready_windows;
static long start_flag;
static long failures;
static long sold[SLOTTEE_MULTIHART_TICKET_WINDOWS];
static struct slottee_multihart_ticket_report final_report;

static void
ticket_worker(void* opaque);

static void
ticket_window(uintptr_t window)
{
  int guaranteed = 0;

  slottee_atomic_fetch_add(&ready_windows, 1);
  while (slottee_atomic_load(&start_flag) == 0) {
    __asm__ volatile("nop");
  }

  while (1) {
    long before = slottee_atomic_fetch_sub(&remaining_tickets, 1);

    if (before > 0) {
      slottee_atomic_fetch_add(&sold[window], 1);
      guaranteed = 1;
      break;
    }

    slottee_atomic_fetch_add(&remaining_tickets, 1);
  }

  while (1) {
    long before = slottee_atomic_fetch_sub(&remaining_tickets, 1);

    if (before > 0) {
      slottee_atomic_fetch_add(&sold[window], 1);
      continue;
    }

    slottee_atomic_fetch_add(&remaining_tickets, 1);
    break;
  }

  if (!guaranteed)
    slottee_atomic_fetch_add(&failures, 1);
}

static void
ticket_worker(void* opaque)
{
  uintptr_t window = (uintptr_t)opaque;

  if (window >= SLOTTEE_MULTIHART_TICKET_WINDOWS) {
    slottee_atomic_fetch_add(&failures, 1);
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&active_workers, 1);
  ticket_window(window);
  slottee_atomic_fetch_sub(&active_workers, 1);
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t window;

  slottee_atomic_store(&remaining_tickets, SLOTTEE_MULTIHART_TICKET_TOTAL);
  slottee_atomic_store(&active_workers, 0);
  slottee_atomic_store(&ready_windows, 0);
  slottee_atomic_store(&start_flag, 0);
  slottee_atomic_store(&failures, 0);
  for (window = 0; window < SLOTTEE_MULTIHART_TICKET_WINDOWS; window++)
    slottee_atomic_store(&sold[window], 0);

  for (window = 1; window <= SLOTTEE_MULTIHART_WORKER_SLOTS; window++) {
    uintptr_t slot_id = window + 1;

    if (slottee_lt_spawn(slot_id, ticket_worker, (void*)window) !=
        SBI_ERR_SM_ENCLAVE_SUCCESS)
      EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  slottee_atomic_fetch_add(&active_workers, 1);
  while (slottee_atomic_load(&active_workers) < SLOTTEE_MULTIHART_TICKET_WINDOWS) {
    __asm__ volatile("nop");
  }
  slottee_atomic_store(&start_flag, 1);

  ticket_window(0);
  slottee_atomic_fetch_sub(&active_workers, 1);

  while (slottee_atomic_load(&active_workers) != 0 ||
         slottee_atomic_load(&ready_windows) != SLOTTEE_MULTIHART_TICKET_WINDOWS) {
    __asm__ volatile("nop");
  }

  final_report.magic = SLOTTEE_MULTIHART_TICKET_MAGIC;
  final_report.total_sold = 0;
  for (window = 0; window < SLOTTEE_MULTIHART_TICKET_WINDOWS; window++) {
    final_report.sold[window] = (uintptr_t)slottee_atomic_load(&sold[window]);
    final_report.total_sold += final_report.sold[window];
  }
  final_report.remaining_tickets =
      (uintptr_t)slottee_atomic_load(&remaining_tickets);
  final_report.active_workers = (uintptr_t)slottee_atomic_load(&active_workers);
  final_report.failures = (uintptr_t)slottee_atomic_load(&failures);

  if (final_report.total_sold != SLOTTEE_MULTIHART_TICKET_TOTAL ||
      final_report.remaining_tickets != 0 ||
      final_report.active_workers != 0 ||
      final_report.failures != 0 ||
      final_report.sold[0] == 0 ||
      final_report.sold[1] == 0 ||
      final_report.sold[2] == 0)
    final_report.failures++;

  if (ocall(OCALL_REPORT_MULTIHART_TICKET, &final_report,
          sizeof(final_report), 0, 0) != 0)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  EAPP_RETURN(final_report.failures == 0 ?
      SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_ILLEGAL_MAGIC);
}
