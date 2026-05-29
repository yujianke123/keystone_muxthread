#ifndef __SLOTTEE_MULTIHART_H__
#define __SLOTTEE_MULTIHART_H__

#include <stdint.h>

#define SLOTTEE_MULTIHART_TICKET_WINDOWS     3
#define SLOTTEE_MULTIHART_TICKET_TOTAL       20
#define SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS 7
#define SLOTTEE_MULTIHART_TICKET_MAX_TOTAL   64
#define SLOTTEE_MULTIHART_TICKET_MAGIC       0x51513737
#define SLOTTEE_MULTIHART_TICKET_CONFIG_MAGIC 0x51513838
#define SLOTTEE_MULTIHART_JOIN_MODE_SPIN     0
#define SLOTTEE_MULTIHART_JOIN_MODE_WAIT     1

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
  uintptr_t notify_calls;
  uintptr_t notify_wakes;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t ready_windows;
  uintptr_t nonzero_windows;
  uintptr_t min_sold;
  uintptr_t max_sold;
  uintptr_t fairness_gap;
  uintptr_t dominant_window;
  uintptr_t total_sold;
  uintptr_t remaining_tickets;
  uintptr_t active_workers;
  uintptr_t failures;
  uintptr_t sold[SLOTTEE_MULTIHART_TICKET_MAX_WINDOWS];
};

#endif
