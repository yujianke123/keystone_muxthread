#ifndef __SLOTTEE_MULTIHART_H__
#define __SLOTTEE_MULTIHART_H__

#include <stdint.h>

#define SLOTTEE_MULTIHART_TICKET_WINDOWS 3
#define SLOTTEE_MULTIHART_TICKET_TOTAL   20
#define SLOTTEE_MULTIHART_TICKET_MAGIC   0x51513737

struct slottee_multihart_ticket_report {
  uintptr_t magic;
  uintptr_t total_sold;
  uintptr_t remaining_tickets;
  uintptr_t active_workers;
  uintptr_t failures;
  uintptr_t sold[SLOTTEE_MULTIHART_TICKET_WINDOWS];
};

#endif
