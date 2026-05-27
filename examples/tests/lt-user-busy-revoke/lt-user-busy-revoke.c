#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "shared/sm_call.h"

#define OCALL_PRINT_VALUE 2
#define SLOTTEE_BUSY_REVOKE_SPINS (1UL << 32)

static volatile unsigned long entry_count;

static void
busy_until_timer_interrupt(void)
{
  volatile unsigned long i;

  for (i = 0; i < SLOTTEE_BUSY_REVOKE_SPINS; i++)
    asm volatile("" ::: "memory");
}

void EAPP_ENTRY
eapp_entry()
{
  unsigned long entry = ++entry_count;
  unsigned long value = SLOTTEE_LT_USER_OCALL_MAGIC;

  if ((entry & 1) == 0) {
    busy_until_timer_interrupt();
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  if (ocall(OCALL_PRINT_VALUE, &value, sizeof(value), 0, 0) != 0)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  EAPP_RETURN(value);
}
