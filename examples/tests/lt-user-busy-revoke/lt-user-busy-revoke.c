#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"

#define OCALL_PRINT_VALUE 2
#define SLOTTEE_BUSY_REVOKE_SPINS (1UL << 40)
#define SLOTTEE_BUSY_REVOKE_CAP_SLOTS 3

static volatile unsigned long entry_count;
static long seed_wait_value;

static void
busy_until_timer_interrupt(void)
{
  volatile unsigned long i;

  for (i = 0; i < SLOTTEE_BUSY_REVOKE_SPINS; i++)
    asm volatile("" ::: "memory");
}

static void
busy_revoke_worker(void* opaque)
{
  (void)opaque;

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

void EAPP_ENTRY
eapp_entry()
{
  uintptr_t slot_id;

  while (1) {
    for (slot_id = 1; slot_id <= SLOTTEE_BUSY_REVOKE_CAP_SLOTS; slot_id++) {
      if (slottee_lt_spawn(slot_id, busy_revoke_worker, (void*)slot_id) !=
          SBI_ERR_SM_ENCLAVE_SUCCESS)
        EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);
    }

    slottee_lt_wait_value(
        &seed_wait_value, 1, SLOTTEE_LT_WAIT_OP_EQ);
  }

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}
