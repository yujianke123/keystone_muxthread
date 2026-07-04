#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "shared/sm_call.h"

#define OCALL_PRINT_VALUE 2

static volatile unsigned long cleanup_entry_count;

void EAPP_ENTRY
eapp_entry()
{
  unsigned long value = SLOTTEE_LT_USER_OCALL_MAGIC;

  if (cleanup_entry_count == 0) {
    cleanup_entry_count = 1;
    asm volatile(".word 0x00000000" ::: "memory");
  }

  if (ocall(OCALL_PRINT_VALUE, &value, sizeof(value), 0, 0) != 0)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}
