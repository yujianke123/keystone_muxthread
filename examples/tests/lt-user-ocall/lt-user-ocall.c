#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "shared/sm_call.h"

#define OCALL_PRINT_VALUE 2

void EAPP_ENTRY
eapp_entry()
{
  volatile unsigned long stack_marker = SLOTTEE_LT_USER_OCALL_MAGIC;
  unsigned long value = SLOTTEE_LT_USER_OCALL_MAGIC;

  if (ocall(OCALL_PRINT_VALUE, &value, sizeof(value), 0, 0) != 0)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  if (stack_marker != SLOTTEE_LT_USER_OCALL_MAGIC)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}
