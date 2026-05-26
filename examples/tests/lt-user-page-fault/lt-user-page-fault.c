#include <stddef.h>
#include <stdint.h>

#include "app/eapp_utils.h"
#include "shared/sm_call.h"

void EAPP_ENTRY
eapp_entry()
{
  volatile uintptr_t* unmapped = (volatile uintptr_t*)0;
  uintptr_t value = *unmapped;

  EAPP_RETURN(value ? SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_OCALL_MAGIC);
}
