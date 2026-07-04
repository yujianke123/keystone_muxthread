#include <stddef.h>
#include <stdint.h>

#include "app/eapp_utils.h"
#include "shared/sm_call.h"

void EAPP_ENTRY
eapp_entry()
{
  asm volatile(".word 0x00000000" ::: "memory");
  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}
