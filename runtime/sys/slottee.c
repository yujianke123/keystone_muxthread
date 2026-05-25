#include "call/sbi.h"

void
slottee_slot_trampoline(uintptr_t slot_token)
{
  uintptr_t slot_id = SLOTTEE_SLOT_TOKEN_SLOT_ID(slot_token);
  uintptr_t lease_id = SLOTTEE_SLOT_TOKEN_LEASE_ID(slot_token);

  sbi_exit_slot(slot_id, lease_id, SLOTTEE_SLOT_EXIT_NORMAL, SLOTTEE_SLOT_MAGIC);

  while (1) {
    sbi_exit_enclave(SLOTTEE_SLOT_MAGIC);
  }
}
