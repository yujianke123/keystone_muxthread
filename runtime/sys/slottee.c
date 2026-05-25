#include "call/sbi.h"

void
slottee_slot_trampoline(uintptr_t lease_id)
{
  sbi_exit_slot(1, lease_id, SLOTTEE_SLOT_EXIT_NORMAL, SLOTTEE_SLOT_MAGIC);

  while (1) {
    sbi_exit_enclave(SLOTTEE_SLOT_MAGIC);
  }
}
