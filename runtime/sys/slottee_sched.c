#include "slottee_sched.h"

#include "call/sbi.h"

enum slottee_lt_state {
  SLOTTEE_LT_EMPTY = 0,
  SLOTTEE_LT_READY = 1,
  SLOTTEE_LT_RUNNING = 2,
  SLOTTEE_LT_EXITED = 3,
};

struct slottee_lt_desc {
  uintptr_t lt_id;
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t run_count;
  enum slottee_lt_state state;
};

static struct slottee_lt_desc slottee_lts[SLOTTEE_MAX_SLOTS];

uintptr_t
slottee_lt_scheduler_run(uintptr_t slot_id, uintptr_t lease_id)
{
  struct slottee_lt_desc* lt;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SLOTTEE_SLOT_MAGIC;

  lt = &slottee_lts[slot_id];
  lt->lt_id = slot_id;
  lt->slot_id = slot_id;
  lt->lease_id = lease_id;
  lt->state = SLOTTEE_LT_READY;

  lt->state = SLOTTEE_LT_RUNNING;
  lt->run_count++;
  lt->state = SLOTTEE_LT_EXITED;

  return SLOTTEE_LT_SCHED_MAGIC;
}
