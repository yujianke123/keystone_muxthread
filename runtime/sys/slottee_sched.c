#include "slottee_sched.h"

#include "call/sbi.h"

#define SLOTTEE_LT_CONTEXT_VERSION 1
#define SLOTTEE_LT_STACK_BASE      ((uintptr_t)0x10000000)
#define SLOTTEE_LT_STACK_SIZE      ((uintptr_t)0x2000)
#define SLOTTEE_LT_STACK_STRIDE    ((uintptr_t)0x10000)
#define SLOTTEE_LT_TLS_BASE        ((uintptr_t)0x20000000)
#define SLOTTEE_LT_TLS_SIZE        ((uintptr_t)0x200)
#define SLOTTEE_LT_TLS_STRIDE      ((uintptr_t)0x1000)

enum slottee_lt_state {
  SLOTTEE_LT_EMPTY = 0,
  SLOTTEE_LT_READY = 1,
  SLOTTEE_LT_RUNNING = 2,
  SLOTTEE_LT_EXITED = 3,
};

struct slottee_lt_context {
  uintptr_t version;
  uintptr_t stack_base;
  uintptr_t stack_size;
  uintptr_t tls_base;
  uintptr_t tls_size;
  uintptr_t saved_pc;
  uintptr_t saved_sp;
  uintptr_t saved_tp;
};

struct slottee_lt_desc {
  uintptr_t lt_id;
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t run_count;
  enum slottee_lt_state state;
  struct slottee_lt_context context;
};

static struct slottee_lt_desc slottee_lts[SLOTTEE_MAX_SLOTS];

static int
slottee_range_overlaps(uintptr_t base_a, uintptr_t size_a, uintptr_t base_b, uintptr_t size_b)
{
  uintptr_t end_a = base_a + size_a;
  uintptr_t end_b = base_b + size_b;

  return base_a < end_b && base_b < end_a;
}

static void
slottee_lt_prepare(struct slottee_lt_desc* lt, uintptr_t slot_id, uintptr_t lease_id)
{
  lt->lt_id = slot_id;
  lt->slot_id = slot_id;
  lt->lease_id = lease_id;
  lt->state = SLOTTEE_LT_READY;
}

static void
slottee_lt_context_init(struct slottee_lt_desc* lt)
{
  uintptr_t slot_id = lt->slot_id;

  lt->context.version = SLOTTEE_LT_CONTEXT_VERSION;
  lt->context.stack_base = SLOTTEE_LT_STACK_BASE + slot_id * SLOTTEE_LT_STACK_STRIDE;
  lt->context.stack_size = SLOTTEE_LT_STACK_SIZE;
  lt->context.tls_base = SLOTTEE_LT_TLS_BASE + slot_id * SLOTTEE_LT_TLS_STRIDE;
  lt->context.tls_size = SLOTTEE_LT_TLS_SIZE;
  lt->context.saved_pc = 0;
  lt->context.saved_sp = lt->context.stack_base + lt->context.stack_size;
  lt->context.saved_tp = lt->context.tls_base;
}

static int
slottee_lt_context_isolated(const struct slottee_lt_desc* lt)
{
  uintptr_t other;

  if (lt->context.version != SLOTTEE_LT_CONTEXT_VERSION ||
      lt->context.stack_size == 0 || lt->context.tls_size == 0)
    return 0;

  if (slottee_range_overlaps(lt->context.stack_base, lt->context.stack_size,
          lt->context.tls_base, lt->context.tls_size))
    return 0;

  for (other = 1; other < SLOTTEE_MAX_SLOTS; other++) {
    uintptr_t other_stack_base;
    uintptr_t other_tls_base;

    if (other == lt->slot_id)
      continue;

    other_stack_base = SLOTTEE_LT_STACK_BASE + other * SLOTTEE_LT_STACK_STRIDE;
    other_tls_base = SLOTTEE_LT_TLS_BASE + other * SLOTTEE_LT_TLS_STRIDE;

    if (slottee_range_overlaps(lt->context.stack_base, lt->context.stack_size,
            other_stack_base, SLOTTEE_LT_STACK_SIZE) ||
        slottee_range_overlaps(lt->context.tls_base, lt->context.tls_size,
            other_tls_base, SLOTTEE_LT_TLS_SIZE))
      return 0;
  }

  return 1;
}

uintptr_t
slottee_lt_scheduler_run(uintptr_t slot_id, uintptr_t lease_id)
{
  struct slottee_lt_desc* lt;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SLOTTEE_SLOT_MAGIC;

  lt = &slottee_lts[slot_id];
  slottee_lt_prepare(lt, slot_id, lease_id);

  lt->state = SLOTTEE_LT_RUNNING;
  lt->run_count++;
  lt->state = SLOTTEE_LT_EXITED;

  return SLOTTEE_LT_SCHED_MAGIC;
}

uintptr_t
slottee_lt_context_run(uintptr_t slot_id, uintptr_t lease_id)
{
  struct slottee_lt_desc* lt;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SLOTTEE_SLOT_MAGIC;

  lt = &slottee_lts[slot_id];
  slottee_lt_prepare(lt, slot_id, lease_id);
  slottee_lt_context_init(lt);

  if (!slottee_lt_context_isolated(lt))
    return SLOTTEE_SLOT_MAGIC;

  lt->state = SLOTTEE_LT_RUNNING;
  lt->run_count++;
  lt->state = SLOTTEE_LT_EXITED;

  return SLOTTEE_LT_CONTEXT_MAGIC;
}
