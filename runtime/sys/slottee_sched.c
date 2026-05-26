#include "slottee_sched.h"

#include "call/sbi.h"

#define SLOTTEE_LT_CONTEXT_VERSION 1
#define SLOTTEE_LT_STACK_WORDS     1024
#define SLOTTEE_LT_TLS_WORDS       64
#define SLOTTEE_LT_STACK_SIZE      ((uintptr_t)(SLOTTEE_LT_STACK_WORDS * sizeof(uintptr_t)))
#define SLOTTEE_LT_TLS_SIZE        ((uintptr_t)(SLOTTEE_LT_TLS_WORDS * sizeof(uintptr_t)))
#define SLOTTEE_LT_TRACE_LIMIT     5
#define SLOTTEE_LT_YIELD_REASON_TEST 1
#define SLOTTEE_LT_STACK_SCRATCH_BASE ((uintptr_t)0x51510000)
#define SLOTTEE_LT_TLS_SCRATCH_BASE   ((uintptr_t)0x51520000)

enum slottee_lt_state {
  SLOTTEE_LT_EMPTY = 0,
  SLOTTEE_LT_READY = 1,
  SLOTTEE_LT_RUNNING = 2,
  SLOTTEE_LT_YIELDED = 3,
  SLOTTEE_LT_EXITED = 4,
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
  uintptr_t stack_scratch;
  uintptr_t tls_scratch;
};

struct slottee_lt_desc {
  uintptr_t lt_id;
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t run_count;
  uintptr_t yield_count;
  uintptr_t resume_count;
  uintptr_t last_reason;
  uintptr_t trace_len;
  enum slottee_lt_state state_trace[SLOTTEE_LT_TRACE_LIMIT];
  enum slottee_lt_state state;
  struct slottee_lt_context context;
};

struct slottee_ready_queue {
  uintptr_t entries[SLOTTEE_MAX_SLOTS];
  uintptr_t head;
  uintptr_t tail;
  uintptr_t count;
};

static struct slottee_lt_desc slottee_lts[SLOTTEE_MAX_SLOTS];
static uintptr_t slottee_lt_stack_backing[SLOTTEE_MAX_SLOTS][SLOTTEE_LT_STACK_WORDS];
static uintptr_t slottee_lt_tls_backing[SLOTTEE_MAX_SLOTS][SLOTTEE_LT_TLS_WORDS];
static struct slottee_ready_queue slottee_ready_queue;

static int
slottee_range_overlaps(uintptr_t base_a, uintptr_t size_a, uintptr_t base_b, uintptr_t size_b)
{
  uintptr_t end_a = base_a + size_a;
  uintptr_t end_b = base_b + size_b;

  return base_a < end_b && base_b < end_a;
}

static void
slottee_queue_reset(void)
{
  slottee_ready_queue.head = 0;
  slottee_ready_queue.tail = 0;
  slottee_ready_queue.count = 0;
}

static int
slottee_queue_enqueue(uintptr_t slot_id)
{
  if (slottee_ready_queue.count >= SLOTTEE_MAX_SLOTS)
    return 0;

  slottee_ready_queue.entries[slottee_ready_queue.tail] = slot_id;
  slottee_ready_queue.tail = (slottee_ready_queue.tail + 1) % SLOTTEE_MAX_SLOTS;
  slottee_ready_queue.count++;
  return 1;
}

static int
slottee_queue_dequeue(uintptr_t* slot_id)
{
  if (slottee_ready_queue.count == 0)
    return 0;

  *slot_id = slottee_ready_queue.entries[slottee_ready_queue.head];
  slottee_ready_queue.head = (slottee_ready_queue.head + 1) % SLOTTEE_MAX_SLOTS;
  slottee_ready_queue.count--;
  return 1;
}

static void
slottee_lt_set_state(struct slottee_lt_desc* lt, enum slottee_lt_state state)
{
  lt->state = state;
  if (lt->trace_len < SLOTTEE_LT_TRACE_LIMIT) {
    lt->state_trace[lt->trace_len] = state;
    lt->trace_len++;
  }
}

static void
slottee_lt_prepare(struct slottee_lt_desc* lt, uintptr_t slot_id, uintptr_t lease_id)
{
  lt->lt_id = slot_id;
  lt->slot_id = slot_id;
  lt->lease_id = lease_id;
  lt->run_count = 0;
  lt->yield_count = 0;
  lt->resume_count = 0;
  lt->last_reason = 0;
  lt->trace_len = 0;
  slottee_lt_set_state(lt, SLOTTEE_LT_READY);
}

static void
slottee_lt_context_init(struct slottee_lt_desc* lt)
{
  uintptr_t slot_id = lt->slot_id;

  lt->context.version = SLOTTEE_LT_CONTEXT_VERSION;
  lt->context.stack_base = (uintptr_t)&slottee_lt_stack_backing[slot_id][0];
  lt->context.stack_size = SLOTTEE_LT_STACK_SIZE;
  lt->context.tls_base = (uintptr_t)&slottee_lt_tls_backing[slot_id][0];
  lt->context.tls_size = SLOTTEE_LT_TLS_SIZE;
  lt->context.saved_pc = 0;
  lt->context.saved_sp = lt->context.stack_base + lt->context.stack_size;
  lt->context.saved_tp = lt->context.tls_base;
  lt->context.stack_scratch = 0;
  lt->context.tls_scratch = 0;
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

    other_stack_base = (uintptr_t)&slottee_lt_stack_backing[other][0];
    other_tls_base = (uintptr_t)&slottee_lt_tls_backing[other][0];

    if (slottee_range_overlaps(lt->context.stack_base, lt->context.stack_size,
            other_stack_base, SLOTTEE_LT_STACK_SIZE) ||
        slottee_range_overlaps(lt->context.stack_base, lt->context.stack_size,
            other_tls_base, SLOTTEE_LT_TLS_SIZE) ||
        slottee_range_overlaps(lt->context.tls_base, lt->context.tls_size,
            other_stack_base, SLOTTEE_LT_STACK_SIZE) ||
        slottee_range_overlaps(lt->context.tls_base, lt->context.tls_size,
            other_tls_base, SLOTTEE_LT_TLS_SIZE))
      return 0;
  }

  return 1;
}

static void
slottee_lt_write_scratch(struct slottee_lt_desc* lt)
{
  uintptr_t* stack = &slottee_lt_stack_backing[lt->slot_id][0];
  uintptr_t* tls = &slottee_lt_tls_backing[lt->slot_id][0];

  lt->context.stack_scratch = SLOTTEE_LT_STACK_SCRATCH_BASE | lt->slot_id;
  lt->context.tls_scratch = SLOTTEE_LT_TLS_SCRATCH_BASE | lt->slot_id;
  stack[0] = lt->context.stack_scratch;
  stack[1] = lt->lease_id;
  tls[0] = lt->context.tls_scratch;
  tls[1] = lt->lt_id;
}

static int
slottee_lt_scratch_ok(const struct slottee_lt_desc* lt)
{
  const uintptr_t* stack = &slottee_lt_stack_backing[lt->slot_id][0];
  const uintptr_t* tls = &slottee_lt_tls_backing[lt->slot_id][0];

  return stack[0] == lt->context.stack_scratch &&
      stack[1] == lt->lease_id &&
      tls[0] == lt->context.tls_scratch &&
      tls[1] == lt->lt_id;
}

static int
slottee_lt_yield_trace_ok(const struct slottee_lt_desc* lt)
{
  return lt->trace_len == SLOTTEE_LT_TRACE_LIMIT &&
      lt->state_trace[0] == SLOTTEE_LT_READY &&
      lt->state_trace[1] == SLOTTEE_LT_RUNNING &&
      lt->state_trace[2] == SLOTTEE_LT_YIELDED &&
      lt->state_trace[3] == SLOTTEE_LT_RUNNING &&
      lt->state_trace[4] == SLOTTEE_LT_EXITED;
}

uintptr_t
slottee_lt_scheduler_run(uintptr_t slot_id, uintptr_t lease_id)
{
  struct slottee_lt_desc* lt;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SLOTTEE_SLOT_MAGIC;

  lt = &slottee_lts[slot_id];
  slottee_lt_prepare(lt, slot_id, lease_id);

  slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
  lt->run_count++;
  slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);

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

  slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
  lt->run_count++;
  slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);

  return SLOTTEE_LT_CONTEXT_MAGIC;
}

uintptr_t
slottee_lt_yield_run(uintptr_t slot_id, uintptr_t lease_id)
{
  struct slottee_lt_desc* lt;
  uintptr_t queued_slot = 0;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SLOTTEE_SLOT_MAGIC;

  lt = &slottee_lts[slot_id];
  slottee_queue_reset();
  slottee_lt_prepare(lt, slot_id, lease_id);
  slottee_lt_context_init(lt);

  if (!slottee_lt_context_isolated(lt) ||
      !slottee_queue_enqueue(slot_id) ||
      !slottee_queue_dequeue(&queued_slot) ||
      queued_slot != slot_id)
    return SLOTTEE_SLOT_MAGIC;

  slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
  slottee_lt_write_scratch(lt);

  slottee_lt_set_state(lt, SLOTTEE_LT_YIELDED);
  lt->yield_count++;
  lt->last_reason = SLOTTEE_LT_YIELD_REASON_TEST;

  if (!slottee_lt_scratch_ok(lt) ||
      !slottee_queue_enqueue(slot_id) ||
      !slottee_queue_dequeue(&queued_slot) ||
      queued_slot != slot_id)
    return SLOTTEE_SLOT_MAGIC;

  slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
  lt->resume_count++;

  if (!slottee_lt_scratch_ok(lt))
    return SLOTTEE_SLOT_MAGIC;

  lt->run_count++;
  slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);

  if (lt->yield_count != 1 ||
      lt->resume_count != 1 ||
      lt->last_reason != SLOTTEE_LT_YIELD_REASON_TEST ||
      slottee_ready_queue.count != 0 ||
      !slottee_lt_scratch_ok(lt) ||
      !slottee_lt_yield_trace_ok(lt) ||
      !slottee_lt_context_isolated(lt))
    return SLOTTEE_SLOT_MAGIC;

  return SLOTTEE_LT_YIELD_MAGIC;
}
