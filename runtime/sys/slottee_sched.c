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
#define SLOTTEE_LT_BIND_STACK_SCRATCH_BASE ((uintptr_t)0x51530000)
#define SLOTTEE_LT_BIND_TLS_SCRATCH_BASE   ((uintptr_t)0x51540000)
#define SLOTTEE_LT_TRAP_SAFE_STACK_GUARD_BASE ((uintptr_t)0x51550000)
#define SLOTTEE_LT_TRAP_SAFE_TLS_MARKER_BASE  ((uintptr_t)0x51560000)
#define SLOTTEE_LT_TRAP_SAFE_BOUNDARY_BASE    ((uintptr_t)0x51570000)

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
  uintptr_t runtime_sp_before;
  uintptr_t runtime_tp_before;
  uintptr_t runtime_sp_after;
  uintptr_t runtime_tp_after;
  uintptr_t bound_sp;
  uintptr_t bound_tp;
  uintptr_t stack_scratch_addr;
  uintptr_t stack_scratch;
  uintptr_t tls_scratch;
  uintptr_t trap_entry_sp;
  uintptr_t trap_entry_tp;
  uintptr_t trap_exit_sp;
  uintptr_t trap_exit_tp;
  uintptr_t trap_guard_addr;
  uintptr_t trap_guard_value;
  uintptr_t trap_tls_marker;
  uintptr_t trap_boundary_marker;
  uintptr_t trap_probe_count;
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
static uintptr_t slottee_lt_stack_backing[SLOTTEE_MAX_SLOTS][SLOTTEE_LT_STACK_WORDS]
    __attribute__((aligned(16)));
static uintptr_t slottee_lt_tls_backing[SLOTTEE_MAX_SLOTS][SLOTTEE_LT_TLS_WORDS]
    __attribute__((aligned(16)));
static struct slottee_ready_queue slottee_ready_queue;

void slottee_lt_bind_switch(uintptr_t lt_sp, uintptr_t lt_tp,
    void (*entry)(void*), void* arg,
    uintptr_t* runtime_sp_before, uintptr_t* runtime_tp_before);

static int
slottee_range_overlaps(uintptr_t base_a, uintptr_t size_a, uintptr_t base_b, uintptr_t size_b)
{
  uintptr_t end_a = base_a + size_a;
  uintptr_t end_b = base_b + size_b;

  return base_a < end_b && base_b < end_a;
}

static int
slottee_addr_in_range(uintptr_t addr, uintptr_t base, uintptr_t size)
{
  return addr >= base && addr < (base + size);
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
  lt->context.runtime_sp_before = 0;
  lt->context.runtime_tp_before = 0;
  lt->context.runtime_sp_after = 0;
  lt->context.runtime_tp_after = 0;
  lt->context.bound_sp = 0;
  lt->context.bound_tp = 0;
  lt->context.stack_scratch_addr = 0;
  lt->context.stack_scratch = 0;
  lt->context.tls_scratch = 0;
  lt->context.trap_entry_sp = 0;
  lt->context.trap_entry_tp = 0;
  lt->context.trap_exit_sp = 0;
  lt->context.trap_exit_tp = 0;
  lt->context.trap_guard_addr = 0;
  lt->context.trap_guard_value = 0;
  lt->context.trap_tls_marker = 0;
  lt->context.trap_boundary_marker = 0;
  lt->context.trap_probe_count = 0;
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

static void
slottee_lt_binding_entry(void* opaque)
{
  struct slottee_lt_desc* lt = (struct slottee_lt_desc*)opaque;
  volatile uintptr_t stack_scratch = SLOTTEE_LT_BIND_STACK_SCRATCH_BASE | lt->slot_id;
  uintptr_t observed_sp = 0;
  uintptr_t observed_tp = 0;
  uintptr_t* tls;

  __asm__ volatile("mv %0, sp" : "=r"(observed_sp));
  __asm__ volatile("mv %0, tp" : "=r"(observed_tp));

  tls = (uintptr_t*)observed_tp;
  tls[2] = SLOTTEE_LT_BIND_TLS_SCRATCH_BASE | lt->slot_id;
  tls[3] = lt->lease_id;

  lt->context.bound_sp = observed_sp;
  lt->context.bound_tp = observed_tp;
  lt->context.stack_scratch_addr = (uintptr_t)&stack_scratch;
  lt->context.stack_scratch = stack_scratch;
  lt->context.tls_scratch = tls[2];
}

static int
slottee_lt_bind_probe_ok(const struct slottee_lt_desc* lt)
{
  const uintptr_t* stack_scratch = (const uintptr_t*)lt->context.stack_scratch_addr;
  const uintptr_t* tls = (const uintptr_t*)lt->context.tls_base;

  return lt->context.runtime_sp_before != 0 &&
      lt->context.runtime_tp_before == lt->context.runtime_tp_after &&
      lt->context.runtime_sp_before == lt->context.runtime_sp_after &&
      slottee_addr_in_range(lt->context.bound_sp,
          lt->context.stack_base, lt->context.stack_size) &&
      lt->context.bound_tp == lt->context.tls_base &&
      slottee_addr_in_range(lt->context.stack_scratch_addr,
          lt->context.stack_base, lt->context.stack_size) &&
      stack_scratch[0] == lt->context.stack_scratch &&
      tls[2] == lt->context.tls_scratch &&
      tls[3] == lt->lease_id;
}

static int
slottee_lt_trap_safe_boundary_probe(struct slottee_lt_desc* lt,
    uintptr_t entry_sp, uintptr_t entry_tp,
    uintptr_t guard_addr, uintptr_t guard_value)
{
  uintptr_t observed_sp = 0;
  uintptr_t observed_tp = 0;
  uintptr_t* tls = (uintptr_t*)entry_tp;

  __asm__ volatile("mv %0, sp" : "=r"(observed_sp));
  __asm__ volatile("mv %0, tp" : "=r"(observed_tp));

  if (!slottee_addr_in_range(entry_sp, lt->context.stack_base, lt->context.stack_size) ||
      !slottee_addr_in_range(observed_sp, lt->context.stack_base, lt->context.stack_size) ||
      observed_tp != entry_tp ||
      observed_tp != lt->context.tls_base ||
      !slottee_addr_in_range(guard_addr, lt->context.stack_base, lt->context.stack_size))
    return 0;

  tls[4] = SLOTTEE_LT_TRAP_SAFE_TLS_MARKER_BASE | lt->slot_id;
  tls[5] = lt->lease_id;
  tls[6] = SLOTTEE_LT_TRAP_SAFE_BOUNDARY_BASE | lt->slot_id;

  lt->context.trap_tls_marker = tls[4];
  lt->context.trap_boundary_marker = tls[6];
  lt->context.trap_probe_count++;

  return *((volatile uintptr_t*)guard_addr) == guard_value;
}

static void
slottee_lt_trap_safe_entry(void* opaque)
{
  struct slottee_lt_desc* lt = (struct slottee_lt_desc*)opaque;
  volatile uintptr_t trap_guard = SLOTTEE_LT_TRAP_SAFE_STACK_GUARD_BASE | lt->slot_id;
  uintptr_t entry_sp = 0;
  uintptr_t entry_tp = 0;
  uintptr_t exit_sp = 0;
  uintptr_t exit_tp = 0;

  __asm__ volatile("mv %0, sp" : "=r"(entry_sp));
  __asm__ volatile("mv %0, tp" : "=r"(entry_tp));

  lt->context.trap_entry_sp = entry_sp;
  lt->context.trap_entry_tp = entry_tp;
  lt->context.trap_guard_addr = (uintptr_t)&trap_guard;
  lt->context.trap_guard_value = trap_guard;

  if (!slottee_lt_trap_safe_boundary_probe(lt, entry_sp, entry_tp,
          (uintptr_t)&trap_guard, trap_guard))
    return;

  __asm__ volatile("mv %0, sp" : "=r"(exit_sp));
  __asm__ volatile("mv %0, tp" : "=r"(exit_tp));

  lt->context.trap_exit_sp = exit_sp;
  lt->context.trap_exit_tp = exit_tp;
}

static int
slottee_lt_trap_safe_probe_ok(const struct slottee_lt_desc* lt)
{
  const uintptr_t* tls = (const uintptr_t*)lt->context.tls_base;
  const volatile uintptr_t* guard =
      (const volatile uintptr_t*)lt->context.trap_guard_addr;

  return lt->context.runtime_sp_before != 0 &&
      lt->context.runtime_tp_before == lt->context.runtime_tp_after &&
      lt->context.runtime_sp_before == lt->context.runtime_sp_after &&
      slottee_addr_in_range(lt->context.trap_entry_sp,
          lt->context.stack_base, lt->context.stack_size) &&
      lt->context.trap_entry_tp == lt->context.tls_base &&
      slottee_addr_in_range(lt->context.trap_exit_sp,
          lt->context.stack_base, lt->context.stack_size) &&
      lt->context.trap_exit_tp == lt->context.tls_base &&
      slottee_addr_in_range(lt->context.trap_guard_addr,
          lt->context.stack_base, lt->context.stack_size) &&
      guard[0] == lt->context.trap_guard_value &&
      tls[4] == lt->context.trap_tls_marker &&
      tls[5] == lt->lease_id &&
      tls[6] == lt->context.trap_boundary_marker &&
      lt->context.trap_probe_count == 1;
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

uintptr_t
slottee_lt_bind_run(uintptr_t slot_id, uintptr_t lease_id)
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
  slottee_lt_bind_switch(lt->context.saved_sp, lt->context.saved_tp,
      slottee_lt_binding_entry, lt,
      &lt->context.runtime_sp_before, &lt->context.runtime_tp_before);
  __asm__ volatile("mv %0, sp" : "=r"(lt->context.runtime_sp_after));
  __asm__ volatile("mv %0, tp" : "=r"(lt->context.runtime_tp_after));
  lt->run_count++;
  slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);

  if (!slottee_lt_bind_probe_ok(lt) ||
      !slottee_lt_context_isolated(lt) ||
      lt->trace_len != 3 ||
      lt->state_trace[0] != SLOTTEE_LT_READY ||
      lt->state_trace[1] != SLOTTEE_LT_RUNNING ||
      lt->state_trace[2] != SLOTTEE_LT_EXITED)
    return SLOTTEE_SLOT_MAGIC;

  return SLOTTEE_LT_BIND_MAGIC;
}

uintptr_t
slottee_lt_trap_safe_run(uintptr_t slot_id, uintptr_t lease_id)
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
  slottee_lt_bind_switch(lt->context.saved_sp, lt->context.saved_tp,
      slottee_lt_trap_safe_entry, lt,
      &lt->context.runtime_sp_before, &lt->context.runtime_tp_before);
  __asm__ volatile("mv %0, sp" : "=r"(lt->context.runtime_sp_after));
  __asm__ volatile("mv %0, tp" : "=r"(lt->context.runtime_tp_after));
  lt->run_count++;
  slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);

  if (!slottee_lt_trap_safe_probe_ok(lt) ||
      !slottee_lt_context_isolated(lt) ||
      lt->trace_len != 3 ||
      lt->state_trace[0] != SLOTTEE_LT_READY ||
      lt->state_trace[1] != SLOTTEE_LT_RUNNING ||
      lt->state_trace[2] != SLOTTEE_LT_EXITED)
    return SLOTTEE_SLOT_MAGIC;

  return SLOTTEE_LT_TRAP_SAFE_MAGIC;
}
