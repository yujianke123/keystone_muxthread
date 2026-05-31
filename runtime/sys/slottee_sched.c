#include "slottee_sched.h"

#include "call/sbi.h"
#include "util/printf.h"

#define SLOTTEE_LT_CONTEXT_VERSION 1
#define SLOTTEE_LT_STACK_WORDS     1024
#define SLOTTEE_LT_TLS_WORDS       64
#define SLOTTEE_LT_STACK_SIZE      ((uintptr_t)(SLOTTEE_LT_STACK_WORDS * sizeof(uintptr_t)))
#define SLOTTEE_LT_TLS_SIZE        ((uintptr_t)(SLOTTEE_LT_TLS_WORDS * sizeof(uintptr_t)))
#define SLOTTEE_LT_TRACE_LIMIT     8
#define SLOTTEE_LT_YIELD_REASON_TEST 1
#define SLOTTEE_LT_WAIT_REASON_TEST  2
#define SLOTTEE_LT_FAIRNESS_GAP_LIMIT 1
#define SLOTTEE_LT_STACK_SCRATCH_BASE ((uintptr_t)0x51510000)
#define SLOTTEE_LT_TLS_SCRATCH_BASE   ((uintptr_t)0x51520000)
#define SLOTTEE_LT_BIND_STACK_SCRATCH_BASE ((uintptr_t)0x51530000)
#define SLOTTEE_LT_BIND_TLS_SCRATCH_BASE   ((uintptr_t)0x51540000)
#define SLOTTEE_LT_TRAP_SAFE_STACK_GUARD_BASE ((uintptr_t)0x51550000)
#define SLOTTEE_LT_TRAP_SAFE_TLS_MARKER_BASE  ((uintptr_t)0x51560000)
#define SLOTTEE_LT_TRAP_SAFE_BOUNDARY_BASE    ((uintptr_t)0x51570000)
#define SLOTTEE_LT_ECALL_STACK_GUARD_BASE     ((uintptr_t)0x515a0000)
#define SLOTTEE_LT_ECALL_TLS_MARKER_BASE      ((uintptr_t)0x515b0000)
#define SLOTTEE_LT_SCHED_THREAD_COUNT         3

enum slottee_lt_state {
  SLOTTEE_LT_EMPTY = 0,
  SLOTTEE_LT_READY = 1,
  SLOTTEE_LT_RUNNING = 2,
  SLOTTEE_LT_YIELDED = 3,
  SLOTTEE_LT_WAITING = 4,
  SLOTTEE_LT_WOKEN = 5,
  SLOTTEE_LT_EXITED = 6,
};

enum slottee_lt_queue_kind {
  SLOTTEE_LT_QUEUE_RUNNABLE = 1,
  SLOTTEE_LT_QUEUE_WAIT = 2,
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
  uintptr_t ecall_before_sp;
  uintptr_t ecall_before_tp;
  uintptr_t ecall_after_sp;
  uintptr_t ecall_after_tp;
  uintptr_t ecall_guard_addr;
  uintptr_t ecall_guard_value;
  uintptr_t ecall_tls_marker;
  uintptr_t ecall_request;
  uintptr_t ecall_reply;
  uintptr_t ecall_status;
  uintptr_t ecall_probe_count;
};

struct slottee_lt_desc {
  uintptr_t lt_id;
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t run_count;
  uintptr_t yield_count;
  uintptr_t wait_count;
  uintptr_t wake_count;
  uintptr_t resume_count;
  uintptr_t dispatch_count;
  uintptr_t last_ticket;
  uintptr_t in_runnable_queue;
  uintptr_t in_wait_queue;
  uintptr_t last_reason;
  uintptr_t trace_len;
  enum slottee_lt_state state_trace[SLOTTEE_LT_TRACE_LIMIT];
  enum slottee_lt_state state;
  struct slottee_lt_context context;
};

struct slottee_lt_queue {
  uintptr_t entries[SLOTTEE_MAX_SLOTS];
  uintptr_t head;
  uintptr_t tail;
  uintptr_t count;
};

struct slottee_lt_scheduler_stats {
  uintptr_t created;
  uintptr_t scheduled;
  uintptr_t yielded;
  uintptr_t waited;
  uintptr_t woken;
  uintptr_t promoted;
  uintptr_t resumed;
  uintptr_t exited;
  uintptr_t duplicate_rejects;
  uintptr_t queue_errors;
  uintptr_t queue_leaks;
  uintptr_t wait_residue;
  uintptr_t unfinished;
  uintptr_t invalid_transitions;
  uintptr_t fairness_min;
  uintptr_t fairness_max;
  uintptr_t fairness_gap;
  uintptr_t fairness_checks;
  uintptr_t fairness_violations;
  uintptr_t next_ticket;
};

static struct slottee_lt_desc slottee_lts[SLOTTEE_MAX_SLOTS];
static uintptr_t slottee_lt_stack_backing[SLOTTEE_MAX_SLOTS][SLOTTEE_LT_STACK_WORDS]
    __attribute__((aligned(16)));
static uintptr_t slottee_lt_tls_backing[SLOTTEE_MAX_SLOTS][SLOTTEE_LT_TLS_WORDS]
    __attribute__((aligned(16)));
static struct slottee_lt_queue slottee_runnable_queue;
static struct slottee_lt_queue slottee_wait_queue;

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

static uintptr_t*
slottee_queue_membership(struct slottee_lt_desc* lt, enum slottee_lt_queue_kind kind)
{
  if (!lt)
    return 0;

  if (kind == SLOTTEE_LT_QUEUE_RUNNABLE)
    return &lt->in_runnable_queue;
  if (kind == SLOTTEE_LT_QUEUE_WAIT)
    return &lt->in_wait_queue;

  return 0;
}

static uintptr_t
slottee_queue_member_value(const struct slottee_lt_desc* lt, enum slottee_lt_queue_kind kind)
{
  if (!lt)
    return 0;

  if (kind == SLOTTEE_LT_QUEUE_RUNNABLE)
    return lt->in_runnable_queue;
  if (kind == SLOTTEE_LT_QUEUE_WAIT)
    return lt->in_wait_queue;

  return 0;
}

static void
slottee_queue_reset(struct slottee_lt_queue* queue)
{
  if (!queue)
    return;

  queue->head = 0;
  queue->tail = 0;
  queue->count = 0;
}

static int
slottee_queue_enqueue(struct slottee_lt_queue* queue,
    enum slottee_lt_queue_kind kind, uintptr_t slot_id)
{
  struct slottee_lt_desc* lt;
  uintptr_t* member;

  if (!queue || slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return 0;

  lt = &slottee_lts[slot_id];
  member = slottee_queue_membership(lt, kind);
  if (!member || *member || queue->count >= SLOTTEE_MAX_SLOTS)
    return 0;

  queue->entries[queue->tail] = slot_id;
  queue->tail = (queue->tail + 1) % SLOTTEE_MAX_SLOTS;
  queue->count++;
  *member = 1;
  return 1;
}

static int
slottee_queue_dequeue(struct slottee_lt_queue* queue,
    enum slottee_lt_queue_kind kind, uintptr_t* slot_id)
{
  struct slottee_lt_desc* lt;
  uintptr_t* member;

  if (!queue || !slot_id || queue->count == 0)
    return 0;

  *slot_id = queue->entries[queue->head];
  queue->head = (queue->head + 1) % SLOTTEE_MAX_SLOTS;
  queue->count--;

  if (*slot_id == 0 || *slot_id >= SLOTTEE_MAX_SLOTS)
    return 0;

  lt = &slottee_lts[*slot_id];
  member = slottee_queue_membership(lt, kind);
  if (!member || !*member)
    return 0;

  *member = 0;
  return 1;
}

static void
slottee_scheduler_queues_reset(void)
{
  uintptr_t slot;

  slottee_queue_reset(&slottee_runnable_queue);
  slottee_queue_reset(&slottee_wait_queue);
  for (slot = 0; slot < SLOTTEE_MAX_SLOTS; slot++) {
    slottee_lts[slot].in_runnable_queue = 0;
    slottee_lts[slot].in_wait_queue = 0;
  }
}

static int
slottee_queue_rejects_duplicate(struct slottee_lt_queue* queue,
    enum slottee_lt_queue_kind kind, uintptr_t slot_id,
    struct slottee_lt_scheduler_stats* stats)
{
  struct slottee_lt_desc* lt;

  if (!queue || slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return 0;

  lt = &slottee_lts[slot_id];
  if (!slottee_queue_member_value(lt, kind))
    return 0;

  if (slottee_queue_enqueue(queue, kind, slot_id))
    return 0;

  if (stats)
    stats->duplicate_rejects++;
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
  lt->wait_count = 0;
  lt->wake_count = 0;
  lt->resume_count = 0;
  lt->dispatch_count = 0;
  lt->last_ticket = 0;
  lt->in_runnable_queue = 0;
  lt->in_wait_queue = 0;
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
  lt->context.ecall_before_sp = 0;
  lt->context.ecall_before_tp = 0;
  lt->context.ecall_after_sp = 0;
  lt->context.ecall_after_tp = 0;
  lt->context.ecall_guard_addr = 0;
  lt->context.ecall_guard_value = 0;
  lt->context.ecall_tls_marker = 0;
  lt->context.ecall_request = 0;
  lt->context.ecall_reply = 0;
  lt->context.ecall_status = 0;
  lt->context.ecall_probe_count = 0;
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
  if (!lt)
    return 0;

  return lt->trace_len == 5 &&
      lt->state_trace[0] == SLOTTEE_LT_READY &&
      lt->state_trace[1] == SLOTTEE_LT_RUNNING &&
      lt->state_trace[2] == SLOTTEE_LT_YIELDED &&
      lt->state_trace[3] == SLOTTEE_LT_RUNNING &&
      lt->state_trace[4] == SLOTTEE_LT_EXITED;
}

static int
slottee_lt_scheduler_trace_ok(const struct slottee_lt_desc* lt)
{
  if (!lt)
    return 0;

  if (lt->wait_count)
    return lt->trace_len == 6 &&
        lt->state_trace[0] == SLOTTEE_LT_READY &&
        lt->state_trace[1] == SLOTTEE_LT_RUNNING &&
        lt->state_trace[2] == SLOTTEE_LT_WAITING &&
        lt->state_trace[3] == SLOTTEE_LT_WOKEN &&
        lt->state_trace[4] == SLOTTEE_LT_RUNNING &&
        lt->state_trace[5] == SLOTTEE_LT_EXITED;

  return lt->trace_len == 5 &&
      lt->state_trace[0] == SLOTTEE_LT_READY &&
      lt->state_trace[1] == SLOTTEE_LT_RUNNING &&
      lt->state_trace[2] == SLOTTEE_LT_YIELDED &&
      lt->state_trace[3] == SLOTTEE_LT_RUNNING &&
      lt->state_trace[4] == SLOTTEE_LT_EXITED;
}

static uintptr_t
slottee_lt_scheduler_slot_id(uintptr_t thread_index)
{
  return thread_index + 1;
}

static int
slottee_lt_scheduler_create_threads(uintptr_t lease_id,
    struct slottee_lt_scheduler_stats* stats)
{
  uintptr_t thread_index;

  if (!stats || SLOTTEE_LT_SCHED_THREAD_COUNT == 0 ||
      SLOTTEE_LT_SCHED_THREAD_COUNT >= SLOTTEE_MAX_SLOTS)
    return 0;

  stats->created = 0;
  slottee_scheduler_queues_reset();

  for (thread_index = 0; thread_index < SLOTTEE_LT_SCHED_THREAD_COUNT;
       thread_index++) {
    uintptr_t lt_slot = slottee_lt_scheduler_slot_id(thread_index);
    struct slottee_lt_desc* lt = &slottee_lts[lt_slot];

    slottee_lt_prepare(lt, lt_slot, lease_id);
    slottee_lt_context_init(lt);

    if (!slottee_lt_context_isolated(lt) ||
        !slottee_queue_enqueue(&slottee_runnable_queue,
            SLOTTEE_LT_QUEUE_RUNNABLE, lt_slot)) {
      stats->queue_errors++;
      return 0;
    }

    if (!slottee_queue_rejects_duplicate(&slottee_runnable_queue,
            SLOTTEE_LT_QUEUE_RUNNABLE, lt_slot, stats)) {
      stats->queue_errors++;
      return 0;
    }

    stats->created++;
  }

  return stats->created == SLOTTEE_LT_SCHED_THREAD_COUNT;
}

static int
slottee_lt_scheduler_dispatch(struct slottee_lt_scheduler_stats* stats,
    uintptr_t expected_state, uintptr_t* out_slot)
{
  uintptr_t queued_slot = 0;
  struct slottee_lt_desc* lt;

  if (!stats || !out_slot)
    return 0;

  if (!slottee_queue_dequeue(&slottee_runnable_queue,
          SLOTTEE_LT_QUEUE_RUNNABLE, &queued_slot)) {
    stats->queue_errors++;
    return 0;
  }

  lt = &slottee_lts[queued_slot];
  if (lt->state != expected_state) {
    stats->invalid_transitions++;
    return 0;
  }

  slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
  stats->next_ticket++;
  lt->last_ticket = stats->next_ticket;
  lt->run_count++;
  lt->dispatch_count++;
  stats->scheduled++;
  *out_slot = queued_slot;
  return 1;
}

static int
slottee_lt_scheduler_yield_or_wait_ready_threads(
    struct slottee_lt_scheduler_stats* stats)
{
  uintptr_t thread_index;

  if (!stats)
    return 0;

  for (thread_index = 0; thread_index < SLOTTEE_LT_SCHED_THREAD_COUNT;
       thread_index++) {
    uintptr_t queued_slot = 0;
    struct slottee_lt_desc* lt;

    if (!slottee_lt_scheduler_dispatch(stats, SLOTTEE_LT_READY, &queued_slot))
      return 0;

    lt = &slottee_lts[queued_slot];
    slottee_lt_write_scratch(lt);

    if (!slottee_lt_scratch_ok(lt))
      return 0;

    if (thread_index == SLOTTEE_LT_SCHED_THREAD_COUNT - 1) {
      slottee_lt_set_state(lt, SLOTTEE_LT_WAITING);
      lt->wait_count++;
      lt->last_reason = SLOTTEE_LT_WAIT_REASON_TEST;
      stats->waited++;

      if (!slottee_queue_enqueue(&slottee_wait_queue,
              SLOTTEE_LT_QUEUE_WAIT, queued_slot)) {
        stats->queue_errors++;
        return 0;
      }
      if (!slottee_queue_rejects_duplicate(&slottee_wait_queue,
              SLOTTEE_LT_QUEUE_WAIT, queued_slot, stats)) {
        stats->queue_errors++;
        return 0;
      }
    } else {
      slottee_lt_set_state(lt, SLOTTEE_LT_YIELDED);
      lt->yield_count++;
      lt->last_reason = SLOTTEE_LT_YIELD_REASON_TEST;
      stats->yielded++;

      if (!slottee_queue_enqueue(&slottee_runnable_queue,
              SLOTTEE_LT_QUEUE_RUNNABLE, queued_slot)) {
        stats->queue_errors++;
        return 0;
      }
      if (!slottee_queue_rejects_duplicate(&slottee_runnable_queue,
              SLOTTEE_LT_QUEUE_RUNNABLE, queued_slot, stats)) {
        stats->queue_errors++;
        return 0;
      }
    }
  }

  return 1;
}

static int
slottee_lt_scheduler_promote_waiters(struct slottee_lt_scheduler_stats* stats)
{
  while (slottee_wait_queue.count) {
    uintptr_t queued_slot = 0;
    struct slottee_lt_desc* lt;

    if (!slottee_queue_dequeue(&slottee_wait_queue,
            SLOTTEE_LT_QUEUE_WAIT, &queued_slot)) {
      if (stats)
        stats->queue_errors++;
      return 0;
    }

    lt = &slottee_lts[queued_slot];
    if (lt->state != SLOTTEE_LT_WAITING ||
        !slottee_lt_scratch_ok(lt)) {
      if (stats)
        stats->invalid_transitions++;
      return 0;
    }

    slottee_lt_set_state(lt, SLOTTEE_LT_WOKEN);
    lt->wake_count++;
    if (stats) {
      stats->woken++;
      stats->promoted++;
    }

    if (!slottee_queue_enqueue(&slottee_runnable_queue,
            SLOTTEE_LT_QUEUE_RUNNABLE, queued_slot)) {
      if (stats)
        stats->queue_errors++;
      return 0;
    }
    if (!slottee_queue_rejects_duplicate(&slottee_runnable_queue,
            SLOTTEE_LT_QUEUE_RUNNABLE, queued_slot, stats)) {
      if (stats)
        stats->queue_errors++;
      return 0;
    }
  }

  return 1;
}

static int
slottee_lt_scheduler_resume_threads(struct slottee_lt_scheduler_stats* stats)
{
  while (slottee_runnable_queue.count) {
    uintptr_t queued_slot = 0;
    uintptr_t expected_state;
    struct slottee_lt_desc* lt;

    if (!slottee_queue_dequeue(&slottee_runnable_queue,
            SLOTTEE_LT_QUEUE_RUNNABLE, &queued_slot)) {
      if (stats)
        stats->queue_errors++;
      return 0;
    }

    lt = &slottee_lts[queued_slot];
    if (!slottee_lt_scratch_ok(lt))
      return 0;

    expected_state = lt->state;
    if (expected_state != SLOTTEE_LT_YIELDED &&
        expected_state != SLOTTEE_LT_WOKEN) {
      if (stats)
        stats->invalid_transitions++;
      return 0;
    }

    slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
    if (stats) {
      stats->next_ticket++;
      stats->scheduled++;
      stats->resumed++;
    }
    lt->last_ticket = stats ? stats->next_ticket : lt->last_ticket + 1;
    lt->run_count++;
    lt->dispatch_count++;
    lt->resume_count++;

    if (!slottee_lt_scratch_ok(lt))
      return 0;

    slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);
    if (stats)
      stats->exited++;
  }

  return 1;
}

static void
slottee_lt_scheduler_check_fairness(struct slottee_lt_scheduler_stats* stats)
{
  uintptr_t thread_index;

  if (!stats)
    return;

  stats->fairness_min = (uintptr_t)-1;
  stats->fairness_max = 0;
  stats->fairness_gap = 0;
  stats->fairness_checks++;

  for (thread_index = 0; thread_index < SLOTTEE_LT_SCHED_THREAD_COUNT;
       thread_index++) {
    uintptr_t lt_slot = slottee_lt_scheduler_slot_id(thread_index);
    const struct slottee_lt_desc* lt = &slottee_lts[lt_slot];

    if (lt->dispatch_count < stats->fairness_min)
      stats->fairness_min = lt->dispatch_count;
    if (lt->dispatch_count > stats->fairness_max)
      stats->fairness_max = lt->dispatch_count;
  }

  if (stats->fairness_min == (uintptr_t)-1)
    stats->fairness_min = 0;
  if (stats->fairness_max >= stats->fairness_min)
    stats->fairness_gap = stats->fairness_max - stats->fairness_min;
  if (stats->fairness_gap > SLOTTEE_LT_FAIRNESS_GAP_LIMIT)
    stats->fairness_violations++;
}

static void
slottee_lt_scheduler_check_consistency(struct slottee_lt_scheduler_stats* stats)
{
  uintptr_t thread_index;

  if (!stats)
    return;

  if (slottee_runnable_queue.count != 0)
    stats->queue_leaks += slottee_runnable_queue.count;
  if (slottee_wait_queue.count != 0)
    stats->wait_residue += slottee_wait_queue.count;

  for (thread_index = 0; thread_index < SLOTTEE_LT_SCHED_THREAD_COUNT;
       thread_index++) {
    uintptr_t lt_slot = slottee_lt_scheduler_slot_id(thread_index);
    const struct slottee_lt_desc* lt = &slottee_lts[lt_slot];

    if (lt->in_runnable_queue || lt->in_wait_queue)
      stats->queue_leaks++;
    if (lt->state != SLOTTEE_LT_EXITED)
      stats->unfinished++;
  }
}

static int
slottee_lt_scheduler_threads_done(const struct slottee_lt_scheduler_stats* stats)
{
  uintptr_t thread_index;

  if (!stats ||
      slottee_runnable_queue.count != 0 ||
      slottee_wait_queue.count != 0 ||
      stats->created != SLOTTEE_LT_SCHED_THREAD_COUNT ||
      stats->scheduled != SLOTTEE_LT_SCHED_THREAD_COUNT * 2 ||
      stats->yielded != SLOTTEE_LT_SCHED_THREAD_COUNT - 1 ||
      stats->waited != 1 ||
      stats->woken != 1 ||
      stats->promoted != 1 ||
      stats->resumed != SLOTTEE_LT_SCHED_THREAD_COUNT ||
      stats->exited != SLOTTEE_LT_SCHED_THREAD_COUNT ||
      stats->duplicate_rejects < SLOTTEE_LT_SCHED_THREAD_COUNT + 1 ||
      stats->queue_errors != 0 ||
      stats->queue_leaks != 0 ||
      stats->wait_residue != 0 ||
      stats->unfinished != 0 ||
      stats->invalid_transitions != 0 ||
      stats->fairness_checks == 0 ||
      stats->fairness_gap > SLOTTEE_LT_FAIRNESS_GAP_LIMIT ||
      stats->fairness_violations != 0)
    return 0;

  for (thread_index = 0; thread_index < SLOTTEE_LT_SCHED_THREAD_COUNT;
       thread_index++) {
    uintptr_t lt_slot = slottee_lt_scheduler_slot_id(thread_index);
    const struct slottee_lt_desc* lt = &slottee_lts[lt_slot];

    if (lt->state != SLOTTEE_LT_EXITED ||
        lt->run_count != 2 ||
        lt->dispatch_count != 2 ||
        lt->resume_count != 1 ||
        lt->yield_count + lt->wait_count != 1 ||
        ((lt->wait_count == 0 &&
          (lt->yield_count != 1 || lt->wake_count != 0 ||
           lt->last_reason != SLOTTEE_LT_YIELD_REASON_TEST)) ||
         (lt->wait_count == 1 &&
          (lt->yield_count != 0 || lt->wake_count != 1 ||
           lt->last_reason != SLOTTEE_LT_WAIT_REASON_TEST))) ||
        !slottee_lt_scratch_ok(lt) ||
        !slottee_lt_scheduler_trace_ok(lt) ||
        !slottee_lt_context_isolated(lt))
      return 0;
  }

  return 1;
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

static void
slottee_lt_ecall_entry(void* opaque)
{
  struct slottee_lt_desc* lt = (struct slottee_lt_desc*)opaque;
  volatile uintptr_t ecall_guard = SLOTTEE_LT_ECALL_STACK_GUARD_BASE | lt->slot_id;
  uintptr_t before_sp = 0;
  uintptr_t before_tp = 0;
  uintptr_t after_sp = 0;
  uintptr_t after_tp = 0;
  uintptr_t reply = 0;
  uintptr_t request;
  uintptr_t* tls;

  __asm__ volatile("mv %0, sp" : "=r"(before_sp));
  __asm__ volatile("mv %0, tp" : "=r"(before_tp));

  request = SLOTTEE_LT_ECALL_MAKE_REQUEST(lt->slot_id, lt->lease_id);
  tls = (uintptr_t*)before_tp;
  tls[7] = SLOTTEE_LT_ECALL_TLS_MARKER_BASE | lt->slot_id;
  tls[8] = request;

  lt->context.ecall_before_sp = before_sp;
  lt->context.ecall_before_tp = before_tp;
  lt->context.ecall_guard_addr = (uintptr_t)&ecall_guard;
  lt->context.ecall_guard_value = ecall_guard;
  lt->context.ecall_tls_marker = tls[7];
  lt->context.ecall_request = request;

  lt->context.ecall_status =
      sbi_lt_ecall_probe(lt->slot_id, lt->lease_id, request, &reply);

  __asm__ volatile("mv %0, sp" : "=r"(after_sp));
  __asm__ volatile("mv %0, tp" : "=r"(after_tp));

  lt->context.ecall_after_sp = after_sp;
  lt->context.ecall_after_tp = after_tp;
  lt->context.ecall_reply = reply;
  lt->context.ecall_probe_count++;

  tls = (uintptr_t*)after_tp;
  tls[9] = reply;
}

static int
slottee_lt_ecall_probe_ok(const struct slottee_lt_desc* lt)
{
  const uintptr_t* tls = (const uintptr_t*)lt->context.tls_base;
  const volatile uintptr_t* guard =
      (const volatile uintptr_t*)lt->context.ecall_guard_addr;

  return lt->context.runtime_sp_before != 0 &&
      lt->context.runtime_tp_before == lt->context.runtime_tp_after &&
      lt->context.runtime_sp_before == lt->context.runtime_sp_after &&
      lt->context.ecall_status == 0 &&
      lt->context.ecall_request ==
          SLOTTEE_LT_ECALL_MAKE_REQUEST(lt->slot_id, lt->lease_id) &&
      lt->context.ecall_reply ==
          SLOTTEE_LT_ECALL_MAKE_REPLY(lt->slot_id, lt->lease_id) &&
      slottee_addr_in_range(lt->context.ecall_before_sp,
          lt->context.stack_base, lt->context.stack_size) &&
      lt->context.ecall_before_sp == lt->context.ecall_after_sp &&
      lt->context.ecall_before_tp == lt->context.tls_base &&
      lt->context.ecall_before_tp == lt->context.ecall_after_tp &&
      slottee_addr_in_range(lt->context.ecall_after_sp,
          lt->context.stack_base, lt->context.stack_size) &&
      lt->context.ecall_after_tp == lt->context.tls_base &&
      slottee_addr_in_range(lt->context.ecall_guard_addr,
          lt->context.stack_base, lt->context.stack_size) &&
      guard[0] == lt->context.ecall_guard_value &&
      tls[7] == lt->context.ecall_tls_marker &&
      tls[8] == lt->context.ecall_request &&
      tls[9] == lt->context.ecall_reply &&
      lt->context.ecall_probe_count == 1;
}

uintptr_t
slottee_lt_scheduler_run(uintptr_t slot_id, uintptr_t lease_id)
{
  struct slottee_lt_scheduler_stats stats = {0};
  int ok;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SLOTTEE_SLOT_MAGIC;

  ok = slottee_lt_scheduler_create_threads(lease_id, &stats) &&
      slottee_lt_scheduler_yield_or_wait_ready_threads(&stats) &&
      slottee_lt_scheduler_promote_waiters(&stats) &&
      slottee_lt_scheduler_resume_threads(&stats);
  slottee_lt_scheduler_check_fairness(&stats);
  slottee_lt_scheduler_check_consistency(&stats);
  ok = ok && slottee_lt_scheduler_threads_done(&stats);

  printf("[slottee] lt_sched_stats anchor_slot=%lu lease=%lu threads=%lu created=%lu scheduled=%lu yielded=%lu waited=%lu woken=%lu promoted=%lu resumed=%lu exited=%lu dup=%lu qerr=%lu qleak=%lu wait_residue=%lu unfinished=%lu invalid=%lu fair_min=%lu fair_max=%lu fair_gap=%lu fair_bad=%lu ok=%lu\r\n",
      slot_id, lease_id, (uintptr_t)SLOTTEE_LT_SCHED_THREAD_COUNT,
      stats.created, stats.scheduled, stats.yielded, stats.waited,
      stats.woken, stats.promoted, stats.resumed, stats.exited,
      stats.duplicate_rejects, stats.queue_errors, stats.queue_leaks,
      stats.wait_residue, stats.unfinished, stats.invalid_transitions,
      stats.fairness_min, stats.fairness_max, stats.fairness_gap,
      stats.fairness_violations, (uintptr_t)ok);

  if (!ok)
    return SLOTTEE_SLOT_MAGIC;

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
  slottee_scheduler_queues_reset();
  slottee_lt_prepare(lt, slot_id, lease_id);
  slottee_lt_context_init(lt);

  if (!slottee_lt_context_isolated(lt) ||
      !slottee_queue_enqueue(&slottee_runnable_queue,
          SLOTTEE_LT_QUEUE_RUNNABLE, slot_id) ||
      !slottee_queue_dequeue(&slottee_runnable_queue,
          SLOTTEE_LT_QUEUE_RUNNABLE, &queued_slot) ||
      queued_slot != slot_id)
    return SLOTTEE_SLOT_MAGIC;

  slottee_lt_set_state(lt, SLOTTEE_LT_RUNNING);
  slottee_lt_write_scratch(lt);

  slottee_lt_set_state(lt, SLOTTEE_LT_YIELDED);
  lt->yield_count++;
  lt->last_reason = SLOTTEE_LT_YIELD_REASON_TEST;

  if (!slottee_lt_scratch_ok(lt) ||
      !slottee_queue_enqueue(&slottee_runnable_queue,
          SLOTTEE_LT_QUEUE_RUNNABLE, slot_id) ||
      !slottee_queue_dequeue(&slottee_runnable_queue,
          SLOTTEE_LT_QUEUE_RUNNABLE, &queued_slot) ||
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
      slottee_runnable_queue.count != 0 ||
      slottee_wait_queue.count != 0 ||
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

uintptr_t
slottee_lt_ecall_run(uintptr_t slot_id, uintptr_t lease_id)
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
      slottee_lt_ecall_entry, lt,
      &lt->context.runtime_sp_before, &lt->context.runtime_tp_before);
  __asm__ volatile("mv %0, sp" : "=r"(lt->context.runtime_sp_after));
  __asm__ volatile("mv %0, tp" : "=r"(lt->context.runtime_tp_after));
  lt->run_count++;
  slottee_lt_set_state(lt, SLOTTEE_LT_EXITED);

  if (!slottee_lt_ecall_probe_ok(lt) ||
      !slottee_lt_context_isolated(lt) ||
      lt->trace_len != 3 ||
      lt->state_trace[0] != SLOTTEE_LT_READY ||
      lt->state_trace[1] != SLOTTEE_LT_RUNNING ||
      lt->state_trace[2] != SLOTTEE_LT_EXITED)
    return SLOTTEE_SLOT_MAGIC;

  return SLOTTEE_LT_ECALL_MAGIC;
}
