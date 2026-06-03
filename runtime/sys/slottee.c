#include "call/sbi.h"
#include "edge_call.h"
#include "eyrie_call.h"
#include "mm/mm.h"
#include "mm/vm.h"
#include "sys/slottee.h"
#include "slottee_sched.h"
#include "sm_err.h"
#include "util/printf.h"
#include "util/regs.h"
#include "util/string.h"
#include "uaccess.h"
#include <asm/csr.h>

#define SLOTTEE_USER_STACK_PAGES 8
#define SLOTTEE_USER_TLS_PAGES   1
#define SLOTTEE_USER_STACK_SIZE \
  ((uintptr_t)(SLOTTEE_USER_STACK_PAGES * RISCV_PAGE_SIZE))
#define SLOTTEE_USER_TLS_SIZE \
  ((uintptr_t)(SLOTTEE_USER_TLS_PAGES * RISCV_PAGE_SIZE))
#define SLOTTEE_USER_REGION_GAP  RISCV_PAGE_SIZE
#define SLOTTEE_USER_SLOT_STRIDE \
  (SLOTTEE_USER_STACK_SIZE + SLOTTEE_USER_TLS_SIZE + SLOTTEE_USER_REGION_GAP)
#define SLOTTEE_RUNTIME_STACK_PAGES 8
#define SLOTTEE_RUNTIME_STACK_WORDS \
  ((SLOTTEE_RUNTIME_STACK_PAGES * RISCV_PAGE_SIZE) / sizeof(uintptr_t))
#define SLOTTEE_LT_SPAWN_OCALL_COPY_SLOT_CAP 5
#define SLOTTEE_LT_FAIRNESS_GAP_LIMIT SLOTTEE_MAX_SLOTS

enum slottee_user_lt_state {
  SLOTTEE_USER_LT_EMPTY = 0,
  SLOTTEE_USER_LT_READY = 1,
  SLOTTEE_USER_LT_RUNNING = 2,
  SLOTTEE_USER_LT_YIELDED = 3,
  SLOTTEE_USER_LT_WAITING = 4,
  SLOTTEE_USER_LT_WOKEN = 5,
  SLOTTEE_USER_LT_EXITED = 6,
};

enum slottee_user_lt_queue_kind {
  SLOTTEE_USER_LT_QUEUE_RUNNABLE = 1,
  SLOTTEE_USER_LT_QUEUE_WAIT = 2,
};

struct slottee_user_lt_queue {
  uintptr_t entries[SLOTTEE_MAX_SLOTS];
  uintptr_t head;
  uintptr_t tail;
  uintptr_t count;
};

struct slottee_active_user_context {
  uintptr_t active;
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t mode;
  uintptr_t enter_count;
  uintptr_t user_stack_base;
  uintptr_t user_stack_top;
  uintptr_t user_tls_base;
  uintptr_t user_tls_size;
  uintptr_t user_stack_pages;
  uintptr_t user_tls_pages;
  uintptr_t user_alloc_ok;
  uintptr_t last_trap_syscall;
  uintptr_t last_trap_scause;
  uintptr_t last_trap_sepc;
  uintptr_t last_trap_stval;
  uintptr_t last_trap_user_sp;
  uintptr_t last_trap_user_tp;
  uintptr_t syscall_trap_count;
  uintptr_t ocall_trap_count;
  uintptr_t ocall_resume_count;
  uintptr_t exit_trap_count;
  uintptr_t fault_trap_count;
  uintptr_t revoke_on_fault;
  uintptr_t lt_entry_active;
  uintptr_t entry_tls_base;
  uintptr_t tls_entry_ok;
  uintptr_t tls_exit_ok;
  uintptr_t tls_exit_mismatch;
  uintptr_t wait_user_ptr;
  uintptr_t wait_target;
  uintptr_t wait_op;
  uintptr_t wait_block_count;
  uintptr_t wait_wakeup_count;
  uintptr_t wait_notify_miss_count;
  uintptr_t timer_wait_stop_count;
  uintptr_t preempt_count;
  uintptr_t preempt_yield_count;
  uintptr_t preempt_dispatch_count;
  uintptr_t preempt_worker;
  uintptr_t dispatch_count;
  uintptr_t in_runnable_queue;
  uintptr_t in_wait_queue;
  uintptr_t saved_ctx_valid;
  uintptr_t fairness_ticket;
  uintptr_t hart_id;
  enum slottee_user_lt_state scheduler_state;
  struct encl_ctx saved_ctx;
  uintptr_t user_stack_entry_ok;
  uintptr_t user_stack_exit_ok;
  uintptr_t tls_resume_ok;
};

struct slottee_lt_entry {
  uintptr_t slot_id;
  uintptr_t fn;
  uintptr_t arg;
  uintptr_t registered;
};

struct slottee_slot_policy_entry {
  uintptr_t active;
  uintptr_t affinity_hint;
  uintptr_t priority;
};

static struct slottee_active_user_context slottee_active_users[SLOTTEE_MAX_SLOTS];
uintptr_t
    slottee_runtime_stacks[SLOTTEE_MAX_SLOTS][SLOTTEE_RUNTIME_STACK_WORDS]
    __attribute__((aligned(RISCV_PAGE_SIZE)));
static uintptr_t slottee_user_entry_point;
static struct slottee_lt_entry slottee_lt_entries[SLOTTEE_MAX_SLOTS];
static struct slottee_slot_policy_entry
    slottee_slot_policy_entries[SLOTTEE_MAX_SLOTS];
static volatile int slottee_slot_policy_lock;
static volatile int slottee_user_memory_lock;
static volatile int slottee_lt_scheduler_lock;
static struct slottee_user_lt_queue slottee_user_runnable_queue;
static struct slottee_user_lt_queue slottee_user_wait_queue;
static uintptr_t slottee_user_scheduler_ticket;
static uintptr_t slottee_user_scheduler_duplicate_rejects;
static uintptr_t slottee_global_wait_user_ptr;
static uintptr_t slottee_global_wait_target;
static uintptr_t slottee_global_wait_op;
static uintptr_t slottee_global_wait_block_count;
static uintptr_t slottee_global_wait_wakeup_count;
static uintptr_t slottee_global_notify_miss_count;

/*
 * OS-level preemptive timer scheduler state (--enter-slot-preempt-sched).
 * One host-entered LT_USER_OCALL slot acts as the scheduler thread; it bootstraps
 * a set of co-resident in-runtime worker LTs that the timer ISR round-robins by
 * rewriting the trap frame, entirely inside the enclave (no host-mediated resume).
 */
static volatile int slottee_preempt_sched_active;
static uintptr_t slottee_preempt_worker_count;
static uintptr_t slottee_preempt_completed;
static uintptr_t slottee_preempt_switches;
static uintptr_t slottee_preempt_ticks;
static uintptr_t slottee_preempt_host_yields;
static uintptr_t slottee_preempt_exit_switches;
static uintptr_t slottee_preempt_current_slot;
static uintptr_t slottee_preempt_worker_slots[SLOTTEE_MAX_SLOTS];
static struct encl_ctx slottee_preempt_scheduler_ctx;
static int slottee_preempt_scheduler_ctx_valid;

static void
slottee_slot_policy_lock_acquire(void)
{
  while (__sync_lock_test_and_set(&slottee_slot_policy_lock, 1))
    __asm__ volatile("nop");
  __sync_synchronize();
}

static void
slottee_slot_policy_lock_release(void)
{
  __sync_synchronize();
  __sync_lock_release(&slottee_slot_policy_lock);
}

static void
slottee_user_memory_lock_acquire(void)
{
  while (__sync_lock_test_and_set(&slottee_user_memory_lock, 1))
    __asm__ volatile("nop");
  __sync_synchronize();
}

static void
slottee_user_memory_lock_release(void)
{
  __sync_synchronize();
  __sync_lock_release(&slottee_user_memory_lock);
}

static void
slottee_lt_scheduler_lock_acquire(void)
{
  while (__sync_lock_test_and_set(&slottee_lt_scheduler_lock, 1))
    __asm__ volatile("nop");
  __sync_synchronize();
}

static void
slottee_lt_scheduler_lock_release(void)
{
  __sync_synchronize();
  __sync_lock_release(&slottee_lt_scheduler_lock);
}

static uintptr_t*
slottee_user_lt_queue_member(
    struct slottee_active_user_context* user,
    enum slottee_user_lt_queue_kind kind)
{
  if (!user)
    return 0;
  if (kind == SLOTTEE_USER_LT_QUEUE_RUNNABLE)
    return &user->in_runnable_queue;
  if (kind == SLOTTEE_USER_LT_QUEUE_WAIT)
    return &user->in_wait_queue;
  return 0;
}

static int
slottee_user_lt_queue_enqueue(struct slottee_user_lt_queue* queue,
    enum slottee_user_lt_queue_kind kind,
    struct slottee_active_user_context* user)
{
  uintptr_t* member;

  if (!queue || !user || user->slot_id == 0 ||
      user->slot_id >= SLOTTEE_MAX_SLOTS || queue->count >= SLOTTEE_MAX_SLOTS)
    return 0;

  member = slottee_user_lt_queue_member(user, kind);
  if (!member || *member) {
    slottee_user_scheduler_duplicate_rejects++;
    return 0;
  }

  queue->entries[queue->tail] = user->slot_id;
  queue->tail = (queue->tail + 1) % SLOTTEE_MAX_SLOTS;
  queue->count++;
  *member = 1;
  return 1;
}

static struct slottee_active_user_context*
slottee_user_lt_queue_dequeue(struct slottee_user_lt_queue* queue,
    enum slottee_user_lt_queue_kind kind)
{
  uintptr_t slot_id;
  uintptr_t* member;
  struct slottee_active_user_context* user;

  if (!queue || queue->count == 0)
    return 0;

  slot_id = queue->entries[queue->head];
  queue->head = (queue->head + 1) % SLOTTEE_MAX_SLOTS;
  queue->count--;
  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return 0;

  user = &slottee_active_users[slot_id];
  member = slottee_user_lt_queue_member(user, kind);
  if (!member || !*member)
    return 0;

  *member = 0;
  return user;
}

static int
slottee_user_lt_queue_remove(struct slottee_user_lt_queue* queue,
    enum slottee_user_lt_queue_kind kind,
    struct slottee_active_user_context* target)
{
  uintptr_t pending[SLOTTEE_MAX_SLOTS];
  uintptr_t pending_count = 0;
  int removed = 0;

  if (!queue || !target)
    return 0;

  while (queue->count) {
    struct slottee_active_user_context* user =
        slottee_user_lt_queue_dequeue(queue, kind);

    if (!user)
      continue;
    if (user == target) {
      removed = 1;
      continue;
    }
    if (pending_count < SLOTTEE_MAX_SLOTS)
      pending[pending_count++] = user->slot_id;
  }

  for (uintptr_t index = 0; index < pending_count; index++)
    (void)slottee_user_lt_queue_enqueue(
        queue, kind, &slottee_active_users[pending[index]]);

  return removed;
}

static void
slottee_user_lt_set_state(
    struct slottee_active_user_context* user,
    enum slottee_user_lt_state state)
{
  if (user)
    user->scheduler_state = state;
}

static int
slottee_wait_condition_ready(uintptr_t user_ptr, uintptr_t target, uintptr_t op)
{
  long value = 0;

  if (!user_ptr || copy_from_user(&value, (void*)user_ptr, sizeof(value)))
    return -1;

  if (op == SLOTTEE_LT_WAIT_OP_EQ)
    return value == (long)target;
  if (op == SLOTTEE_LT_WAIT_OP_GE)
    return value >= (long)target;

  return -1;
}

static void
slottee_user_lt_clear_wait(struct slottee_active_user_context* user)
{
  if (!user)
    return;

  user->wait_user_ptr = 0;
  user->wait_target = 0;
  user->wait_op = 0;
}

static void
slottee_user_lt_save_frame(
    struct slottee_active_user_context* user, const struct encl_ctx* ctx)
{
  if (!user || !ctx)
    return;

  user->saved_ctx = *ctx;
  user->saved_ctx_valid = 1;
}

static void
slottee_user_lt_record_dispatch(struct slottee_active_user_context* user)
{
  if (!user)
    return;

  slottee_user_scheduler_ticket++;
  user->fairness_ticket = slottee_user_scheduler_ticket;
  user->dispatch_count++;
}

static uintptr_t
slottee_lt_register_wait(struct slottee_active_user_context* user,
    struct encl_ctx* ctx, uintptr_t user_ptr, uintptr_t target, uintptr_t op)
{
  int ready;

  slottee_lt_scheduler_lock_acquire();
  ready = slottee_wait_condition_ready(user_ptr, target, op);
  if (ready < 0) {
    slottee_lt_scheduler_lock_release();
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (ready > 0) {
    slottee_lt_scheduler_lock_release();
    return SLOTTEE_LT_WAIT_RESULT_READY;
  }

  if (!user) {
    slottee_global_wait_user_ptr = user_ptr;
    slottee_global_wait_target = target;
    slottee_global_wait_op = op;
    slottee_global_wait_block_count++;
    slottee_lt_scheduler_lock_release();
    return SLOTTEE_LT_WAIT_RESULT_BLOCKED;
  }

  user->wait_user_ptr = user_ptr;
  user->wait_target = target;
  user->wait_op = op;
  slottee_user_lt_save_frame(user, ctx);
  slottee_user_lt_set_state(user, SLOTTEE_USER_LT_WAITING);
  if (!slottee_user_lt_queue_enqueue(&slottee_user_wait_queue,
          SLOTTEE_USER_LT_QUEUE_WAIT, user)) {
    slottee_user_lt_clear_wait(user);
    slottee_user_lt_set_state(user, SLOTTEE_USER_LT_RUNNING);
    slottee_lt_scheduler_lock_release();
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
  user->wait_block_count++;
  user->timer_wait_stop_count++;
  slottee_lt_scheduler_lock_release();
  return SLOTTEE_LT_WAIT_RESULT_BLOCKED;
}

static uintptr_t
slottee_user_lt_promote_waiters(uintptr_t user_ptr)
{
  uintptr_t pending[SLOTTEE_MAX_SLOTS];
  uintptr_t pending_count = 0;
  uintptr_t wakes = 0;

  slottee_lt_scheduler_lock_acquire();
  while (slottee_user_wait_queue.count) {
    struct slottee_active_user_context* user =
        slottee_user_lt_queue_dequeue(&slottee_user_wait_queue,
            SLOTTEE_USER_LT_QUEUE_WAIT);

    if (!user)
      continue;
    if (user->wait_user_ptr == user_ptr &&
        slottee_wait_condition_ready(user->wait_user_ptr,
            user->wait_target, user->wait_op) > 0) {
      if (slottee_user_lt_queue_enqueue(&slottee_user_runnable_queue,
              SLOTTEE_USER_LT_QUEUE_RUNNABLE, user)) {
        slottee_user_lt_set_state(user, SLOTTEE_USER_LT_WOKEN);
        user->wait_wakeup_count++;
        slottee_user_lt_clear_wait(user);
        wakes++;
      } else if (pending_count < SLOTTEE_MAX_SLOTS) {
        pending[pending_count++] = user->slot_id;
      }
    } else if (pending_count < SLOTTEE_MAX_SLOTS) {
      pending[pending_count++] = user->slot_id;
    }
  }

  for (uintptr_t index = 0; index < pending_count; index++)
    (void)slottee_user_lt_queue_enqueue(&slottee_user_wait_queue,
        SLOTTEE_USER_LT_QUEUE_WAIT, &slottee_active_users[pending[index]]);
  slottee_lt_scheduler_lock_release();

  return wakes;
}

static uintptr_t
slottee_global_wait_promote(uintptr_t user_ptr)
{
  uintptr_t wakes = 0;

  slottee_lt_scheduler_lock_acquire();
  if (slottee_global_wait_user_ptr == user_ptr &&
      slottee_wait_condition_ready(slottee_global_wait_user_ptr,
          slottee_global_wait_target, slottee_global_wait_op) > 0) {
    slottee_global_wait_wakeup_count++;
    slottee_global_wait_user_ptr = 0;
    slottee_global_wait_target = 0;
    slottee_global_wait_op = 0;
    wakes++;
  }
  slottee_lt_scheduler_lock_release();

  return wakes;
}

static void
slottee_user_lt_preempt_current(
    struct slottee_active_user_context* user, struct encl_ctx* ctx)
{
  struct slottee_active_user_context* dispatched = 0;

  slottee_lt_scheduler_lock_acquire();
  slottee_user_lt_save_frame(user, ctx);
  slottee_user_lt_set_state(user, SLOTTEE_USER_LT_YIELDED);
  user->preempt_yield_count++;
  if (!user->in_runnable_queue)
    (void)slottee_user_lt_queue_enqueue(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, user);

  dispatched = slottee_user_lt_queue_dequeue(&slottee_user_runnable_queue,
      SLOTTEE_USER_LT_QUEUE_RUNNABLE);
  if (dispatched == user && user->saved_ctx_valid) {
    slottee_user_lt_set_state(user, SLOTTEE_USER_LT_RUNNING);
    user->preempt_dispatch_count++;
    slottee_user_lt_record_dispatch(user);
  } else if (dispatched) {
    (void)slottee_user_lt_queue_enqueue(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, dispatched);
  }
  slottee_lt_scheduler_lock_release();
}

static void
slottee_user_lt_resume_after_wait(struct slottee_active_user_context* user)
{
  if (!user)
    return;

  slottee_lt_scheduler_lock_acquire();
  if (user->in_runnable_queue)
    (void)slottee_user_lt_queue_remove(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, user);
  if (user->in_wait_queue)
    (void)slottee_user_lt_queue_remove(&slottee_user_wait_queue,
        SLOTTEE_USER_LT_QUEUE_WAIT, user);
  slottee_user_lt_clear_wait(user);
  slottee_user_lt_set_state(user, SLOTTEE_USER_LT_RUNNING);
  slottee_user_lt_record_dispatch(user);
  slottee_lt_scheduler_lock_release();
}

static void
slottee_user_lt_cleanup_queues(struct slottee_active_user_context* user)
{
  if (!user)
    return;

  slottee_lt_scheduler_lock_acquire();
  if (user->in_runnable_queue)
    (void)slottee_user_lt_queue_remove(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, user);
  if (user->in_wait_queue)
    (void)slottee_user_lt_queue_remove(&slottee_user_wait_queue,
        SLOTTEE_USER_LT_QUEUE_WAIT, user);
  slottee_user_lt_clear_wait(user);
  slottee_user_lt_set_state(user, SLOTTEE_USER_LT_EXITED);
  slottee_lt_scheduler_lock_release();
}

void
slottee_set_user_entry(uintptr_t entry)
{
  slottee_user_entry_point = entry;
}

static int
slottee_user_addr_in_range(uintptr_t addr, uintptr_t base, uintptr_t size)
{
  return addr >= base && addr < (base + size);
}

static int
slottee_user_ranges_overlap(
    uintptr_t left_base, uintptr_t left_size, uintptr_t right_base, uintptr_t right_size)
{
  return left_base < (right_base + right_size) &&
      right_base < (left_base + left_size);
}

static uintptr_t
slottee_user_stack_base(uintptr_t slot_id)
{
  return EYRIE_USER_STACK_END - ((slot_id + 1) * SLOTTEE_USER_SLOT_STRIDE);
}

static uintptr_t
slottee_user_tls_base(uintptr_t slot_id)
{
  return slottee_user_stack_base(slot_id) + SLOTTEE_USER_STACK_SIZE +
      SLOTTEE_USER_REGION_GAP;
}

static struct slottee_active_user_context*
slottee_active_user_for_slot(uintptr_t slot_id)
{
  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return NULL;

  return &slottee_active_users[slot_id];
}

static uintptr_t
slottee_runtime_stack_top(uintptr_t slot_id)
{
  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return 0;

  return (uintptr_t)&slottee_runtime_stacks[slot_id][SLOTTEE_RUNTIME_STACK_WORDS];
}

static int
slottee_user_entry_addr_ok(uintptr_t fn)
{
  return fn && fn < EYRIE_USER_STACK_END;
}

static int
slottee_mode_is_user_ocall(uintptr_t mode)
{
  return mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL ||
      mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_REVOKE_FAULT;
}

static int
slottee_user_ranges_isolated(
    const struct slottee_active_user_context* user, uintptr_t slot_id)
{
  uintptr_t slot_stack_base;
  uintptr_t slot_tls_base;
  uintptr_t other;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS ||
      !user || !user->user_alloc_ok)
    return 0;

  slot_stack_base = user->user_stack_base;
  slot_tls_base = user->user_tls_base;

  if (slottee_user_ranges_overlap(slot_stack_base, SLOTTEE_USER_STACK_SIZE,
          slot_tls_base, SLOTTEE_USER_TLS_SIZE))
    return 0;

  for (other = 1; other < SLOTTEE_MAX_SLOTS; other++) {
    uintptr_t other_stack_base;
    uintptr_t other_tls_base;

    if (other == slot_id)
      continue;

    other_stack_base = slottee_user_stack_base(other);
    other_tls_base = slottee_user_tls_base(other);
    if (slottee_user_ranges_overlap(slot_stack_base, SLOTTEE_USER_STACK_SIZE,
            other_stack_base, SLOTTEE_USER_STACK_SIZE) ||
        slottee_user_ranges_overlap(slot_stack_base, SLOTTEE_USER_STACK_SIZE,
            other_tls_base, SLOTTEE_USER_TLS_SIZE) ||
        slottee_user_ranges_overlap(slot_tls_base, SLOTTEE_USER_TLS_SIZE,
            other_stack_base, SLOTTEE_USER_STACK_SIZE) ||
        slottee_user_ranges_overlap(slot_tls_base, SLOTTEE_USER_TLS_SIZE,
            other_tls_base, SLOTTEE_USER_TLS_SIZE))
      return 0;
  }

  return 1;
}

static void
slottee_record_trap_frame(
    struct slottee_active_user_context* user, struct encl_ctx* ctx,
    uintptr_t syscall_id)
{
  if (!user || !user->active || !ctx)
    return;

  user->last_trap_syscall = syscall_id;
  user->last_trap_scause = ctx->scause;
  user->last_trap_sepc = ctx->regs.sepc;
  user->last_trap_stval = ctx->sbadaddr;
  user->last_trap_user_sp = ctx->regs.sp;
  user->last_trap_user_tp = ctx->regs.tp;
}

static int
slottee_frame_matches_user(
    const struct slottee_active_user_context* user, const struct encl_ctx* ctx)
{
  if (!user || !ctx || !user->active)
    return 0;

  if (!slottee_mode_is_user_ocall(user->mode) || !user->user_alloc_ok)
    return 0;

  return slottee_user_addr_in_range(ctx->regs.sp, user->user_stack_base,
             SLOTTEE_USER_STACK_SIZE) ||
      slottee_user_addr_in_range(ctx->regs.tp, user->user_tls_base,
          user->user_tls_size) ||
      ctx->regs.tp == user->user_tls_base;
}

static struct slottee_active_user_context*
slottee_active_user_for_frame(struct encl_ctx* ctx)
{
  uintptr_t slot;

  if (!ctx)
    return NULL;

  for (slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    struct slottee_active_user_context* user = &slottee_active_users[slot];

    if (!user->active)
      continue;
    if (slottee_frame_matches_user(user, ctx))
      return user;
  }

  return NULL;
}

static int
slottee_prepare_user_memory(struct slottee_active_user_context* user, uintptr_t slot_id)
{
  uintptr_t stack_base = slottee_user_stack_base(slot_id);
  uintptr_t tls_base = slottee_user_tls_base(slot_id);
  size_t stack_count;
  size_t tls_count;

  if (!user)
    return 0;

  slottee_user_memory_lock_acquire();
  if (user->user_alloc_ok &&
      user->user_stack_base == stack_base &&
      user->user_tls_base == tls_base) {
    slottee_user_memory_lock_release();
    return 1;
  }

  stack_count = alloc_pages(vpn(stack_base), SLOTTEE_USER_STACK_PAGES,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);
  tls_count = alloc_pages(vpn(tls_base), SLOTTEE_USER_TLS_PAGES,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

  user->user_stack_base = stack_base;
  user->user_stack_top = stack_base + SLOTTEE_USER_STACK_SIZE;
  user->user_tls_base = tls_base;
  user->user_tls_size = SLOTTEE_USER_TLS_SIZE;
  user->user_stack_pages = stack_count;
  user->user_tls_pages = tls_count;
  user->user_alloc_ok =
      stack_count == SLOTTEE_USER_STACK_PAGES &&
      tls_count == SLOTTEE_USER_TLS_PAGES;

  printf("[slottee] lt_user_mem slot=%lu stack=0x%lx-0x%lx tls=0x%lx-0x%lx pages=%lu/%lu ok=%lu\r\n",
      slot_id, user->user_stack_base, user->user_stack_top,
      user->user_tls_base, user->user_tls_base + user->user_tls_size,
      user->user_stack_pages, user->user_tls_pages, user->user_alloc_ok);

  slottee_user_memory_lock_release();
  return user->user_alloc_ok;
}

static struct slottee_active_user_context*
slottee_activate_user_context(uintptr_t slot_id, uintptr_t lease_id, uintptr_t mode)
{
  struct slottee_active_user_context* user =
      slottee_active_user_for_slot(slot_id);

  if (!user)
    return NULL;

  user->active = 1;
  user->slot_id = slot_id;
  user->lease_id = lease_id;
  user->mode = mode;
  user->enter_count++;
  user->hart_id = sbi_current_hart();
  user->last_trap_syscall = 0;
  user->last_trap_scause = 0;
  user->last_trap_sepc = 0;
  user->last_trap_stval = 0;
  user->last_trap_user_sp = 0;
  user->last_trap_user_tp = 0;
  user->syscall_trap_count = 0;
  user->ocall_trap_count = 0;
  user->ocall_resume_count = 0;
  user->exit_trap_count = 0;
  user->fault_trap_count = 0;
  user->revoke_on_fault =
      mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_REVOKE_FAULT;
  user->lt_entry_active = slottee_lt_entries[slot_id].registered;
  user->entry_tls_base = 0;
  user->tls_entry_ok = 0;
  user->tls_exit_ok = 0;
  user->tls_exit_mismatch = 0;
  user->wait_user_ptr = 0;
  user->wait_target = 0;
  user->wait_op = 0;
  user->wait_block_count = 0;
  user->wait_wakeup_count = 0;
  user->wait_notify_miss_count = 0;
  user->timer_wait_stop_count = 0;
  user->preempt_count = 0;
  user->preempt_yield_count = 0;
  user->preempt_dispatch_count = 0;
  user->preempt_worker = 0;
  user->dispatch_count = 0;
  user->in_runnable_queue = 0;
  user->in_wait_queue = 0;
  user->saved_ctx_valid = 0;
  user->fairness_ticket = 0;
  user->scheduler_state = SLOTTEE_USER_LT_READY;
  memset(&user->saved_ctx, 0, sizeof(user->saved_ctx));
  user->user_stack_entry_ok = 0;
  user->user_stack_exit_ok = 0;
  user->tls_resume_ok = 0;

  if (slottee_mode_is_user_ocall(mode)) {
    slottee_prepare_user_memory(user, slot_id);
    slottee_lt_scheduler_lock_acquire();
    slottee_user_lt_set_state(user, SLOTTEE_USER_LT_RUNNING);
    slottee_user_lt_record_dispatch(user);
    slottee_lt_scheduler_lock_release();
  }

  return user;
}

static uintptr_t
slottee_active_user_prepare_user_entry(
    struct slottee_active_user_context* user, uintptr_t entry, uintptr_t arg,
    uintptr_t* user_sp)
{
  if (!user || !user->active || !slottee_mode_is_user_ocall(user->mode) ||
      !user->user_alloc_ok || !entry)
    return 0;

  printf("[slottee] lt_user_entry slot=%lu sepc=0x%lx arg=0x%lx sscratch=0x%lx tp=0x%lx lt=%lu\r\n",
      user->slot_id, entry, arg, user->user_stack_top, user->user_tls_base,
      user->lt_entry_active);

  user->entry_tls_base = user->user_tls_base;
  user->tls_entry_ok = slottee_user_addr_in_range(user->entry_tls_base,
      user->user_tls_base, user->user_tls_size);
  if (user_sp)
    *user_sp = user->user_stack_top;
  user->user_stack_entry_ok = user_sp &&
      *user_sp == user->user_stack_top &&
      slottee_user_addr_in_range(*user_sp - 1, user->user_stack_base,
          SLOTTEE_USER_STACK_SIZE);

  __asm__ volatile("csrw sepc, %0" :: "r"(entry));
  __asm__ volatile("mv tp, %0" :: "r"(user->user_tls_base) : "memory");

  return slottee_runtime_stack_top(user->slot_id);
}

void
slottee_active_user_record_syscall(struct encl_ctx* ctx, uintptr_t syscall_id)
{
  struct slottee_active_user_context* user = slottee_active_user_for_frame(ctx);

  if (!user)
    return;

  slottee_record_trap_frame(user, ctx, syscall_id);
  user->syscall_trap_count++;
}

void
slottee_active_user_record_ocall(struct encl_ctx* ctx)
{
  struct slottee_active_user_context* user = slottee_active_user_for_frame(ctx);

  if (!user || !slottee_mode_is_user_ocall(user->mode))
    return;

  slottee_record_trap_frame(user, ctx, RUNTIME_SYSCALL_OCALL);
  user->ocall_trap_count++;
}

void
slottee_active_user_record_ocall_resume(struct encl_ctx* ctx, uintptr_t value)
{
  struct slottee_active_user_context* user = slottee_active_user_for_frame(ctx);

  if (!user || !slottee_mode_is_user_ocall(user->mode) || value != 0)
    return;

  user->ocall_resume_count++;
  user->tls_resume_ok += ctx->regs.tp == user->entry_tls_base ? 1 : 0;
}

/*
 * Bootstrap one in-runtime preemptive worker LT.  The worker is never entered by
 * the host: it lives entirely as an Eyrie-RT logical thread multiplexed on the
 * scheduler slot's SM thread.  Its initial register frame is cloned from the
 * scheduler's live frame (so it inherits the eapp gp and ambient supervisor
 * state) and then re-pointed at the worker entry: pc=fn, sp=own stack top,
 * tp=own TLS, a0=arg.  Each subsequent timer switch restores this saved_ctx.
 */
static void
slottee_preempt_init_worker(struct slottee_active_user_context* user,
    uintptr_t slot_id, uintptr_t lease_id, uintptr_t fn, uintptr_t arg,
    const struct encl_ctx* tmpl)
{
  user->active = 1;
  user->slot_id = slot_id;
  user->lease_id = lease_id;
  user->mode = SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL;
  user->enter_count++;
  user->hart_id = sbi_current_hart();
  user->preempt_worker = 1;
  user->last_trap_syscall = 0;
  user->last_trap_scause = 0;
  user->last_trap_sepc = 0;
  user->last_trap_stval = 0;
  user->last_trap_user_sp = 0;
  user->last_trap_user_tp = 0;
  user->syscall_trap_count = 0;
  user->ocall_trap_count = 0;
  user->ocall_resume_count = 0;
  user->exit_trap_count = 0;
  user->fault_trap_count = 0;
  user->revoke_on_fault = 0;
  user->lt_entry_active = 1;
  user->tls_exit_ok = 0;
  user->tls_exit_mismatch = 0;
  user->wait_user_ptr = 0;
  user->wait_target = 0;
  user->wait_op = 0;
  user->wait_block_count = 0;
  user->wait_wakeup_count = 0;
  user->wait_notify_miss_count = 0;
  user->timer_wait_stop_count = 0;
  user->preempt_count = 0;
  user->preempt_yield_count = 0;
  user->preempt_dispatch_count = 0;
  user->dispatch_count = 0;
  user->in_runnable_queue = 0;
  user->in_wait_queue = 0;
  user->fairness_ticket = 0;
  user->scheduler_state = SLOTTEE_USER_LT_READY;
  user->user_stack_exit_ok = 0;
  user->tls_resume_ok = 0;

  slottee_prepare_user_memory(user, slot_id);

  user->entry_tls_base = user->user_tls_base;
  user->tls_entry_ok = slottee_user_addr_in_range(user->entry_tls_base,
      user->user_tls_base, user->user_tls_size);
  user->user_stack_entry_ok = user->user_alloc_ok;

  user->saved_ctx = *tmpl;
  user->saved_ctx.regs.sepc = fn;
  user->saved_ctx.regs.sp = user->user_stack_top;
  user->saved_ctx.regs.tp = user->user_tls_base;
  user->saved_ctx.regs.a0 = arg;
  user->saved_ctx.regs.ra = 0;
  user->saved_ctx_valid = user->user_alloc_ok;
}

static struct slottee_active_user_context*
slottee_preempt_pick_next(void)
{
  return slottee_user_lt_queue_dequeue(&slottee_user_runnable_queue,
      SLOTTEE_USER_LT_QUEUE_RUNNABLE);
}

/*
 * Timer-driven context switch for the OS-level preemptive scheduler.  Called
 * from the redirected S-mode timer ISR with the preempted worker's full frame in
 * *ctx.  Saving *ctx into the current worker and copying the next runnable
 * worker's saved_ctx back into *ctx makes return_to_encl sret into a *different*
 * LT — a real preemptive context switch with no host-mediated resume.
 */
static uintptr_t
slottee_preempt_timer_switch(struct slottee_active_user_context* cur,
    struct encl_ctx* ctx)
{
  struct slottee_active_user_context* next;

  slottee_lt_scheduler_lock_acquire();
  slottee_preempt_ticks++;

  slottee_user_lt_save_frame(cur, ctx);
  cur->scheduler_state = SLOTTEE_USER_LT_YIELDED;
  if (!cur->in_runnable_queue)
    (void)slottee_user_lt_queue_enqueue(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, cur);

  next = slottee_preempt_pick_next();
  if (next && next != cur && next->saved_ctx_valid) {
    cur->preempt_count++;
    cur->preempt_yield_count++;
    next->scheduler_state = SLOTTEE_USER_LT_RUNNING;
    next->preempt_dispatch_count++;
    slottee_user_lt_record_dispatch(next);
    slottee_preempt_current_slot = next->slot_id;
    slottee_preempt_switches++;
    *ctx = next->saved_ctx;
  } else if (next) {
    /* Only one runnable worker remains: keep it on-core, no real swap. */
    next->scheduler_state = SLOTTEE_USER_LT_RUNNING;
    slottee_preempt_current_slot = next->slot_id;
  }
  slottee_lt_scheduler_lock_release();
  return 1;
}

/*
 * Preempt-aware worker exit.  Instead of tearing down the enclave run, retire the
 * exiting worker and switch into the next runnable worker; when none remain,
 * restore the saved scheduler-thread frame so PREEMPT_RUN returns in-place.
 */
static int
slottee_preempt_worker_exit(struct slottee_active_user_context* user,
    struct encl_ctx* ctx, uintptr_t value)
{
  struct slottee_active_user_context* next;

  slottee_lt_scheduler_lock_acquire();

  slottee_record_trap_frame(user, ctx, RUNTIME_SYSCALL_EXIT);
  user->exit_trap_count++;
  user->user_stack_exit_ok = slottee_user_addr_in_range(user->last_trap_user_sp,
      user->user_stack_base, SLOTTEE_USER_STACK_SIZE);
  user->tls_exit_ok = user->last_trap_user_tp == user->entry_tls_base;
  user->tls_exit_mismatch += user->tls_exit_ok ? 0 : 1;
  user->scheduler_state = SLOTTEE_USER_LT_EXITED;
  user->preempt_worker = 0;
  if (user->in_runnable_queue)
    (void)slottee_user_lt_queue_remove(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, user);
  user->active = 0;
  user->saved_ctx_valid = 0;
  slottee_preempt_completed++;
  (void)value;

  next = slottee_preempt_pick_next();
  if (next && next->saved_ctx_valid) {
    slottee_preempt_exit_switches++;
    next->scheduler_state = SLOTTEE_USER_LT_RUNNING;
    next->preempt_dispatch_count++;
    slottee_user_lt_record_dispatch(next);
    slottee_preempt_current_slot = next->slot_id;
    *ctx = next->saved_ctx;
    slottee_lt_scheduler_lock_release();
    return 1;
  }

  slottee_preempt_sched_active = 0;
  slottee_preempt_current_slot = 0;
  if (slottee_preempt_scheduler_ctx_valid) {
    *ctx = slottee_preempt_scheduler_ctx;
    ctx->regs.a0 = slottee_preempt_completed;
    slottee_preempt_scheduler_ctx_valid = 0;
  }
  slottee_lt_scheduler_lock_release();
  printf("[slottee] preempt_all_done completed=%lu switches=%lu exit_switches=%lu ticks=%lu\r\n",
      slottee_preempt_completed, slottee_preempt_switches,
      slottee_preempt_exit_switches, slottee_preempt_ticks);
  return 1;
}

uintptr_t
slottee_lt_timer_preempt(struct encl_ctx* ctx)
{
  struct slottee_active_user_context* user = slottee_active_user_for_frame(ctx);

  if (!ctx || (ctx->sstatus & SR_SPP))
    return 0;

  /*
   * OS-level preemptive path: when the in-runtime scheduler is active and the
   * preempted frame belongs to one of its workers, switch LTs inside the enclave
   * instead of stopping out to the host.
   */
  if (slottee_preempt_sched_active && user && user->preempt_worker) {
    slottee_record_trap_frame(user, ctx, STOP_TIMER_INTERRUPT);
    return slottee_preempt_timer_switch(user, ctx);
  }

  if (!user || !slottee_mode_is_user_ocall(user->mode))
    return 0;

  slottee_record_trap_frame(user, ctx, STOP_TIMER_INTERRUPT);
  user->preempt_count++;
  slottee_user_lt_preempt_current(user, ctx);
  (void)sbi_stop_enclave(STOP_TIMER_INTERRUPT);
  return 1;
}

static int
slottee_active_user_ocall_exit_ok(
    const struct slottee_active_user_context* user, uintptr_t value)
{
  if (!user || !slottee_mode_is_user_ocall(user->mode))
    return 1;

  if (user->lt_entry_active)
    return user->user_alloc_ok &&
        user->exit_trap_count == 1 &&
        user->tls_entry_ok &&
        slottee_user_addr_in_range(user->last_trap_user_sp,
            user->user_stack_base, SLOTTEE_USER_STACK_SIZE);

  return value == SLOTTEE_LT_USER_OCALL_MAGIC &&
      user->user_alloc_ok &&
      slottee_user_ranges_isolated(user, user->slot_id) &&
      user->ocall_trap_count == 1 &&
      user->ocall_resume_count == 1 &&
      user->exit_trap_count == 1 &&
      slottee_user_addr_in_range(user->last_trap_user_sp,
          user->user_stack_base, SLOTTEE_USER_STACK_SIZE) &&
      user->last_trap_user_tp == user->user_tls_base;
}

int
slottee_active_user_exit(struct encl_ctx* ctx, uintptr_t value)
{
  struct slottee_active_user_context* user = slottee_active_user_for_frame(ctx);
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t status;

  if (!user ||
      (user->mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER &&
       !slottee_mode_is_user_ocall(user->mode)))
    return 0;

  /* In-runtime preemptive worker exit retires the LT and switches in place. */
  if (slottee_preempt_sched_active && user->preempt_worker)
    return slottee_preempt_worker_exit(user, ctx, value);

  slottee_record_trap_frame(user, ctx, RUNTIME_SYSCALL_EXIT);
  user->exit_trap_count++;
  user->tls_exit_ok = user->last_trap_user_tp == user->entry_tls_base;
  user->tls_exit_mismatch += user->tls_exit_ok ? 0 : 1;
  user->user_stack_exit_ok = slottee_user_addr_in_range(user->last_trap_user_sp,
      user->user_stack_base, SLOTTEE_USER_STACK_SIZE);
  if (!slottee_active_user_ocall_exit_ok(user, value))
    value = SLOTTEE_LT_USER_ILLEGAL_MAGIC;

  if (slottee_mode_is_user_ocall(user->mode)) {
    printf("[slottee] lt_user_exit slot=%lu value=%lu syscalls=%lu ocalls=%lu resumes=%lu exits=%lu faults=%lu sp=0x%lx tp=0x%lx stack_entry=%lu stack_exit=%lu tls_entry=%lu tls_exit=%lu tls_resume=%lu tls_mismatch=%lu wait_blocks=%lu wait_wakeups=%lu timer_stops=%lu preempts=%lu notify_misses=%lu\r\n",
        user->slot_id, value, user->syscall_trap_count,
        user->ocall_trap_count, user->ocall_resume_count,
        user->exit_trap_count, user->fault_trap_count,
        user->last_trap_user_sp, user->last_trap_user_tp,
        user->user_stack_entry_ok, user->user_stack_exit_ok,
        user->tls_entry_ok, user->tls_exit_ok, user->tls_resume_ok,
        user->tls_exit_mismatch, user->wait_block_count, user->wait_wakeup_count,
        user->timer_wait_stop_count,
        user->preempt_count,
        user->wait_notify_miss_count);
  }

  slot_id = user->slot_id;
  lease_id = user->lease_id;
  slottee_user_lt_cleanup_queues(user);
  user->active = 0;
  status = sbi_exit_slot(slot_id, lease_id, SLOTTEE_SLOT_EXIT_NORMAL, value);

  while (1) {
    sbi_exit_enclave(status ? status : value);
  }
}

int
slottee_active_user_fault_exit(struct encl_ctx* ctx, uintptr_t value)
{
  struct slottee_active_user_context* user = slottee_active_user_for_frame(ctx);
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t exit_reason;
  uintptr_t status;

  if (!user)
    return 0;

  slottee_record_trap_frame(user, ctx, 0);
  user->fault_trap_count++;

  printf("[slottee] lt_user_fault slot=%lu value=%lu scause=0x%lx sepc=0x%lx stval=0x%lx sp=0x%lx tp=0x%lx\r\n",
      user->slot_id, value, user->last_trap_scause,
      user->last_trap_sepc, user->last_trap_stval,
      user->last_trap_user_sp, user->last_trap_user_tp);

  slot_id = user->slot_id;
  lease_id = user->lease_id;
  exit_reason = user->revoke_on_fault ?
      SLOTTEE_SLOT_EXIT_REVOKE : SLOTTEE_SLOT_EXIT_NORMAL;
  slottee_user_lt_cleanup_queues(user);
  user->active = 0;
  status = sbi_exit_slot(slot_id, lease_id, exit_reason, value);

  while (1) {
    sbi_exit_enclave(status ? status : value);
  }
}

uintptr_t
slottee_slot_trampoline_with_arg(
    uintptr_t slot_token, uintptr_t* user_arg, uintptr_t* user_sp)
{
  uintptr_t slot_id = SLOTTEE_SLOT_TOKEN_SLOT_ID(slot_token);
  uintptr_t slot_mode = SLOTTEE_SLOT_TOKEN_MODE(slot_token);
  uintptr_t lease_id = SLOTTEE_SLOT_TOKEN_LEASE_ID(slot_token);
  uintptr_t value = SLOTTEE_SLOT_MAGIC;
  uintptr_t entry = slottee_user_entry_point;
  uintptr_t arg = 0;
  struct slottee_active_user_context* user;
  struct slottee_lt_entry* lt_entry = NULL;

  if (slot_id < SLOTTEE_MAX_SLOTS)
    lt_entry = &slottee_lt_entries[slot_id];

  if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_SCHED) {
    value = slottee_lt_scheduler_run(slot_id, lease_id);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_CONTEXT) {
    value = slottee_lt_context_run(slot_id, lease_id);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_YIELD) {
    value = slottee_lt_yield_run(slot_id, lease_id);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_BIND) {
    value = slottee_lt_bind_run(slot_id, lease_id);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_TRAP_SAFE) {
    value = slottee_lt_trap_safe_run(slot_id, lease_id);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_ECALL) {
    value = slottee_lt_ecall_run(slot_id, lease_id);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER) {
    slottee_activate_user_context(slot_id, lease_id, slot_mode);
    return 0;
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL) {
    if (lt_entry && lt_entry->registered) {
      entry = lt_entry->fn;
      arg = lt_entry->arg;
    }
    user = slottee_activate_user_context(slot_id, lease_id, slot_mode);
    if (user_arg)
      *user_arg = arg;
    return slottee_active_user_prepare_user_entry(user, entry, arg, user_sp);
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_REVOKE_FAULT) {
    user = slottee_activate_user_context(slot_id, lease_id, slot_mode);
    if (user_arg)
      *user_arg = 0;
    return slottee_active_user_prepare_user_entry(
        user, slottee_user_entry_point, 0, user_sp);
  }

  sbi_exit_slot(slot_id, lease_id, SLOTTEE_SLOT_EXIT_NORMAL, value);

  while (1) {
    sbi_exit_enclave(value);
  }
}

uintptr_t
slottee_slot_trampoline(uintptr_t slot_token)
{
  return slottee_slot_trampoline_with_arg(slot_token, 0, 0);
}

static uintptr_t
slottee_lt_export_cap(const struct slot_cap_t* cap)
{
  struct edge_call* edge_call = (struct edge_call*)shared_buffer;
  uintptr_t buffer_data_start = edge_call_data_ptr();

  if (!cap || sizeof(*cap) > shared_buffer_size -
          (buffer_data_start - shared_buffer))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  edge_call->call_id = SLOTTEE_LT_SPAWN_OCALL_COPY_SLOT_CAP;
  memcpy((void*)buffer_data_start, cap, sizeof(*cap));

  if (edge_call_setup_call(edge_call, (void*)buffer_data_start,
          sizeof(*cap)) != 0)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (sbi_stop_enclave(STOP_EDGE_CALL_HOST) != 0)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (edge_call->return_data.call_status != CALL_STATUS_OK)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static uintptr_t
slottee_slot_policy_active_count(void)
{
  uintptr_t slot_id;
  uintptr_t active = 0;

  for (slot_id = 1; slot_id < SLOTTEE_MAX_SLOTS; slot_id++) {
    if (slottee_slot_policy_entries[slot_id].active)
      active++;
  }

  return active;
}

static uintptr_t
slottee_slot_policy_next_free_slot(void)
{
  uintptr_t slot_id;

  for (slot_id = 1; slot_id < SLOTTEE_MAX_SLOTS; slot_id++) {
    if (!slottee_slot_policy_entries[slot_id].active)
      return slot_id;
  }

  return 0;
}

uintptr_t
slottee_slot_request(uintptr_t policy_ptr)
{
  struct slottee_slot_policy policy = {0};
  uintptr_t max_concurrent;
  uintptr_t active_slots;
  uintptr_t slot_id;

  if (!policy_ptr ||
      copy_from_user(&policy, (void*)policy_ptr, sizeof(policy)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  max_concurrent = policy.max_concurrent ?
      policy.max_concurrent : SLOTTEE_MAX_CONCURRENT_DEFAULT;
  if (max_concurrent >= SLOTTEE_MAX_SLOTS)
    max_concurrent = SLOTTEE_MAX_SLOTS - 1;
  if (max_concurrent == 0)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  slottee_slot_policy_lock_acquire();
  active_slots = slottee_slot_policy_active_count();
  if (active_slots >= max_concurrent) {
    slottee_slot_policy_lock_release();
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }

  slot_id = slottee_slot_policy_next_free_slot();
  if (!slot_id) {
    slottee_slot_policy_lock_release();
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }

  slottee_slot_policy_entries[slot_id].active = 1;
  slottee_slot_policy_entries[slot_id].affinity_hint = policy.affinity_hint;
  slottee_slot_policy_entries[slot_id].priority = policy.priority;
  slottee_slot_policy_lock_release();
  return slot_id;
}

uintptr_t
slottee_slot_release(uintptr_t slot_id)
{
  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  slottee_slot_policy_lock_acquire();
  if (!slottee_slot_policy_entries[slot_id].active) {
    slottee_slot_policy_lock_release();
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  memset(&slottee_slot_policy_entries[slot_id], 0,
      sizeof(slottee_slot_policy_entries[slot_id]));
  slottee_slot_policy_lock_release();
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

uintptr_t
slottee_lt_spawn(uintptr_t slot_id, uintptr_t fn, uintptr_t arg)
{
  struct mint_slot_cap_req_t req;
  struct mint_slot_cap_resp_t resp;
  uintptr_t ret;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS ||
      !slottee_user_entry_addr_ok(fn))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  memset(&req, 0, sizeof(req));
  memset(&resp, 0, sizeof(resp));
  req.version = SLOTTEE_MINT_CAP_VERSION;
  req.slot_id = slot_id;
  req.cap_seq = SLOTTEE_DEFAULT_CAP_SEQ;
  req.rights = SLOTTEE_CAP_RIGHT_ENTER;
  req.max_lease_cycles = SLOTTEE_DEFAULT_MAX_LEASE_CYCLES;

  ret = sbi_mint_slot_cap((uintptr_t)&req, (uintptr_t)&resp);
  if (resp.status)
    ret = resp.status;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
    return ret;

  slottee_lt_entries[slot_id].slot_id = slot_id;
  slottee_lt_entries[slot_id].fn = fn;
  slottee_lt_entries[slot_id].arg = arg;
  __sync_synchronize();
  slottee_lt_entries[slot_id].registered = 1;

  ret = slottee_lt_export_cap(&resp.cap);
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    slottee_lt_entries[slot_id].registered = 0;
    return ret;
  }

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

uintptr_t
slottee_lt_wait_value(
    struct encl_ctx* ctx, uintptr_t user_ptr, uintptr_t target, uintptr_t op)
{
  struct slottee_active_user_context* user;
  uintptr_t wait_result;

  if (!user_ptr)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (op != SLOTTEE_LT_WAIT_OP_EQ && op != SLOTTEE_LT_WAIT_OP_GE)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  user = slottee_active_user_for_frame(ctx);
  wait_result = slottee_lt_register_wait(user, ctx, user_ptr, target, op);
  if (wait_result != SLOTTEE_LT_WAIT_RESULT_BLOCKED)
    return wait_result;

  /*
   * The stop SBI returns to this instruction only after the host resumes the
   * enclave.  Its a0 may contain the host resume status, so the wait primitive
   * treats that continuation as the observable "blocked once" result.
   */
  (void)sbi_stop_enclave(STOP_TIMER_INTERRUPT);
  if (user)
    slottee_user_lt_resume_after_wait(user);
  return SLOTTEE_LT_WAIT_RESULT_BLOCKED;
}

uintptr_t
slottee_lt_notify_value(struct encl_ctx* ctx, uintptr_t user_ptr)
{
  uintptr_t wakes = 0;
  struct slottee_active_user_context* notifier;

  if (!user_ptr)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  wakes += slottee_user_lt_promote_waiters(user_ptr);
  wakes += slottee_global_wait_promote(user_ptr);

  if (wakes)
    return SLOTTEE_LT_NOTIFY_RESULT_WOKE;

  notifier = slottee_active_user_for_frame(ctx);
  if (notifier)
    notifier->wait_notify_miss_count++;
  else
    slottee_global_notify_miss_count++;

  return SLOTTEE_LT_NOTIFY_RESULT_MISS;
}

uintptr_t
slottee_lt_collect_stats(struct encl_ctx* ctx, uintptr_t stats_ptr)
{
  struct slottee_lt_runtime_stats stats = {0};
  struct slottee_active_user_context* current_user =
      slottee_active_user_for_frame(ctx);
  uintptr_t slot;
  uintptr_t current_slot = 0;
  uintptr_t active_lt_count = 0;

  if (!stats_ptr)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  stats.wait_blocks = slottee_global_wait_block_count;
  stats.wait_wakeups = slottee_global_wait_wakeup_count;
  stats.notify_misses = slottee_global_notify_miss_count;
  stats.timer_wait_stops = slottee_global_wait_block_count;
  stats.fairness_min = (uintptr_t)-1;

  slottee_lt_scheduler_lock_acquire();
  stats.runnable_queue_depth = slottee_user_runnable_queue.count;
  stats.wait_queue_depth = slottee_user_wait_queue.count;
  stats.scheduler_duplicate_rejects =
      slottee_user_scheduler_duplicate_rejects;

  if (current_user)
    current_slot = current_user->slot_id;

  for (slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    struct slottee_active_user_context* user = &slottee_active_users[slot];

    stats.wait_blocks += user->wait_block_count;
    stats.wait_wakeups += user->wait_wakeup_count;
    stats.notify_misses += user->wait_notify_miss_count;
    stats.tls_entry_ok += user->tls_entry_ok;
    stats.tls_exit_ok += user->tls_exit_ok;
    stats.tls_exit_mismatch += user->tls_exit_mismatch;
    stats.user_context_entries += user->enter_count;
    stats.user_context_exits += user->exit_trap_count;
    stats.syscall_traps += user->syscall_trap_count;
    stats.ocall_traps += user->ocall_trap_count;
    stats.ocall_resumes += user->ocall_resume_count;
    stats.exit_traps += user->exit_trap_count;
    stats.fault_traps += user->fault_trap_count;
    stats.timer_wait_stops += user->timer_wait_stop_count;
    stats.preempt_count += user->preempt_count;
    stats.preempt_yields += user->preempt_yield_count;
    stats.preempt_dispatches += user->preempt_dispatch_count;
    if (user->in_runnable_queue)
      stats.scheduler_queue_leaks++;
    if (user->in_wait_queue)
      stats.scheduler_wait_residue++;
    if (slottee_mode_is_user_ocall(user->mode) &&
        slot != current_slot &&
        user->scheduler_state != SLOTTEE_USER_LT_EXITED &&
        user->scheduler_state != SLOTTEE_USER_LT_EMPTY)
      stats.scheduler_unfinished += user->active ? 1 : 0;
    if (slottee_mode_is_user_ocall(user->mode) && user->dispatch_count) {
      active_lt_count++;
      if (user->dispatch_count < stats.fairness_min)
        stats.fairness_min = user->dispatch_count;
      if (user->dispatch_count > stats.fairness_max)
        stats.fairness_max = user->dispatch_count;
    }
    stats.stack_entry_ok += user->user_stack_entry_ok;
    stats.stack_exit_ok += user->user_stack_exit_ok;
    stats.tls_resume_ok += user->tls_resume_ok;
    stats.hart_id[slot] = user->hart_id;
  }
  if (stats.fairness_min == (uintptr_t)-1)
    stats.fairness_min = 0;
  if (active_lt_count) {
    stats.fairness_checks = 1;
    stats.fairness_gap = stats.fairness_max - stats.fairness_min;
    if (stats.fairness_gap > SLOTTEE_LT_FAIRNESS_GAP_LIMIT)
      stats.fairness_violations++;
  }
  slottee_lt_scheduler_lock_release();

  if (copy_to_user((void*)stats_ptr, &stats, sizeof(stats)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/*
 * Entry point for the OS-level preemptive timer scheduler.  Issued by an eapp
 * thread already running inside a timer-redirectable LT_USER_OCALL slot (the
 * "scheduler thread").  Bootstraps `count` co-resident worker LTs and switches
 * the trap frame into the first one; the syscall handler must NOT clobber a0 on
 * success (it returns without writing the result).  Control returns here only
 * after every worker has exited, via slottee_preempt_worker_exit restoring the
 * saved scheduler frame with a0 = completed worker count.
 */
uintptr_t
slottee_preempt_run(struct encl_ctx* ctx, uintptr_t specs_ptr, uintptr_t count)
{
  struct slottee_preempt_spec specs[SLOTTEE_MAX_SLOTS];
  struct slottee_active_user_context* sched = slottee_active_user_for_frame(ctx);
  struct slottee_active_user_context* first;
  uintptr_t assigned = 0;
  uintptr_t i;

  if (!sched || !slottee_mode_is_user_ocall(sched->mode) ||
      slottee_preempt_sched_active)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (count == 0 || count >= SLOTTEE_MAX_SLOTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (!specs_ptr ||
      copy_from_user(specs, (void*)specs_ptr, count * sizeof(specs[0])))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  for (i = 0; i < count; i++) {
    if (!slottee_user_entry_addr_ok(specs[i].fn))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  slottee_lt_scheduler_lock_acquire();

  slottee_preempt_worker_count = 0;
  slottee_preempt_completed = 0;
  slottee_preempt_switches = 0;
  slottee_preempt_ticks = 0;
  slottee_preempt_host_yields = 0;
  slottee_preempt_exit_switches = 0;
  slottee_preempt_current_slot = 0;

  /*
   * The scheduler thread may have taken a stray host-mediated timer preempt in
   * the tiny window before this call, leaving itself (or stale dispatch state)
   * on the runnable queue.  Drain the queue and clear the scheduler's membership
   * so only freshly bootstrapped workers are runnable, and reset the duplicate
   * counter so the report reflects this run only.
   */
  while (slottee_user_runnable_queue.count)
    (void)slottee_user_lt_queue_dequeue(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE);
  if (sched->in_wait_queue)
    (void)slottee_user_lt_queue_remove(&slottee_user_wait_queue,
        SLOTTEE_USER_LT_QUEUE_WAIT, sched);
  sched->scheduler_state = SLOTTEE_USER_LT_RUNNING;
  slottee_user_scheduler_duplicate_rejects = 0;

  for (uintptr_t slot = 1; slot < SLOTTEE_MAX_SLOTS && assigned < count; slot++) {
    if (slot == sched->slot_id)
      continue;
    slottee_preempt_worker_slots[assigned++] = slot;
  }
  if (assigned != count) {
    slottee_lt_scheduler_lock_release();
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }

  /* ctx already points past the PREEMPT_RUN ecall (handle_syscall did sepc+=4);
   * save it so the scheduler thread resumes right after the call. */
  slottee_preempt_scheduler_ctx = *ctx;
  slottee_preempt_scheduler_ctx_valid = 1;

  for (i = 0; i < count; i++) {
    struct slottee_active_user_context* user =
        &slottee_active_users[slottee_preempt_worker_slots[i]];

    slottee_preempt_init_worker(user, slottee_preempt_worker_slots[i],
        sched->lease_id, specs[i].fn, specs[i].arg, ctx);
    if (!user->user_alloc_ok) {
      slottee_preempt_scheduler_ctx_valid = 0;
      slottee_lt_scheduler_lock_release();
      return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
    }
    (void)slottee_user_lt_queue_enqueue(&slottee_user_runnable_queue,
        SLOTTEE_USER_LT_QUEUE_RUNNABLE, user);
  }

  slottee_preempt_worker_count = count;

  first = slottee_preempt_pick_next();
  if (!first) {
    slottee_preempt_scheduler_ctx_valid = 0;
    slottee_lt_scheduler_lock_release();
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
  first->scheduler_state = SLOTTEE_USER_LT_RUNNING;
  first->preempt_dispatch_count++;
  slottee_user_lt_record_dispatch(first);
  slottee_preempt_current_slot = first->slot_id;
  slottee_preempt_sched_active = 1;
  *ctx = first->saved_ctx;

  slottee_lt_scheduler_lock_release();
  printf("[slottee] preempt_run start sched=%lu count=%lu first=%lu fn=0x%lx sp=0x%lx\r\n",
      sched->slot_id, count, first->slot_id, first->saved_ctx.regs.sepc,
      first->saved_ctx.regs.sp);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

uintptr_t
slottee_preempt_collect_stats(struct encl_ctx* ctx, uintptr_t stats_ptr)
{
  struct slottee_preempt_sched_stats stats;
  uintptr_t i;

  (void)ctx;
  if (!stats_ptr)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  memset(&stats, 0, sizeof(stats));
  slottee_lt_scheduler_lock_acquire();
  stats.worker_count = slottee_preempt_worker_count;
  stats.completed = slottee_preempt_completed;
  stats.preempt_switches = slottee_preempt_switches;
  stats.preempt_ticks = slottee_preempt_ticks;
  stats.host_yields = slottee_preempt_host_yields;
  stats.exit_switches = slottee_preempt_exit_switches;
  stats.runnable_queue_depth = slottee_user_runnable_queue.count;
  stats.scheduler_wait_residue = slottee_user_wait_queue.count;
  stats.scheduler_duplicate_rejects = slottee_user_scheduler_duplicate_rejects;
  stats.active = slottee_preempt_sched_active;
  stats.fairness_min = (uintptr_t)-1;
  stats.fairness_max = 0;

  for (i = 0; i < slottee_preempt_worker_count && i < SLOTTEE_MAX_SLOTS; i++) {
    uintptr_t slot = slottee_preempt_worker_slots[i];
    struct slottee_active_user_context* user = &slottee_active_users[slot];
    uintptr_t dispatched = user->dispatch_count;

    stats.per_worker_slot[i] = slot;
    stats.per_worker_dispatch[i] = dispatched;
    stats.per_worker_preempts[i] = user->preempt_count;
    if (user->in_runnable_queue || user->in_wait_queue)
      stats.scheduler_queue_leaks++;
    if (user->scheduler_state != SLOTTEE_USER_LT_EXITED)
      stats.scheduler_unfinished++;
    if (dispatched < stats.fairness_min)
      stats.fairness_min = dispatched;
    if (dispatched > stats.fairness_max)
      stats.fairness_max = dispatched;
  }
  if (stats.fairness_min == (uintptr_t)-1)
    stats.fairness_min = 0;
  stats.fairness_gap = stats.fairness_max - stats.fairness_min;
  if (stats.fairness_gap > SLOTTEE_LT_FAIRNESS_GAP_LIMIT)
    stats.fairness_violations++;
  slottee_lt_scheduler_lock_release();

  printf("[slottee] preempt_stats wc=%lu done=%lu sw=%lu host_yield=%lu d=%lu/%lu/%lu p=%lu/%lu/%lu unfin=%lu qleak=%lu active=%lu\r\n",
      stats.worker_count, stats.completed, stats.preempt_switches,
      stats.host_yields,
      stats.per_worker_dispatch[0], stats.per_worker_dispatch[1],
      stats.per_worker_dispatch[2], stats.per_worker_preempts[0],
      stats.per_worker_preempts[1], stats.per_worker_preempts[2],
      stats.scheduler_unfinished, stats.scheduler_queue_leaks, stats.active);

  if (copy_to_user((void*)stats_ptr, &stats, sizeof(stats)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
