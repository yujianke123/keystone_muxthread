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
static uintptr_t slottee_global_wait_user_ptr;
static uintptr_t slottee_global_wait_target;
static uintptr_t slottee_global_wait_op;
static uintptr_t slottee_global_wait_block_count;
static uintptr_t slottee_global_wait_wakeup_count;
static uintptr_t slottee_global_notify_miss_count;

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
  user->user_stack_entry_ok = 0;
  user->user_stack_exit_ok = 0;
  user->tls_resume_ok = 0;

  if (slottee_mode_is_user_ocall(mode))
    slottee_prepare_user_memory(user, slot_id);

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
  __asm__ volatile("csrw sscratch, %0" :: "r"(user->user_stack_top));
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

  slottee_record_trap_frame(user, ctx, RUNTIME_SYSCALL_EXIT);
  user->exit_trap_count++;
  user->tls_exit_ok = user->last_trap_user_tp == user->entry_tls_base;
  user->tls_exit_mismatch += user->tls_exit_ok ? 0 : 1;
  user->user_stack_exit_ok = slottee_user_addr_in_range(user->last_trap_user_sp,
      user->user_stack_base, SLOTTEE_USER_STACK_SIZE);
  if (!slottee_active_user_ocall_exit_ok(user, value))
    value = SLOTTEE_LT_USER_ILLEGAL_MAGIC;

  if (slottee_mode_is_user_ocall(user->mode)) {
    printf("[slottee] lt_user_exit slot=%lu value=%lu syscalls=%lu ocalls=%lu resumes=%lu exits=%lu faults=%lu sp=0x%lx tp=0x%lx stack_entry=%lu stack_exit=%lu tls_entry=%lu tls_exit=%lu tls_resume=%lu tls_mismatch=%lu wait_blocks=%lu wait_wakeups=%lu timer_stops=%lu notify_misses=%lu\r\n",
        user->slot_id, value, user->syscall_trap_count,
        user->ocall_trap_count, user->ocall_resume_count,
        user->exit_trap_count, user->fault_trap_count,
        user->last_trap_user_sp, user->last_trap_user_tp,
        user->user_stack_entry_ok, user->user_stack_exit_ok,
        user->tls_entry_ok, user->tls_exit_ok, user->tls_resume_ok,
        user->tls_exit_mismatch, user->wait_block_count, user->wait_wakeup_count,
        user->timer_wait_stop_count,
        user->wait_notify_miss_count);
  }

  slot_id = user->slot_id;
  lease_id = user->lease_id;
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
  long value = 0;
  int ready = 0;

  if (!user_ptr || copy_from_user(&value, (void*)user_ptr, sizeof(value)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (op == SLOTTEE_LT_WAIT_OP_EQ)
    ready = value == (long)target;
  else if (op == SLOTTEE_LT_WAIT_OP_GE)
    ready = value >= (long)target;
  else
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (ready)
    return SLOTTEE_LT_WAIT_RESULT_READY;

  user = slottee_active_user_for_frame(ctx);
  if (user) {
    user->wait_user_ptr = user_ptr;
    user->wait_target = target;
    user->wait_op = op;
    user->wait_block_count++;
    user->timer_wait_stop_count++;
  } else {
    slottee_global_wait_user_ptr = user_ptr;
    slottee_global_wait_target = target;
    slottee_global_wait_op = op;
    slottee_global_wait_block_count++;
  }

  /*
   * The stop SBI returns to this instruction only after the host resumes the
   * enclave.  Its a0 may contain the host resume status, so the wait primitive
   * treats that continuation as the observable "blocked once" result.
   */
  (void)sbi_stop_enclave(STOP_TIMER_INTERRUPT);
  return SLOTTEE_LT_WAIT_RESULT_BLOCKED;
}

uintptr_t
slottee_lt_notify_value(struct encl_ctx* ctx, uintptr_t user_ptr)
{
  uintptr_t slot;
  uintptr_t wakes = 0;
  struct slottee_active_user_context* notifier;

  if (!user_ptr)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  for (slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    struct slottee_active_user_context* user = &slottee_active_users[slot];

    if (!user->wait_user_ptr)
      continue;
    if (user->wait_user_ptr != user_ptr)
      continue;

    user->wait_wakeup_count++;
    user->wait_user_ptr = 0;
    wakes++;
  }

  if (slottee_global_wait_user_ptr == user_ptr) {
    slottee_global_wait_wakeup_count++;
    slottee_global_wait_user_ptr = 0;
    wakes++;
  }

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
slottee_lt_collect_stats(uintptr_t stats_ptr)
{
  struct slottee_lt_runtime_stats stats = {0};
  uintptr_t slot;

  if (!stats_ptr)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  stats.wait_blocks = slottee_global_wait_block_count;
  stats.wait_wakeups = slottee_global_wait_wakeup_count;
  stats.notify_misses = slottee_global_notify_miss_count;
  stats.timer_wait_stops = slottee_global_wait_block_count;

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
    stats.stack_entry_ok += user->user_stack_entry_ok;
    stats.stack_exit_ok += user->user_stack_exit_ok;
    stats.tls_resume_ok += user->tls_resume_ok;
  }

  if (copy_to_user((void*)stats_ptr, &stats, sizeof(stats)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
