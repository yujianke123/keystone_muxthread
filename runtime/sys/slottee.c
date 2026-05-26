#include "call/sbi.h"
#include "eyrie_call.h"
#include "mm/mm.h"
#include "mm/vm.h"
#include "sys/slottee.h"
#include "slottee_sched.h"
#include "util/printf.h"
#include "util/regs.h"

#define SLOTTEE_USER_STACK_PAGES 8
#define SLOTTEE_USER_TLS_PAGES   1
#define SLOTTEE_USER_STACK_SIZE \
  ((uintptr_t)(SLOTTEE_USER_STACK_PAGES * RISCV_PAGE_SIZE))
#define SLOTTEE_USER_TLS_SIZE \
  ((uintptr_t)(SLOTTEE_USER_TLS_PAGES * RISCV_PAGE_SIZE))
#define SLOTTEE_USER_REGION_GAP  RISCV_PAGE_SIZE
#define SLOTTEE_USER_SLOT_STRIDE \
  (SLOTTEE_USER_STACK_SIZE + SLOTTEE_USER_TLS_SIZE + SLOTTEE_USER_REGION_GAP)

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
};

static struct slottee_active_user_context slottee_active_user;
static uintptr_t slottee_user_entry_point;

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

static int
slottee_user_ranges_isolated(uintptr_t slot_id)
{
  uintptr_t slot_stack_base = slottee_active_user.user_stack_base;
  uintptr_t slot_tls_base = slottee_active_user.user_tls_base;
  uintptr_t other;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS ||
      !slottee_active_user.user_alloc_ok)
    return 0;

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
slottee_record_trap_frame(struct encl_ctx* ctx, uintptr_t syscall_id)
{
  if (!slottee_active_user.active || !ctx)
    return;

  slottee_active_user.last_trap_syscall = syscall_id;
  slottee_active_user.last_trap_scause = ctx->scause;
  slottee_active_user.last_trap_sepc = ctx->regs.sepc;
  slottee_active_user.last_trap_stval = ctx->sbadaddr;
  slottee_active_user.last_trap_user_sp = ctx->regs.sp;
  slottee_active_user.last_trap_user_tp = ctx->regs.tp;
}

static int
slottee_prepare_user_memory(uintptr_t slot_id)
{
  uintptr_t stack_base = slottee_user_stack_base(slot_id);
  uintptr_t tls_base = slottee_user_tls_base(slot_id);
  size_t stack_count;
  size_t tls_count;

  stack_count = alloc_pages(vpn(stack_base), SLOTTEE_USER_STACK_PAGES,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);
  tls_count = alloc_pages(vpn(tls_base), SLOTTEE_USER_TLS_PAGES,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

  slottee_active_user.user_stack_base = stack_base;
  slottee_active_user.user_stack_top = stack_base + SLOTTEE_USER_STACK_SIZE;
  slottee_active_user.user_tls_base = tls_base;
  slottee_active_user.user_tls_size = SLOTTEE_USER_TLS_SIZE;
  slottee_active_user.user_stack_pages = stack_count;
  slottee_active_user.user_tls_pages = tls_count;
  slottee_active_user.user_alloc_ok =
      stack_count == SLOTTEE_USER_STACK_PAGES &&
      tls_count == SLOTTEE_USER_TLS_PAGES;

  printf("[slottee] lt_user_mem slot=%lu stack=0x%lx-0x%lx tls=0x%lx-0x%lx pages=%lu/%lu ok=%lu\r\n",
      slot_id, slottee_active_user.user_stack_base,
      slottee_active_user.user_stack_top, slottee_active_user.user_tls_base,
      slottee_active_user.user_tls_base + slottee_active_user.user_tls_size,
      slottee_active_user.user_stack_pages, slottee_active_user.user_tls_pages,
      slottee_active_user.user_alloc_ok);

  return slottee_active_user.user_alloc_ok;
}

static void
slottee_activate_user_context(uintptr_t slot_id, uintptr_t lease_id, uintptr_t mode)
{
  slottee_active_user.active = 1;
  slottee_active_user.slot_id = slot_id;
  slottee_active_user.lease_id = lease_id;
  slottee_active_user.mode = mode;
  slottee_active_user.enter_count++;
  slottee_active_user.last_trap_syscall = 0;
  slottee_active_user.last_trap_scause = 0;
  slottee_active_user.last_trap_sepc = 0;
  slottee_active_user.last_trap_stval = 0;
  slottee_active_user.last_trap_user_sp = 0;
  slottee_active_user.last_trap_user_tp = 0;
  slottee_active_user.syscall_trap_count = 0;
  slottee_active_user.ocall_trap_count = 0;
  slottee_active_user.ocall_resume_count = 0;
  slottee_active_user.exit_trap_count = 0;
  slottee_active_user.fault_trap_count = 0;

  if (mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL)
    slottee_prepare_user_memory(slot_id);
}

int
slottee_active_user_prepare_user_entry(void)
{
  if (!slottee_active_user.active ||
      slottee_active_user.mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL ||
      !slottee_active_user.user_alloc_ok ||
      !slottee_user_entry_point)
    return 0;

  printf("[slottee] lt_user_entry slot=%lu sepc=0x%lx sscratch=0x%lx tp=0x%lx\r\n",
      slottee_active_user.slot_id, slottee_user_entry_point,
      slottee_active_user.user_stack_top, slottee_active_user.user_tls_base);

  __asm__ volatile("csrw sepc, %0" :: "r"(slottee_user_entry_point));
  __asm__ volatile("csrw sscratch, %0" :: "r"(slottee_active_user.user_stack_top));
  __asm__ volatile("mv tp, %0" :: "r"(slottee_active_user.user_tls_base) : "memory");

  return 1;
}

void
slottee_active_user_record_syscall(struct encl_ctx* ctx, uintptr_t syscall_id)
{
  if (!slottee_active_user.active)
    return;

  slottee_record_trap_frame(ctx, syscall_id);
  slottee_active_user.syscall_trap_count++;
}

void
slottee_active_user_record_ocall(struct encl_ctx* ctx)
{
  if (!slottee_active_user.active ||
      slottee_active_user.mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL)
    return;

  slottee_record_trap_frame(ctx, RUNTIME_SYSCALL_OCALL);
  slottee_active_user.ocall_trap_count++;
}

void
slottee_active_user_record_ocall_resume(uintptr_t value)
{
  if (!slottee_active_user.active ||
      slottee_active_user.mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL ||
      value != 0)
    return;

  slottee_active_user.ocall_resume_count++;
}

static int
slottee_active_user_ocall_exit_ok(uintptr_t value)
{
  if (slottee_active_user.mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL)
    return 1;

  return value == SLOTTEE_LT_USER_OCALL_MAGIC &&
      slottee_active_user.user_alloc_ok &&
      slottee_user_ranges_isolated(slottee_active_user.slot_id) &&
      slottee_active_user.ocall_trap_count == 1 &&
      slottee_active_user.ocall_resume_count == 1 &&
      slottee_active_user.exit_trap_count == 1 &&
      slottee_user_addr_in_range(slottee_active_user.last_trap_user_sp,
          slottee_active_user.user_stack_base, SLOTTEE_USER_STACK_SIZE) &&
      slottee_active_user.last_trap_user_tp == slottee_active_user.user_tls_base;
}

int
slottee_active_user_exit(uintptr_t value)
{
  uintptr_t status;

  if (!slottee_active_user.active ||
      (slottee_active_user.mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER &&
       slottee_active_user.mode != SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL))
    return 0;

  slottee_active_user.exit_trap_count++;
  if (!slottee_active_user_ocall_exit_ok(value))
    value = SLOTTEE_LT_USER_ILLEGAL_MAGIC;

  if (slottee_active_user.mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL) {
    printf("[slottee] lt_user_exit slot=%lu value=%lu syscalls=%lu ocalls=%lu resumes=%lu exits=%lu faults=%lu sp=0x%lx tp=0x%lx\r\n",
        slottee_active_user.slot_id, value,
        slottee_active_user.syscall_trap_count,
        slottee_active_user.ocall_trap_count,
        slottee_active_user.ocall_resume_count,
        slottee_active_user.exit_trap_count,
        slottee_active_user.fault_trap_count,
        slottee_active_user.last_trap_user_sp,
        slottee_active_user.last_trap_user_tp);
  }

  status = sbi_exit_slot(slottee_active_user.slot_id,
      slottee_active_user.lease_id, SLOTTEE_SLOT_EXIT_NORMAL, value);

  while (1) {
    sbi_exit_enclave(status ? status : value);
  }
}

int
slottee_active_user_fault_exit(struct encl_ctx* ctx, uintptr_t value)
{
  uintptr_t status;

  if (!slottee_active_user.active)
    return 0;

  slottee_record_trap_frame(ctx, 0);
  slottee_active_user.fault_trap_count++;

  printf("[slottee] lt_user_fault slot=%lu value=%lu scause=0x%lx sepc=0x%lx stval=0x%lx sp=0x%lx tp=0x%lx\r\n",
      slottee_active_user.slot_id, value,
      slottee_active_user.last_trap_scause,
      slottee_active_user.last_trap_sepc,
      slottee_active_user.last_trap_stval,
      slottee_active_user.last_trap_user_sp,
      slottee_active_user.last_trap_user_tp);

  status = sbi_exit_slot(slottee_active_user.slot_id,
      slottee_active_user.lease_id, SLOTTEE_SLOT_EXIT_NORMAL, value);

  while (1) {
    sbi_exit_enclave(status ? status : value);
  }
}

void
slottee_slot_trampoline(uintptr_t slot_token)
{
  uintptr_t slot_id = SLOTTEE_SLOT_TOKEN_SLOT_ID(slot_token);
  uintptr_t slot_mode = SLOTTEE_SLOT_TOKEN_MODE(slot_token);
  uintptr_t lease_id = SLOTTEE_SLOT_TOKEN_LEASE_ID(slot_token);
  uintptr_t value = SLOTTEE_SLOT_MAGIC;

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
    return;
  } else if (slot_mode == SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL) {
    slottee_activate_user_context(slot_id, lease_id, slot_mode);
    return;
  }

  sbi_exit_slot(slot_id, lease_id, SLOTTEE_SLOT_EXIT_NORMAL, value);

  while (1) {
    sbi_exit_enclave(value);
  }
}
