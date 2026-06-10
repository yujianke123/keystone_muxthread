#ifndef __SLOTTEE_H__
#define __SLOTTEE_H__

#include <stdint.h>

struct encl_ctx;

#define SLOTTEE_MAX_CONCURRENT_DEFAULT 3
#define SLOTTEE_LT_QUANTUM_CYCLES 10000

uintptr_t slottee_slot_trampoline(uintptr_t slot_token);
uintptr_t slottee_slot_trampoline_with_arg(
    uintptr_t slot_token, uintptr_t* user_arg, uintptr_t* user_sp);
void slottee_set_user_entry(uintptr_t entry);
uintptr_t slottee_slot_request(uintptr_t policy_ptr);
uintptr_t slottee_slot_release(uintptr_t slot_id);
uintptr_t slottee_lt_spawn(uintptr_t slot_id, uintptr_t fn, uintptr_t arg);
uintptr_t slottee_lt_wait_value(
    struct encl_ctx* ctx, uintptr_t user_ptr, uintptr_t target, uintptr_t op);
uintptr_t slottee_lt_notify_value(struct encl_ctx* ctx, uintptr_t user_ptr);
uintptr_t slottee_lt_host_yield(void);
uintptr_t slottee_lt_collect_stats(struct encl_ctx* ctx, uintptr_t stats_ptr);
uintptr_t slottee_lt_timer_preempt(struct encl_ctx* ctx);
uintptr_t slottee_preempt_run(
    struct encl_ctx* ctx, uintptr_t specs_ptr, uintptr_t count,
    uintptr_t switch_budget, uintptr_t flags);
uintptr_t slottee_preempt_collect_stats(struct encl_ctx* ctx, uintptr_t stats_ptr);
void slottee_active_user_record_syscall(struct encl_ctx* ctx, uintptr_t syscall_id);
void slottee_active_user_record_ocall(struct encl_ctx* ctx);
void slottee_active_user_record_ocall_resume(struct encl_ctx* ctx, uintptr_t value);
int slottee_active_user_exit(struct encl_ctx* ctx, uintptr_t value);
int slottee_active_user_fault_exit(struct encl_ctx* ctx, uintptr_t value);

#endif
