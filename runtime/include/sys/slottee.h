#ifndef __SLOTTEE_H__
#define __SLOTTEE_H__

#include <stdint.h>

struct encl_ctx;

uintptr_t slottee_slot_trampoline(uintptr_t slot_token);
uintptr_t slottee_slot_trampoline_with_arg(uintptr_t slot_token, uintptr_t* user_arg);
void slottee_set_user_entry(uintptr_t entry);
uintptr_t slottee_lt_spawn(uintptr_t slot_id, uintptr_t fn, uintptr_t arg);
void slottee_active_user_record_syscall(struct encl_ctx* ctx, uintptr_t syscall_id);
void slottee_active_user_record_ocall(struct encl_ctx* ctx);
void slottee_active_user_record_ocall_resume(struct encl_ctx* ctx, uintptr_t value);
int slottee_active_user_exit(struct encl_ctx* ctx, uintptr_t value);
int slottee_active_user_fault_exit(struct encl_ctx* ctx, uintptr_t value);

#endif
