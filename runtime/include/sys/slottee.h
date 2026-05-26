#ifndef __SLOTTEE_H__
#define __SLOTTEE_H__

#include <stdint.h>

struct encl_ctx;

void slottee_slot_trampoline(uintptr_t slot_token);
void slottee_active_user_prepare_user_entry(void);
void slottee_active_user_record_syscall(struct encl_ctx* ctx, uintptr_t syscall_id);
void slottee_active_user_record_ocall(struct encl_ctx* ctx);
void slottee_active_user_record_ocall_resume(uintptr_t value);
int slottee_active_user_exit(uintptr_t value);
int slottee_active_user_fault_exit(struct encl_ctx* ctx, uintptr_t value);

#endif
