#ifndef __SLOTTEE_H__
#define __SLOTTEE_H__

#include <stdint.h>

void slottee_slot_trampoline(uintptr_t slot_token);
int slottee_active_user_exit(uintptr_t value);

#endif
