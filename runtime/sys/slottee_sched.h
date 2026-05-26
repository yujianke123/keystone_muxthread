#ifndef SLOTTEE_SCHED_H
#define SLOTTEE_SCHED_H

#include <stdint.h>

uintptr_t slottee_lt_scheduler_run(uintptr_t slot_id, uintptr_t lease_id);
uintptr_t slottee_lt_context_run(uintptr_t slot_id, uintptr_t lease_id);
uintptr_t slottee_lt_yield_run(uintptr_t slot_id, uintptr_t lease_id);
uintptr_t slottee_lt_bind_run(uintptr_t slot_id, uintptr_t lease_id);
uintptr_t slottee_lt_trap_safe_run(uintptr_t slot_id, uintptr_t lease_id);

#endif
