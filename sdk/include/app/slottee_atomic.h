#ifndef __SLOTTEE_ATOMIC_H__
#define __SLOTTEE_ATOMIC_H__

#include <stdint.h>

static inline long
slottee_atomic_fetch_sub(long* ptr, long value)
{
  return __atomic_fetch_sub(ptr, value, __ATOMIC_SEQ_CST);
}

static inline long
slottee_atomic_fetch_add(long* ptr, long value)
{
  return __atomic_fetch_add(ptr, value, __ATOMIC_SEQ_CST);
}

static inline long
slottee_atomic_load(const long* ptr)
{
  return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

static inline void
slottee_atomic_store(long* ptr, long value)
{
  __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

#endif
