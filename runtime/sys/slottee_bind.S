#include "util/asm_helpers.h"

.text
.align 2
.global slottee_lt_bind_switch
.type slottee_lt_bind_switch, @function
slottee_lt_bind_switch:
  addi sp, sp, -4*REGBYTES
  STORE ra, 0*REGBYTES(sp)
  STORE s0, 1*REGBYTES(sp)
  STORE s1, 2*REGBYTES(sp)

  addi s0, sp, 4*REGBYTES
  mv s1, tp

  STORE s0, 0(a4)
  STORE s1, 0(a5)

  mv sp, a0
  mv tp, a1
  mv a0, a3
  jalr a2

  addi sp, s0, -4*REGBYTES
  mv tp, s1

  LOAD ra, 0*REGBYTES(sp)
  LOAD s0, 1*REGBYTES(sp)
  LOAD s1, 2*REGBYTES(sp)
  addi sp, sp, 4*REGBYTES
  ret
