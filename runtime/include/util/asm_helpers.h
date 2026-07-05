#ifndef _ASM_HELPERS_H_
#define _ASM_HELPERS_H_

#if __riscv_xlen == 64
#define STORE sd
#define LOAD ld
#define SWAP amoswap.d
#define LOG_REGBYTES  3
#define WORD .dword
#elif __riscv_xlen == 32
#define STORE sw
#define LOAD lw
#define SWAP amoswap.w
#define LOG_REGBYTES  2
#define WORD .word
#endif

#define LWU lwu
#define REGBYTES (1<<LOG_REGBYTES)
/* 35 = regs(32) + sstatus/sbadaddr/scause(3)；+33 = fpr[32]+fcsr(FP 上下文, offset 35..67)。 */
#define ENCL_CONTEXT_SIZE (REGBYTES*68)
#define HOST_CONTEXT_SIZE (REGBYTES*32)

#define ENCL_STACK_SIZE (8*1024)

#endif  // _ASM_HELPERS_H_
