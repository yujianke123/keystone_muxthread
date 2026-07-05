//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

#ifndef _REGS_H_
#define _REGS_H_
#include <stdint.h>

struct regs {
	uintptr_t sepc; // use this slot as sepc
	uintptr_t ra;
	uintptr_t sp;
	uintptr_t gp;
	uintptr_t tp;
	uintptr_t t0;
	uintptr_t t1;
	uintptr_t t2;
	uintptr_t s0;
	uintptr_t s1;
	uintptr_t a0;
	uintptr_t a1;
	uintptr_t a2;
	uintptr_t a3;
	uintptr_t a4;
	uintptr_t a5;
	uintptr_t a6;
	uintptr_t a7;
	uintptr_t s2;
	uintptr_t s3;
	uintptr_t s4;
	uintptr_t s5;
	uintptr_t s6;
	uintptr_t s7;
	uintptr_t s8;
	uintptr_t s9;
	uintptr_t s10;
	uintptr_t s11;
	uintptr_t t3;
	uintptr_t t4;
	uintptr_t t5;
	uintptr_t t6;
};

struct encl_ctx {
	struct regs regs;
  /* Supervisor CSRs */
	uintptr_t sstatus;//32
	uintptr_t sbadaddr;//33
	uintptr_t scause;//34
	/* FP 上下文（多线程 in-enclave 浮点）：f0-f31 + fcsr。offset 35..67。
	 * entry.S 在 trap save/restore 条件保存(sstatus.FS!=Off)，随 encl_ctx 一起被
	 * slottee LT 切换(*ctx=next->saved_ctx)搬运，从而每逻辑线程独立 FP 状态。 */
	uint64_t fpr[32];//35..66
	uint64_t fcsr;//67
};
#endif /* _REGS_H_ */
