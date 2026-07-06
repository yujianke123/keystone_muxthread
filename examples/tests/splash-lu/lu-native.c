/*
 * C3 SPLASH-2 LU（无主元、右视分块）REE 原生 pthread 基线。
 * 参照 SPLASH-2 LU 核（ParTEE §5.4 同款配置：N=64；此处并加大 N 取可用计时信号）。
 * 非主元 LU 分解 A=L·U，块大小 B，块列右视更新按行块跨线程并行；rdtime@4MHz 计时（与
 * enclave 版同口径），FNV-1a checksum 校验 L\U 就地结果。用途：建立 C3 LU 核 + REE 基线，
 * 供后续 in-enclave SlotTEE LU 对照（TEE 开销%）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>

#define MAXN 512
static double A[MAXN][MAXN];
static long cfg_n, cfg_b, cfg_threads;

static inline unsigned long rdtime_now(void) {
  unsigned long c;
  asm volatile("rdtime %0" : "=r"(c));
  return c;
}

/* 确定性、对角占优填充（保证无主元 LU 数值稳定、结果确定）。 */
static void fill(long n) {
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++)
      A[i][j] = (double)(((i * 7 + j * 3 + 1) & 0x1f) + 1);
  for (long i = 0; i < n; i++)
    A[i][i] += (double)(n * 32);   /* 对角占优 */
}

/* 对角块 k 就地 LU（串行小块）。 */
static void lu_diag(long k, long b, long n) {
  long kk = (k + b > n) ? n : k + b;
  for (long i = k; i < kk; i++) {
    for (long j = k; j < i; j++) {
      double s = A[i][j];
      for (long p = k; p < j; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s / A[j][j];
    }
    for (long j = i; j < kk; j++) {
      double s = A[i][j];
      for (long p = k; p < i; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s;
    }
  }
}

struct targ { long k, b, n, t, nt; };

/* 右视更新：用已分解的对角块，更新 [kk,n) 行块的列 [k,kk) 与尾部；按行跨线程分。 */
static void *update_worker(void *p) {
  struct targ *a = (struct targ *)p;
  long k = a->k, b = a->b, n = a->n;
  long kk = (k + b > n) ? n : k + b;
  /* L 列块 (行 kk..n, 列 k..kk)：前代 */
  for (long i = kk + a->t; i < n; i += a->nt)
    for (long j = k; j < kk; j++) {
      double s = A[i][j];
      for (long p = k; p < j; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s / A[j][j];
    }
  return NULL;
}

static void *trail_worker(void *p) {
  struct targ *a = (struct targ *)p;
  long k = a->k, b = a->b, n = a->n;
  long kk = (k + b > n) ? n : k + b;
  /* 尾部 Schur 补更新 (行 kk..n, 列 kk..n) 按行分线程 */
  for (long i = kk + a->t; i < n; i += a->nt)
    for (long j = kk; j < n; j++) {
      double s = A[i][j];
      for (long p = k; p < kk; p++) s -= A[i][p] * A[p][j];
      A[i][j] = s;
    }
  return NULL;
}

static uintptr_t checksum(long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++) {
      long v = (long)(A[i][j] * 1000.0);   /* 量化避免浮点噪声 */
      acc ^= (uintptr_t)(unsigned long)v;
      acc *= 1099511628211u;
    }
  return acc;
}

/* nt==0：直接单线程(无 pthread)，与 in-enclave G=0 同结构，供公平 TEE 开销对比。 */
static void lu_update_rows_direct(long k, long b, long n) {
  long kk = (k + b > n) ? n : k + b;
  for (long i = kk; i < n; i++) {
    for (long j = k; j < kk; j++) { double s2 = A[i][j]; for (long p = k; p < j; p++) s2 -= A[i][p]*A[p][j]; A[i][j] = s2/A[j][j]; }
    for (long j = kk; j < n; j++) { double s2 = A[i][j]; for (long p = k; p < kk; p++) s2 -= A[i][p]*A[p][j]; A[i][j] = s2; }
  }
}

static unsigned long lu_factor(long n, long b, long nt) {
  pthread_t tid[4];
  struct targ ta[4];
  unsigned long s = rdtime_now();
  if (nt == 0) {
    for (long k = 0; k < n; k += b) { lu_diag(k, b, n); lu_update_rows_direct(k, b, n); }
    return rdtime_now() - s;
  }
  for (long k = 0; k < n; k += b) {
    lu_diag(k, b, n);
    for (long t = 0; t < nt; t++) { ta[t]=(struct targ){k,b,n,t,nt}; pthread_create(&tid[t],NULL,update_worker,&ta[t]); }
    for (long t = 0; t < nt; t++) pthread_join(tid[t], NULL);
    for (long t = 0; t < nt; t++) { ta[t]=(struct targ){k,b,n,t,nt}; pthread_create(&tid[t],NULL,trail_worker,&ta[t]); }
    for (long t = 0; t < nt; t++) pthread_join(tid[t], NULL);
  }
  return rdtime_now() - s;
}

int main(void) {
  long sizes[] = {64, 128, 256, 512};
  int threadset[] = {0, 1, 2, 4};   /* 0=直接单线程(无pthread,对标in-enclave G=0) */
  long B = 16;
  printf("lu_native,setup,metric=rdtime_native_4mhz,block=%ld,sizes=64/128/256/512,threads=0(direct)/1/2/4\n", B);
  printf("lu_native,result,N,threads,cycles,csum\n");
  for (int si = 0; si < 4; si++) {
    long n = sizes[si];
    for (int ti = 0; ti < 3; ti++) {
      int th = threadset[ti];
      fill(n);
      cfg_n = n; cfg_b = B; cfg_threads = th;
      unsigned long cyc = lu_factor(n, B, th);
      printf("lu_native,result,%ld,%d,%lu,0x%lx\n", n, th, cyc, (unsigned long)checksum(n));
      fflush(stdout);
    }
  }
  printf("[ree] lu native done ok=1\n");
  return 0;
}
