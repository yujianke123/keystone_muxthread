/*
 * C2 REE 原生 pthread 矩阵乘法基线（非 enclave，裸 Linux）。
 * 位精确复刻 examples/tests/lt-user-matmul/lt-user-matmul.c 的 kernel（同 A/B 填充、
 * 同 Bt 转置、同 matmul_rows、同 FNV-1a checksum、同行分块），用 pthread 1/2/4 并行。
 * 计时用 rdtime（VF2 U-mode 可读，4MHz），与 enclave 版 compute 同单位可直接比。
 * 用途：REE 原生 compute vs SlotTEE enclave compute(C1) → TEE 开销% = (TEE-REE)/REE。
 * checksum 应与 C1 逐位相同（证明同一计算）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>

#define MAXN 512
static int A[MAXN][MAXN];
static int B[MAXN][MAXN];
static int Bt[MAXN][MAXN];
static int C[MAXN][MAXN];
static long cfg_n;
static long cfg_threads;
static unsigned long wdur[4];

static inline unsigned long rdtime_now(void) {
  unsigned long c;
  asm volatile("rdtime %0" : "=r"(c));
  return c;
}

static void fill(long n) {
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++) {
      A[i][j] = (int)((i * 7 + j * 3 + 1) & 0x7f);
      B[i][j] = (int)((i * 5 + j * 11 + 2) & 0x7f);
    }
  for (long k = 0; k < n; k++)
    for (long j = 0; j < n; j++)
      Bt[j][k] = B[k][j];
}

static void matmul_rows(long r0, long r1, long n) {
  for (long i = r0; i < r1; i++)
    for (long j = 0; j < n; j++) {
      int s = 0;
      const int *arow = A[i];
      const int *brow = Bt[j];
      for (long k = 0; k < n; k++)
        s += arow[k] * brow[k];
      C[i][j] = s;
    }
}

static uintptr_t matmul_checksum(long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++)
    for (long j = 0; j < n; j++) {
      acc ^= (uintptr_t)(unsigned int)C[i][j];
      acc *= 1099511628211u;
    }
  return acc;
}

struct targ { long g; };

static void *worker(void *p) {
  struct targ *t = (struct targ *)p;
  long n = cfg_n, gc = cfg_threads;
  long rows = n / gc;
  long r0 = t->g * rows;
  long r1 = (t->g == gc - 1) ? n : (r0 + rows);
  unsigned long s = rdtime_now();
  matmul_rows(r0, r1, n);
  unsigned long e = rdtime_now();
  wdur[t->g] = e - s;
  return NULL;
}

int main(void) {
  long sizes[] = {16, 32, 64, 128, 256, 512};
  int threadset[] = {1, 2, 4};
  printf("ree_matmul,setup,harts=4,sizes=16..512,threads=1/2/4,metric=rdtime_native_4mhz\n");
  printf("ree_matmul,result,N,threads,max_compute,csum\n");
  for (int si = 0; si < 6; si++) {
    long n = sizes[si];
    fill(n);
    for (int ti = 0; ti < 3; ti++) {
      int th = threadset[ti];
      cfg_n = n;
      cfg_threads = th;
      pthread_t tid[4];
      struct targ ta[4];
      for (int g = 0; g < th; g++) {
        ta[g].g = g;
        pthread_create(&tid[g], NULL, worker, &ta[g]);
      }
      for (int g = 0; g < th; g++)
        pthread_join(tid[g], NULL);
      unsigned long mx = 0;
      for (int g = 0; g < th; g++)
        if (wdur[g] > mx) mx = wdur[g];
      printf("ree_matmul,result,%ld,%d,%lu,0x%lx\n",
             n, th, mx, (unsigned long)matmul_checksum(n));
      fflush(stdout);
    }
  }
  printf("[ree] matmul native pthread done ok=1\n");
  return 0;
}
