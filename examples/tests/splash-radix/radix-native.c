/*
 * C3 SPLASH-2 Radix（LSD 整数基数排序，逐 pass 并行）REE 原生 pthread 基线。
 * 参照 SPLASH-2 Radix（ParTEE §5.4：N=4096；此处并加大 N 取可用计时信号）。
 * radix=256（每 pass 1 字节，32 位键 4 pass）。每 pass：各线程对本分区算局部直方图 →
 * 全局前缀（bucket-major, thread-minor，串行小步）→ 各线程稳定 scatter 本分区。
 * pthread_barrier 同步，rdtime@4MHz 计时。checksum 校验排序结果（跨线程一致）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#define MAXN 262144
#define RADIX 256
static unsigned int A[MAXN], B[MAXN];
static long cfg_n, cfg_threads;
static pthread_barrier_t barrier;
static unsigned long worker_cycles[4];
/* hist[thread][bucket] 局部直方图 + 全局偏移 */
static long hist[4][RADIX];
static long goff[4][RADIX];

static inline unsigned long rdtime_now(void) {
  unsigned long c; asm volatile("rdtime %0" : "=r"(c)); return c;
}

static void fill(long n) {
  unsigned int x = 2463534242u;   /* 确定性 xorshift 填充 */
  for (long i = 0; i < n; i++) { x ^= x<<13; x ^= x>>17; x ^= x<<5; A[i] = x; }
}

struct targ { long t, nt, n; };

static void radix_pass(unsigned int *src, unsigned int *dst, int shift,
                       struct targ *a) {
  long n = a->n, t = a->t, nt = a->nt;
  long lo = n * t / nt, hi = n * (t + 1) / nt;
  /* 1. 局部直方图 */
  memset(hist[t], 0, sizeof(long) * RADIX);
  for (long i = lo; i < hi; i++) hist[t][(src[i] >> shift) & (RADIX - 1)]++;
  pthread_barrier_wait(&barrier);
  /* 2. 全局前缀（thread0 串行小步：bucket-major, thread-minor）→ goff[t][b] */
  if (t == 0) {
    long acc = 0;
    for (int b = 0; b < RADIX; b++)
      for (long tt = 0; tt < nt; tt++) { goff[tt][b] = acc; acc += hist[tt][b]; }
  }
  pthread_barrier_wait(&barrier);
  /* 3. 稳定 scatter：本分区按 goff 递增写 dst */
  long off[RADIX];
  for (int b = 0; b < RADIX; b++) off[b] = goff[t][b];
  for (long i = lo; i < hi; i++) {
    int b = (src[i] >> shift) & (RADIX - 1);
    dst[off[b]++] = src[i];
  }
  pthread_barrier_wait(&barrier);
}

static void *radix_worker(void *p) {
  struct targ *a = (struct targ *)p;
  unsigned long s = rdtime_now();
  for (int pass = 0; pass < 4; pass++) {
    if (pass % 2 == 0) radix_pass(A, B, pass * 8, a);
    else               radix_pass(B, A, pass * 8, a);
  }
  worker_cycles[a->t] = rdtime_now() - s;
  return NULL;
}

static uintptr_t checksum(long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++) { acc ^= A[i]; acc *= 1099511628211u; }
  return acc;
}

static int sorted_ok(long n) {
  for (long i = 1; i < n; i++) if (A[i-1] > A[i]) return 0;
  return 1;
}

static unsigned long run_radix(long n, long nt) {
  pthread_t tid[4]; struct targ ta[4];
  pthread_barrier_init(&barrier, NULL, nt);
  for (long t = 0; t < nt; t++) { ta[t] = (struct targ){t, nt, n}; pthread_create(&tid[t], NULL, radix_worker, &ta[t]); }
  for (long t = 0; t < nt; t++) pthread_join(tid[t], NULL);
  pthread_barrier_destroy(&barrier);
  unsigned long mx = 0;
  for (long t = 0; t < nt; t++) if (worker_cycles[t] > mx) mx = worker_cycles[t];
  return mx;
}

int main(void) {
  long sizes[] = {4096, 65536, 262144};
  int threadset[] = {1, 2, 4};
  printf("radix_native,setup,metric=rdtime_native_4mhz,radix=256,4pass,sizes=4096/65536/262144,threads=1/2/4\n");
  printf("radix_native,result,N,threads,cycles,csum,sorted\n");
  for (int si = 0; si < 3; si++) {
    long n = sizes[si];
    for (int ti = 0; ti < 3; ti++) {
      int th = threadset[ti];
      fill(n); cfg_n = n; cfg_threads = th;
      unsigned long cyc = run_radix(n, th);
      printf("radix_native,result,%ld,%d,%lu,0x%lx,%d\n", n, th, cyc, (unsigned long)checksum(n), sorted_ok(n));
      fflush(stdout);
    }
  }
  printf("[ree] radix native done ok=1\n");
  return 0;
}
