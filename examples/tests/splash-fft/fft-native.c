/*
 * C3 SPLASH-2 FFT（radix-2 DIT，逐 stage 并行）REE 原生 pthread 基线。
 * 参照 SPLASH-2 FFT（ParTEE §5.4：N=512；此处并加大 N 取可用计时信号）。
 * 一个 N 点复数 FFT：位反转置换 → log2(N) 个 stage，每 stage 的蝶形跨 pthread 并行、
 * stage 间 pthread_barrier 同步。rdtime@4MHz 计时（与 enclave 版同口径），量化 FNV-1a
 * checksum 校验输出。用途：建立 C3 FFT 核 + REE 基线，供后续 in-enclave 对照。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <math.h>

#define MAXN 16384
static double re[MAXN], im[MAXN];
static long cfg_n, cfg_threads;
static pthread_barrier_t barrier;
static unsigned long worker_cycles[4];

static inline unsigned long rdtime_now(void) {
  unsigned long c;
  asm volatile("rdtime %0" : "=r"(c));
  return c;
}

/* 确定性输入。 */
static void fill(long n) {
  for (long i = 0; i < n; i++) {
    re[i] = (double)((i * 7 + 3) & 0x3f) - 32.0;
    im[i] = 0.0;
  }
}

static void bit_reverse(long n) {
  for (long i = 1, j = 0; i < n; i++) {
    long bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      double tr = re[i]; re[i] = re[j]; re[j] = tr;
      double ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
  }
}

struct targ { long t, nt, n; };

static void *fft_worker(void *p) {
  struct targ *a = (struct targ *)p;
  long n = a->n;
  unsigned long s = rdtime_now();
  /* thread0 做位反转（串行前置），其余等 barrier */
  if (a->t == 0) bit_reverse(n);
  pthread_barrier_wait(&barrier);
  for (long len = 2; len <= n; len <<= 1) {
    double ang = -2.0 * M_PI / (double)len;
    long half = len >> 1;
    long nblocks = n / len;
    /* 把 nblocks 个块跨线程分 */
    for (long b = a->t; b < nblocks; b += a->nt) {
      long base = b * len;
      for (long k = 0; k < half; k++) {
        double wr = cos(ang * k), wi = sin(ang * k);
        double ur = re[base + k], ui = im[base + k];
        double vr = re[base + k + half] * wr - im[base + k + half] * wi;
        double vi = re[base + k + half] * wi + im[base + k + half] * wr;
        re[base + k] = ur + vr; im[base + k] = ui + vi;
        re[base + k + half] = ur - vr; im[base + k + half] = ui - vi;
      }
    }
    pthread_barrier_wait(&barrier);
  }
  worker_cycles[a->t] = rdtime_now() - s;
  return NULL;
}

static uintptr_t checksum(long n) {
  uintptr_t acc = 1469598103u;
  for (long i = 0; i < n; i++) {
    long v = (long)(re[i] * 100.0), w = (long)(im[i] * 100.0);
    acc ^= (uintptr_t)(unsigned long)v; acc *= 1099511628211u;
    acc ^= (uintptr_t)(unsigned long)w; acc *= 1099511628211u;
  }
  return acc;
}

static unsigned long run_fft(long n, long nt) {
  pthread_t tid[4];
  struct targ ta[4];
  pthread_barrier_init(&barrier, NULL, nt);
  for (long t = 0; t < nt; t++) { ta[t] = (struct targ){t, nt, n}; pthread_create(&tid[t], NULL, fft_worker, &ta[t]); }
  for (long t = 0; t < nt; t++) pthread_join(tid[t], NULL);
  pthread_barrier_destroy(&barrier);
  unsigned long mx = 0;
  for (long t = 0; t < nt; t++) if (worker_cycles[t] > mx) mx = worker_cycles[t];
  return mx;
}

int main(void) {
  long sizes[] = {512, 4096, 16384};
  int threadset[] = {1, 2, 4};
  printf("fft_native,setup,metric=rdtime_native_4mhz,radix2_DIT,sizes=512/4096/16384,threads=1/2/4\n");
  printf("fft_native,result,N,threads,cycles,csum\n");
  for (int si = 0; si < 3; si++) {
    long n = sizes[si];
    for (int ti = 0; ti < 3; ti++) {
      int th = threadset[ti];
      fill(n); cfg_n = n; cfg_threads = th;
      unsigned long cyc = run_fft(n, th);
      printf("fft_native,result,%ld,%d,%lu,0x%lx\n", n, th, cyc, (unsigned long)checksum(n));
      fflush(stdout);
    }
  }
  printf("[ree] fft native done ok=1\n");
  return 0;
}
