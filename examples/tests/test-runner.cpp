//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <pthread.h>
#include <cstdio>
#include <iostream>
#include "edge_wrapper.h"
#include "host/keystone.h"
#include "shared/sm_err.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

const char* longstr = "hellohellohellohellohellohellohellohellohellohello";

unsigned long
print_buffer(char* str) {
  printf("Enclave said: %s", str);
  return strlen(str);
}

void
print_value(unsigned long val) {
  printf("Enclave said value: %u\n", val);
  return;
}

const char*
get_host_string() {
  return longstr;
}

static struct report_t report;
static const uintptr_t enter_slot_bench_iters = 3;
static const uintptr_t enter_slot_pool_workers = 2;
static const uintptr_t enter_slot_resume_limit = 8;

void
print_hex(void* buffer, size_t len) {
  int i;
  for (i = 0; i < len; i += sizeof(uintptr_t)) {
    printf("%.16lx ", *((uintptr_t*)((uintptr_t)buffer + i)));
  }
  printf("\n");
}

void
copy_report(void* buffer) {
  Report report;

  report.fromBytes((unsigned char*)buffer);

  if (report.checkSignaturesOnly(_sanctum_dev_public_key)) {
    printf("Attestation report SIGNATURE is valid\n");
  } else {
    printf("Attestation report is invalid\n");
  }
}

static int
expect_enter_slot_status(const char* label, Keystone::Error ret, uintptr_t status,
    uintptr_t value, uintptr_t expected) {
  if (ret != Keystone::Error::Success) {
    printf("[FAIL] %s ioctl failed\n", label);
    return 1;
  }

  printf("%s returned %lu value %lu\n", label, status, value);
  if (status != expected) {
    printf("[FAIL] %s returned unexpected status (%lu != %lu)\n", label, status, expected);
    return 1;
  }

  return 0;
}

static slot_cap_t
make_enter_slot_test_cap(uintptr_t slot_id) {
  slot_cap_t cap = {};
  cap.version = SLOTTEE_ENTER_SLOT_VERSION;
  cap.slot_id = slot_id;
  cap.epoch = SLOTTEE_INITIAL_EPOCH;
  cap.cap_seq = SLOTTEE_DEFAULT_CAP_SEQ;
  cap.rights = SLOTTEE_CAP_RIGHT_ENTER;
  cap.max_lease_cycles = SLOTTEE_DEFAULT_MAX_LEASE_CYCLES;
  return cap;
}

static void
wait_for_enter_slot_ttl(uintptr_t cycles) {
  uintptr_t start = 0;
  uintptr_t now = 0;

  asm volatile("rdcycle %0" : "=r"(start));
  do {
    asm volatile("rdcycle %0" : "=r"(now));
  } while ((now - start) < cycles);
}

static uintptr_t
read_cycle_counter() {
  uintptr_t cycles = 0;

  asm volatile("rdcycle %0" : "=r"(cycles));
  return cycles;
}

static int
expect_enter_slot_bench_row(const char* bench, uintptr_t iter, Keystone::Error ret,
    uintptr_t status, uintptr_t value, uintptr_t expected, uintptr_t cycles) {
  printf("%s,%lu,%lu,%lu,%lu\n", bench, iter, status, value, cycles);
  fflush(stdout);

  if (ret != Keystone::Error::Success) {
    printf("[FAIL] %s bench ioctl failed at iter %lu\n", bench, iter);
    return 1;
  }

  if (status != expected) {
    printf("[FAIL] %s bench iter %lu returned unexpected status (%lu != %lu)\n",
        bench, iter, status, expected);
    return 1;
  }

  return 0;
}

static int
expect_enter_slot_bench_value(const char* bench, uintptr_t iter, uintptr_t value,
    uintptr_t expected) {
  if (value != expected) {
    printf("[FAIL] %s bench iter %lu returned unexpected value (%lu != %lu)\n",
        bench, iter, value, expected);
    return 1;
  }

  return 0;
}

static int
init_enter_slot_bench_enclave(Keystone::Enclave& enclave, const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params) {
  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT bench failed to init enclave\n");
    return 1;
  }

  return 0;
}

static int
run_enter_slot_bench(const char* eapp_file, const char* rt_file, const char* ld_file,
    Keystone::Params params) {
  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);
  printf("bench,iter,status,value,cycles\n");
  fflush(stdout);

  for (uintptr_t iter = 0; iter < enter_slot_bench_iters; iter++) {
    Keystone::Enclave enclave;
    uintptr_t status = 0;
    uintptr_t value = 0;

    if (init_enter_slot_bench_enclave(enclave, eapp_file, rt_file, ld_file, params))
      return 1;

    uintptr_t start = read_cycle_counter();
    Keystone::Error ret = enclave.enterSlot(1, &status, &value);
    uintptr_t cycles = read_cycle_counter() - start;

    if (expect_enter_slot_bench_row("null_enter", iter, ret, status, value,
            SBI_ERR_SM_NOT_IMPLEMENTED, cycles)) {
      enclave.destroy();
      return 1;
    }
  }

  for (uintptr_t iter = 0; iter < enter_slot_bench_iters; iter++) {
    Keystone::Enclave enclave;
    uintptr_t status = 0;
    uintptr_t value = 0;

    if (init_enter_slot_bench_enclave(enclave, eapp_file, rt_file, ld_file, params))
      return 1;

    Keystone::Error ret = enclave.enterSlot(1, &status, &value);
    if (ret != Keystone::Error::Success || status != SBI_ERR_SM_NOT_IMPLEMENTED) {
      printf("[FAIL] ENTER_SLOT duplicate bench setup failed at iter %lu\n", iter);
      enclave.destroy();
      return 1;
    }

    value = 0;
    uintptr_t start = read_cycle_counter();
    ret = enclave.enterSlot(1, &status, &value);
    uintptr_t cycles = read_cycle_counter() - start;

    if (expect_enter_slot_bench_row("duplicate_reject", iter, ret, status, value,
            SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT, cycles)) {
      enclave.destroy();
      return 1;
    }
  }

  for (uintptr_t iter = 0; iter < enter_slot_bench_iters; iter++) {
    Keystone::Enclave enclave;
    uintptr_t status = 0;
    uintptr_t value = 0;

    if (init_enter_slot_bench_enclave(enclave, eapp_file, rt_file, ld_file, params))
      return 1;

    uintptr_t start = read_cycle_counter();
    Keystone::Error ret = enclave.enterSlotWithEpoch(
        SLOTTEE_INITIAL_EPOCH + 1, 1, SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value);
    uintptr_t cycles = read_cycle_counter() - start;

    if (expect_enter_slot_bench_row("stale_epoch_reject", iter, ret, status, value,
            SBI_ERR_SM_ENCLAVE_NOT_FRESH, cycles)) {
      enclave.destroy();
      return 1;
    }
  }

  for (uintptr_t iter = 0; iter < enter_slot_bench_iters; iter++) {
    Keystone::Enclave enclave;
    uintptr_t status = 0;
    uintptr_t value = 0;
    slot_cap_t cap = make_enter_slot_test_cap(1);
    cap.max_lease_cycles = SLOTTEE_TEST_MAX_LEASE_CYCLES;

    if (init_enter_slot_bench_enclave(enclave, eapp_file, rt_file, ld_file, params))
      return 1;

    Keystone::Error ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value);
    if (ret != Keystone::Error::Success || status != SBI_ERR_SM_NOT_IMPLEMENTED) {
      printf("[FAIL] ENTER_SLOT revoke replay bench setup failed at iter %lu\n", iter);
      enclave.destroy();
      return 1;
    }

    wait_for_enter_slot_ttl(SLOTTEE_TEST_MAX_LEASE_CYCLES * 32);

    value = 0;
    uintptr_t start = read_cycle_counter();
    ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value);
    uintptr_t cycles = read_cycle_counter() - start;

    if (expect_enter_slot_bench_row("revoke_replay_reject", iter, ret, status, value,
            SBI_ERR_SM_ENCLAVE_NOT_FRESH, cycles)) {
      enclave.destroy();
      return 1;
    }
  }

  for (uintptr_t iter = 0; iter < enter_slot_bench_iters; iter++) {
    Keystone::Enclave enclave;
    uintptr_t status = 0;
    uintptr_t value = 0;

    if (init_enter_slot_bench_enclave(enclave, eapp_file, rt_file, ld_file, params))
      return 1;

    uintptr_t start = read_cycle_counter();
    Keystone::Error ret = enclave.enterSlot(
        1, SLOTTEE_ENTER_SLOT_FLAG_REAL, &status, &value);
    uintptr_t cycles = read_cycle_counter() - start;

    if (expect_enter_slot_bench_row("real_enter", iter, ret, status, value,
            SBI_ERR_SM_ENCLAVE_SUCCESS, cycles) ||
        expect_enter_slot_bench_value("real_enter", iter, value, SLOTTEE_SLOT_MAGIC)) {
      enclave.destroy();
      return 1;
    }
  }

  return 0;
}

struct enter_slot_pool_worker_arg {
  const char* eapp_file;
  const char* rt_file;
  const char* ld_file;
  Keystone::Params params;
  uintptr_t slot_id;
  uintptr_t flags;
  Keystone::Error ret;
  uintptr_t status;
  uintptr_t value;
};

static void*
enter_slot_pool_worker(void* opaque) {
  enter_slot_pool_worker_arg* arg = (enter_slot_pool_worker_arg*)opaque;
  Keystone::Enclave enclave;

  arg->ret = Keystone::Error::DeviceError;
  arg->status = 0;
  arg->value = 0;

  if (enclave.init(arg->eapp_file, arg->rt_file, arg->ld_file, arg->params) !=
      Keystone::Error::Success) {
    return NULL;
  }

  arg->ret = enclave.enterSlot(arg->slot_id, arg->flags, &arg->status, &arg->value);
  for (uintptr_t retry = 0;
       arg->ret == Keystone::Error::Success &&
       arg->status == SBI_ERR_SM_ENCLAVE_INTERRUPTED &&
       retry < enter_slot_resume_limit;
       retry++) {
    uintptr_t resume_value = 0;
    Keystone::Error resume_ret = enclave.resume(&resume_value);
    if (resume_ret == Keystone::Error::Success) {
      arg->status = SBI_ERR_SM_ENCLAVE_SUCCESS;
      arg->value = resume_value;
      break;
    }
    if (resume_ret != Keystone::Error::EnclaveInterrupted) {
      arg->ret = resume_ret;
      break;
    }
  }
  enclave.destroy();
  return NULL;
}

static int
run_enter_slot_pool_case(const char* label, uintptr_t flags, uintptr_t expected_value,
    const char* eapp_file, const char* rt_file, const char* ld_file, Keystone::Params params) {
  pthread_t threads[enter_slot_pool_workers];
  enter_slot_pool_worker_arg args[enter_slot_pool_workers];

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  printf("%s_worker,slot,status,value\n", label);
  fflush(stdout);

  for (uintptr_t worker = 0; worker < enter_slot_pool_workers; worker++) {
    args[worker].eapp_file = eapp_file;
    args[worker].rt_file = rt_file;
    args[worker].ld_file = ld_file;
    args[worker].params = params;
    args[worker].slot_id = worker + 1;
    args[worker].flags = flags;
    args[worker].ret = Keystone::Error::DeviceError;
    args[worker].status = 0;
    args[worker].value = 0;

    if (pthread_create(&threads[worker], NULL, enter_slot_pool_worker, &args[worker]) != 0) {
      printf("[FAIL] ENTER_SLOT %s failed to create worker %lu\n", label, worker);
      return 1;
    }
  }

  for (uintptr_t worker = 0; worker < enter_slot_pool_workers; worker++) {
    if (pthread_join(threads[worker], NULL) != 0) {
      printf("[FAIL] ENTER_SLOT %s failed to join worker %lu\n", label, worker);
      return 1;
    }
  }

  for (uintptr_t worker = 0; worker < enter_slot_pool_workers; worker++) {
    printf("%s_worker,%lu,%lu,%lu\n", label,
        args[worker].slot_id, args[worker].status, args[worker].value);
    if (expect_enter_slot_status("ENTER_SLOT pool", args[worker].ret,
            args[worker].status, args[worker].value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
        expect_enter_slot_bench_value(
            label, worker, args[worker].value, expected_value)) {
      return 1;
    }
  }

  return 0;
}

static int
run_enter_slot_pthread_pool(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("pool", SLOTTEE_ENTER_SLOT_FLAG_REAL,
      SLOTTEE_SLOT_MAGIC, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_scheduler(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_sched", SLOTTEE_ENTER_SLOT_FLAG_REAL_LT,
      SLOTTEE_LT_SCHED_MAGIC, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_context(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_context", SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT,
      SLOTTEE_LT_CONTEXT_MAGIC, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_yield(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_yield", SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD,
      SLOTTEE_LT_YIELD_MAGIC, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_bind(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_bind", SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_BIND,
      SLOTTEE_LT_BIND_MAGIC, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_trap_safe(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_trap_safe",
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_TRAP_SAFE,
      SLOTTEE_LT_TRAP_SAFE_MAGIC, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_ecall(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_ecall",
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_ECALL,
      SLOTTEE_LT_ECALL_MAGIC, eapp_file, rt_file, ld_file, params);
}

int
main(int argc, char** argv) {
  if (argc < 4 || argc > 20) {
    printf(
        "Usage: %s <eapp> <runtime> [--utm-size SIZE(K)] [--freemem-size "
        "SIZE(K)] [--time] [--load-only] [--enter-slot-stub] "
        "[--enter-slot-real] [--enter-slot-negative] [--enter-slot-lease] "
        "[--enter-slot-destroy-recreate] [--enter-slot-epoch] "
        "[--enter-slot-multislot] [--enter-slot-capability] "
        "[--enter-slot-revoke-replay] [--enter-slot-bench] "
        "[--enter-slot-pthread-pool] [--enter-slot-lt-scheduler] "
        "[--enter-slot-lt-context] [--enter-slot-lt-yield] "
        "[--enter-slot-lt-bind] [--enter-slot-lt-trap-safe] "
        "[--enter-slot-lt-ecall] "
        "[--utm-ptr 0xPTR] [--retval EXPECTED]\n",
        argv[0]);
    return 0;
  }

  int self_timing = 0;
  int load_only   = 0;
  int enter_slot_stub = 0;
  int enter_slot_real = 0;
  int enter_slot_negative = 0;
  int enter_slot_lease = 0;
  int enter_slot_destroy_recreate = 0;
  int enter_slot_epoch = 0;
  int enter_slot_multislot = 0;
  int enter_slot_capability = 0;
  int enter_slot_revoke_replay = 0;
  int enter_slot_bench = 0;
  int enter_slot_pthread_pool = 0;
  int enter_slot_lt_scheduler = 0;
  int enter_slot_lt_context = 0;
  int enter_slot_lt_yield = 0;
  int enter_slot_lt_bind = 0;
  int enter_slot_lt_trap_safe = 0;
  int enter_slot_lt_ecall = 0;

  size_t untrusted_size = 2 * 1024 * 1024;
  size_t freemem_size   = 48 * 1024 * 1024;
  bool retval_exist = false;
  unsigned long retval = 0;

  static struct option long_options[] = {
      {"time", no_argument, &self_timing, 1},
      {"load-only", no_argument, &load_only, 1},
      {"enter-slot-stub", no_argument, &enter_slot_stub, 1},
      {"enter-slot-real", no_argument, &enter_slot_real, 1},
      {"enter-slot-negative", no_argument, &enter_slot_negative, 1},
      {"enter-slot-lease", no_argument, &enter_slot_lease, 1},
      {"enter-slot-destroy-recreate", no_argument, &enter_slot_destroy_recreate, 1},
      {"enter-slot-epoch", no_argument, &enter_slot_epoch, 1},
      {"enter-slot-multislot", no_argument, &enter_slot_multislot, 1},
      {"enter-slot-capability", no_argument, &enter_slot_capability, 1},
      {"enter-slot-revoke-replay", no_argument, &enter_slot_revoke_replay, 1},
      {"enter-slot-bench", no_argument, &enter_slot_bench, 1},
      {"enter-slot-pthread-pool", no_argument, &enter_slot_pthread_pool, 1},
      {"enter-slot-lt-scheduler", no_argument, &enter_slot_lt_scheduler, 1},
      {"enter-slot-lt-context", no_argument, &enter_slot_lt_context, 1},
      {"enter-slot-lt-yield", no_argument, &enter_slot_lt_yield, 1},
      {"enter-slot-lt-bind", no_argument, &enter_slot_lt_bind, 1},
      {"enter-slot-lt-trap-safe", no_argument, &enter_slot_lt_trap_safe, 1},
      {"enter-slot-lt-ecall", no_argument, &enter_slot_lt_ecall, 1},
      {"utm-size", required_argument, 0, 'u'},
      {"freemem-size", required_argument, 0, 'f'},
      {"retval", required_argument, 0, 'r'},
      {0, 0, 0, 0}};

  char* eapp_file = argv[1];
  char* rt_file   = argv[2];
  char* ld_file   = argv[3];

  int c;
  int opt_index = 3;
  while (1) {
    c = getopt_long(argc, argv, "u:f:", long_options, &opt_index);

    if (c == -1) break;

    switch (c) {
      case 0:
        break;
      case 'u':
        untrusted_size = atoi(optarg) * 1024;
        break;
      case 'f':
        freemem_size = atoi(optarg) * 1024;
        break;
      case 'r':
        retval_exist = true;
        retval = atoi(optarg);
        break;
    }
  }

  Keystone::Params params;
  unsigned long cycles1, cycles2, cycles3, cycles4;

  params.setFreeMemSize(freemem_size);
  params.setUntrustedSize(untrusted_size);

  if (enter_slot_bench) {
    return run_enter_slot_bench(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_pthread_pool) {
    return run_enter_slot_pthread_pool(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_scheduler) {
    return run_enter_slot_lt_scheduler(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_context) {
    return run_enter_slot_lt_context(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_yield) {
    return run_enter_slot_lt_yield(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_bind) {
    return run_enter_slot_lt_bind(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_trap_safe) {
    return run_enter_slot_lt_trap_safe(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_ecall) {
    return run_enter_slot_lt_ecall(eapp_file, rt_file, ld_file, params);
  }

  Keystone::Enclave enclave;

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles1));
  }

  enclave.init(eapp_file, rt_file, ld_file, params);

  if (enter_slot_stub) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlot(1, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT stub", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
  }

  if (enter_slot_real) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlot(
        1, SLOTTEE_ENTER_SLOT_FLAG_REAL, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT real", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_SUCCESS)) {
      return 1;
    }
    if (enter_slot_value != SLOTTEE_SLOT_MAGIC) {
      printf("[FAIL] ENTER_SLOT real returned unexpected value (%lu != %lu)\n",
          enter_slot_value, (uintptr_t)SLOTTEE_SLOT_MAGIC);
      return 1;
    }
    printf("ENTER_SLOT real slot state cleaned\n");
    return 0;
  }

  if (enter_slot_negative) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    Keystone::Error enter_slot_ret =
        enclave.enterSlot(0, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT slot0", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    enter_slot_ret = enclave.enterSlot(
        1, SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_ECALL + 1, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT flags", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    enter_slot_ret = enclave.enterSlotWithVersion(
        SLOTTEE_ENTER_SLOT_VERSION + 1, SLOTTEE_INITIAL_EPOCH, 1, SLOTTEE_ENTER_SLOT_FLAG_NONE,
        &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT version", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    enter_slot_ret = enclave.enterSlot(SLOTTEE_MAX_SLOTS, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT range", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }
  }

  if (enter_slot_lease) {
    uintptr_t enter_slot_status = 0;
    uintptr_t first_lease = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlot(1, &enter_slot_status, &first_lease);
    if (expect_enter_slot_status("ENTER_SLOT lease first", enter_slot_ret, enter_slot_status,
            first_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (first_lease == 0) {
      printf("[FAIL] ENTER_SLOT lease first returned zero lease id\n");
      return 1;
    }

    uintptr_t second_value = 0;
    enter_slot_ret = enclave.enterSlot(1, &enter_slot_status, &second_value);
    if (expect_enter_slot_status("ENTER_SLOT lease duplicate", enter_slot_ret,
            enter_slot_status, second_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }
  }

  if (enter_slot_epoch) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlotWithEpoch(
        SLOTTEE_INITIAL_EPOCH + 1, 1, SLOTTEE_ENTER_SLOT_FLAG_NONE,
        &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT epoch stale", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
      return 1;
    }

    enter_slot_ret = enclave.enterSlot(
        1, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT epoch valid", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (enter_slot_value == 0) {
      printf("[FAIL] ENTER_SLOT epoch valid returned zero lease id\n");
      return 1;
    }
  }

  if (enter_slot_multislot) {
    uintptr_t enter_slot_status = 0;
    uintptr_t slot1_lease = 0;
    uintptr_t slot2_lease = 0;

    Keystone::Error enter_slot_ret = enclave.enterSlot(1, &enter_slot_status, &slot1_lease);
    if (expect_enter_slot_status("ENTER_SLOT multislot slot1", enter_slot_ret,
            enter_slot_status, slot1_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (slot1_lease == 0) {
      printf("[FAIL] ENTER_SLOT multislot slot1 returned zero lease id\n");
      return 1;
    }

    enter_slot_ret = enclave.enterSlot(2, &enter_slot_status, &slot2_lease);
    if (expect_enter_slot_status("ENTER_SLOT multislot slot2", enter_slot_ret,
            enter_slot_status, slot2_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (slot2_lease == 0 || slot2_lease == slot1_lease) {
      printf("[FAIL] ENTER_SLOT multislot slot2 returned invalid lease id\n");
      return 1;
    }

    enter_slot_ret = enclave.enterSlot(1, &enter_slot_status, &slot1_lease);
    if (expect_enter_slot_status("ENTER_SLOT multislot duplicate", enter_slot_ret,
            enter_slot_status, slot1_lease, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }
  }

  if (enter_slot_capability) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    slot_cap_t cap = make_enter_slot_test_cap(1);

    cap.rights = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap rights", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    cap.cap_seq = 0;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap seq", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    cap.max_lease_cycles = 0;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap lease", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    cap.cap_mac[0] = 1;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap mac", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap valid", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (enter_slot_value == 0) {
      printf("[FAIL] ENTER_SLOT cap valid returned zero lease id\n");
      return 1;
    }
  }

  if (enter_slot_revoke_replay) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    slot_cap_t cap = make_enter_slot_test_cap(1);
    cap.max_lease_cycles = SLOTTEE_TEST_MAX_LEASE_CYCLES;

    Keystone::Error enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT revoke first", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (enter_slot_value == 0) {
      printf("[FAIL] ENTER_SLOT revoke first returned zero lease id\n");
      return 1;
    }

    wait_for_enter_slot_ttl(SLOTTEE_TEST_MAX_LEASE_CYCLES * 32);

    enter_slot_value = 0;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT revoke replay", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
      return 1;
    }
  }

  if (enter_slot_destroy_recreate) {
    uintptr_t enter_slot_status = 0;
    uintptr_t first_lease = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlot(1, &enter_slot_status, &first_lease);
    if (expect_enter_slot_status("ENTER_SLOT recreate first", enter_slot_ret,
            enter_slot_status, first_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (first_lease == 0) {
      printf("[FAIL] ENTER_SLOT recreate first returned zero lease id\n");
      return 1;
    }

    if (enclave.destroy() != Keystone::Error::Success) {
      printf("[FAIL] failed to destroy first enclave\n");
      return 1;
    }

    Keystone::Enclave recreated;
    if (recreated.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
      printf("[FAIL] failed to recreate enclave\n");
      return 1;
    }

    uintptr_t recreated_lease = 0;
    enter_slot_ret = recreated.enterSlot(1, &enter_slot_status, &recreated_lease);
    if (expect_enter_slot_status("ENTER_SLOT recreate second", enter_slot_ret,
            enter_slot_status, recreated_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (recreated_lease == 0) {
      printf("[FAIL] ENTER_SLOT recreate second returned zero lease id\n");
      return 1;
    }

    return 0;
  }

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles2));
  }

  edge_init(&enclave);

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles3));
  }

  uintptr_t encl_ret;
  if (!load_only) enclave.run(&encl_ret);

  if (retval_exist && encl_ret != retval) {
    printf("[FAIL] enclave returned a wrong value (%d != %d)\r\n", encl_ret, retval);
  }

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles4));
    printf("[keystone-test] Init: %lu cycles\r\n", cycles2 - cycles1);
    printf("[keystone-test] Runtime: %lu cycles\r\n", cycles4 - cycles3);
  }

  return 0;
}
