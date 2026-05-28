//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include "edge_wrapper.h"
#include "host/keystone.h"
#include "shared/sm_err.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

const char* longstr = "hellohellohellohellohellohellohellohellohellohello";
static int suppress_enclave_prints;

unsigned long
print_buffer(char* str) {
  printf("Enclave said: %s", str);
  return strlen(str);
}

void
print_value(unsigned long val) {
  if (!suppress_enclave_prints)
    printf("Enclave said value: %u\n", val);
  return;
}

const char*
get_host_string() {
  return longstr;
}

static struct report_t report;
static struct slot_cap_t copied_slot_cap;
static struct slot_cap_t copied_slot_caps[SLOTTEE_MAX_SLOTS];
static int copied_slot_cap_ready;
static int copied_slot_cap_ready_by_slot[SLOTTEE_MAX_SLOTS];
static const uintptr_t enter_slot_bench_iters = 3;
static const uintptr_t slottee_paper_eval_iters = 5;
static const uintptr_t slottee_ticket_total = 20;
static const uintptr_t slottee_ticket_windows = 3;
static const uintptr_t slottee_ticket_retry_limit = 128;
static const char* slottee_null_enter_baseline_commit = "d4e1754";
static const uintptr_t slottee_null_enter_baseline_count = 3;
static const uintptr_t slottee_null_enter_baseline_min = 430912;
static const uintptr_t slottee_null_enter_baseline_max = 2520128;
static const unsigned long long slottee_null_enter_baseline_total = 3891424ULL;
static const uintptr_t enter_slot_pool_workers = 2;
static const uintptr_t enter_slot_resume_limit = 8;
static const uintptr_t enter_slot_revoke_stress_rounds = 3;
static const uintptr_t enter_slot_active_revoke_timer_rounds = 3;
static const uintptr_t enter_slot_active_revoke_probe_limit = 128;
static const uintptr_t slottee_debug_mint_op_value = 4;
static const unsigned int enter_slot_active_revoke_mark_delay_us = 2000;
static const unsigned int enter_slot_active_revoke_ready_settle_us = 1000;

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

void
copy_slot_cap(void* buffer, size_t size) {
  if (size == sizeof(copied_slot_cap)) {
    memcpy(&copied_slot_cap, buffer, size);
    copied_slot_cap_ready = 1;
    if (copied_slot_cap.slot_id < SLOTTEE_MAX_SLOTS) {
      copied_slot_caps[copied_slot_cap.slot_id] = copied_slot_cap;
      copied_slot_cap_ready_by_slot[copied_slot_cap.slot_id] = 1;
    }
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

static Keystone::Error
mint_enter_slot_test_cap_with_resp(
    Keystone::Enclave& enclave, slot_cap_t* cap, slottee_debug_resp_t* debug_resp) {
#ifdef SLOTTEE_DEBUG_MINT_ENABLE
  slottee_debug_req_t req = {};
  slottee_debug_resp_t resp = {};
  Keystone::Error ret;

  if (!cap)
    return Keystone::Error::DeviceError;

  req.version = SLOTTEE_DEBUG_VERSION;
  req.op = SLOTTEE_DEBUG_OP_MINT_CAP;
  req.cap = *cap;

  ret = enclave.slotteeDebug(req, &resp);
  if (ret != Keystone::Error::Success)
    return ret;

  if (resp.status != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    printf("[FAIL] SLOTTEE_DEBUG mint cap failed status=%lu\n", resp.status);
    return Keystone::Error::DeviceError;
  }

  *cap = resp.cap;
  if (debug_resp)
    *debug_resp = resp;
  return Keystone::Error::Success;
#else
  (void)enclave;
  (void)cap;
  if (debug_resp) {
    memset(debug_resp, 0, sizeof(*debug_resp));
    debug_resp->status = SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
  }
  printf("[slottee] debug mint compile gate disabled\n");
  return Keystone::Error::DeviceError;
#endif
}

static Keystone::Error
mint_enter_slot_test_cap(Keystone::Enclave& enclave, slot_cap_t* cap) {
  return mint_enter_slot_test_cap_with_resp(enclave, cap, NULL);
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

    slot_cap_t cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }

    uintptr_t start = read_cycle_counter();
    Keystone::Error ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value);
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

    slot_cap_t cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }

    Keystone::Error ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value);
    if (ret != Keystone::Error::Success || status != SBI_ERR_SM_NOT_IMPLEMENTED) {
      printf("[FAIL] ENTER_SLOT duplicate bench setup failed at iter %lu\n", iter);
      enclave.destroy();
      return 1;
    }

    value = 0;
    uintptr_t start = read_cycle_counter();
    ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value);
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
            SBI_ERR_SM_ENCLAVE_BAD_CAP, cycles)) {
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

    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }

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

    slot_cap_t cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }

    uintptr_t start = read_cycle_counter();
    Keystone::Error ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_REAL, &status, &value);
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

  slot_cap_t cap = make_enter_slot_test_cap(arg->slot_id);
  arg->ret = mint_enter_slot_test_cap(enclave, &cap);
  if (arg->ret == Keystone::Error::Success)
    arg->ret = enclave.enterSlotWithCap(
        cap, arg->flags, &arg->status, &arg->value);
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

static int
run_enter_slot_lt_user(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_pool_case("lt_user",
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER,
      12345, eapp_file, rt_file, ld_file, params);
}

static Keystone::Error
enter_slot_request_once_with_cap(Keystone::Enclave& enclave, const slot_cap_t& cap,
    uintptr_t flags, uintptr_t* status, uintptr_t* value, uintptr_t* lease_id) {
  enter_slot_req_t req = {};
  enter_slot_resp_t resp = {};

  req.version = SLOTTEE_ENTER_SLOT_VERSION;
  req.cap = cap;
  req.flags = flags;

  Keystone::Error ret = enclave.enterSlotWithRequest(req, &resp);
  if (status)
    *status = resp.status;
  if (value)
    *value = resp.value;
  if (lease_id)
    *lease_id = resp.lease_id;

  return ret;
}

static Keystone::Error
enter_slot_request_once(Keystone::Enclave& enclave, uintptr_t slot_id, uintptr_t flags,
    uintptr_t* status, uintptr_t* value, uintptr_t* lease_id) {
  slot_cap_t cap = make_enter_slot_test_cap(slot_id);

  Keystone::Error ret = mint_enter_slot_test_cap(enclave, &cap);
  if (ret != Keystone::Error::Success)
    return ret;

  return enter_slot_request_once_with_cap(
      enclave, cap, flags, status, value, lease_id);
}

static Keystone::Error
slottee_debug_once(Keystone::Enclave& enclave, uintptr_t op, slottee_debug_resp_t* resp)
{
  slottee_debug_req_t req = {};

  req.version = SLOTTEE_DEBUG_VERSION;
  req.op = op;
  return enclave.slotteeDebug(req, resp);
}

static int
expect_slottee_debug_row(const char* label, const char* phase, Keystone::Error ret,
    const slottee_debug_resp_t& resp, uintptr_t ready, uintptr_t epoch,
    uintptr_t n_thread, uintptr_t busy_slots)
{
  printf("%s,%s,%d,%lu,%lu,%lu,%lu,%lu\n", label, phase, (int)ret,
      resp.status, resp.reentry_ready, resp.epoch, resp.n_thread,
      resp.busy_slots);
  fflush(stdout);

  if (ret != Keystone::Error::Success ||
      resp.status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      resp.reentry_ready != ready || resp.epoch != epoch ||
      resp.n_thread != n_thread || resp.busy_slots != busy_slots) {
    printf("[FAIL] %s debug %s returned unexpected state\n", label, phase);
    return 1;
  }

  return 0;
}

static Keystone::Error
enter_slot_resume_once(Keystone::Enclave& enclave, uintptr_t* status, uintptr_t* value)
{
  uintptr_t resume_value = 0;
  Keystone::Error resume_ret = enclave.resume(&resume_value);

  if (resume_ret == Keystone::Error::Success) {
    *status = SBI_ERR_SM_ENCLAVE_SUCCESS;
    *value = resume_value;
  } else if (resume_ret == Keystone::Error::EdgeCallHost) {
    *status = SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    *value = 0;
  } else if (resume_ret == Keystone::Error::EnclaveInterrupted) {
    *status = SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    *value = 0;
  } else if (resume_ret == Keystone::Error::EnclaveNotResumable) {
    *status = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
    *value = 0;
  }

  return resume_ret;
}

static Keystone::Error
enter_slot_request_round(Keystone::Enclave& enclave, uintptr_t slot_id,
    uintptr_t flags, uintptr_t* status, uintptr_t* value, uintptr_t* lease_id,
    uintptr_t* resume_count)
{
  Keystone::Error ret;

  if (resume_count)
    *resume_count = 0;

  ret = enter_slot_request_once(enclave, slot_id, flags, status, value, lease_id);
  if (ret != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT slot%lu request failed ret=%d status=%lu value=%lu lease=%lu\n",
        slot_id, (int)ret, status ? *status : 0, value ? *value : 0,
        lease_id ? *lease_id : 0);
  }

  for (uintptr_t retry = 0; ret == Keystone::Error::Success &&
       *status == SBI_ERR_SM_ENCLAVE_INTERRUPTED &&
       retry < enter_slot_resume_limit; retry++) {
    ret = enter_slot_resume_once(enclave, status, value);
    if (resume_count)
      (*resume_count)++;
    if (ret == Keystone::Error::Success &&
        *status == SBI_ERR_SM_ENCLAVE_SUCCESS)
      break;
    if (ret != Keystone::Error::EnclaveInterrupted)
      break;
    ret = Keystone::Error::Success;
  }

  return ret;
}

static int
run_enter_slot_same_enclave_multislot(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  Keystone::Enclave enclave;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t slot1_lease = 0;
  uintptr_t slot2_lease = 0;
  uintptr_t slot1_resumes = 0;
  uintptr_t slot2_resumes = 0;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT same-enclave multislot failed to init enclave\n");
    return 1;
  }

  printf("same_enclave_real,slot,status,value,lease,resumes\n");
  fflush(stdout);

  if (enter_slot_request_round(enclave, 1, SLOTTEE_ENTER_SLOT_FLAG_REAL,
          &status, &value, &slot1_lease,
          &slot1_resumes) != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT same-enclave slot1", Keystone::Error::Success,
          status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("same_enclave_real", 1, value,
          SLOTTEE_SLOT_MAGIC)) {
    enclave.destroy();
    return 1;
  }
  printf("same_enclave_real,1,%lu,%lu,%lu,%lu\n",
      status, value, slot1_lease, slot1_resumes);
  fflush(stdout);

  status = 0;
  value = 0;
  if (enter_slot_request_round(enclave, 2, SLOTTEE_ENTER_SLOT_FLAG_REAL,
          &status, &value, &slot2_lease,
          &slot2_resumes) != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT same-enclave slot2", Keystone::Error::Success,
          status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("same_enclave_real", 2, value,
          SLOTTEE_SLOT_MAGIC)) {
    enclave.destroy();
    return 1;
  }
  printf("same_enclave_real,2,%lu,%lu,%lu,%lu\n",
      status, value, slot2_lease, slot2_resumes);
  fflush(stdout);

  if (slot1_lease == 0 || slot2_lease == 0 || slot1_lease == slot2_lease) {
    printf("[FAIL] ENTER_SLOT same-enclave returned invalid lease ids (%lu, %lu)\n",
        slot1_lease, slot2_lease);
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

struct enter_slot_ocall_worker_arg {
  const char* eapp_file;
  const char* rt_file;
  const char* ld_file;
  Keystone::Params params;
  uintptr_t slot_id;
  Keystone::Error ret;
  uintptr_t status;
  uintptr_t value;
  uintptr_t ocall_count;
  uintptr_t resume_count;
};

static pthread_mutex_t enter_slot_ocall_lock = PTHREAD_MUTEX_INITIALIZER;

static Keystone::Error
enter_slot_user_ocall_round_with_cap_and_flags(Keystone::Enclave& enclave,
    const slot_cap_t& cap, uintptr_t flags, uintptr_t* status, uintptr_t* value,
    uintptr_t* lease_id,
    uintptr_t* ocall_count, uintptr_t* resume_count)
{
  Keystone::Error ret;

  if (ocall_count)
    *ocall_count = 0;
  if (resume_count)
    *resume_count = 0;

  ret = enter_slot_request_once_with_cap(enclave, cap,
      flags, status, value, lease_id);
  if (ret != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT LT user ocall slot%lu request failed ret=%d status=%lu value=%lu lease=%lu\n",
        cap.slot_id, (int)ret, status ? *status : 0, value ? *value : 0,
        lease_id ? *lease_id : 0);
  }
  for (uintptr_t retry = 0; ret == Keystone::Error::Success &&
       retry < enter_slot_resume_limit; retry++) {
    if (*status == SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST) {
      incoming_call_dispatch(enclave.getSharedBuffer());
      if (ocall_count)
        (*ocall_count)++;
      ret = enter_slot_resume_once(enclave, status, value);
      if (resume_count)
        (*resume_count)++;
      if (ret == Keystone::Error::Success &&
          *status == SBI_ERR_SM_ENCLAVE_SUCCESS)
        break;
      if (ret != Keystone::Error::EdgeCallHost &&
          ret != Keystone::Error::EnclaveInterrupted)
        break;
      ret = Keystone::Error::Success;
      continue;
    }

    if (*status == SBI_ERR_SM_ENCLAVE_INTERRUPTED) {
      ret = enter_slot_resume_once(enclave, status, value);
      if (resume_count)
        (*resume_count)++;
      if (ret == Keystone::Error::Success &&
          *status == SBI_ERR_SM_ENCLAVE_SUCCESS)
        break;
      if (ret != Keystone::Error::EnclaveInterrupted)
        break;
      ret = Keystone::Error::Success;
      continue;
    }

    break;
  }

  return ret;
}

static Keystone::Error
enter_slot_user_ocall_round_with_cap(Keystone::Enclave& enclave, const slot_cap_t& cap,
    uintptr_t* status, uintptr_t* value, uintptr_t* lease_id,
    uintptr_t* ocall_count, uintptr_t* resume_count)
{
  return enter_slot_user_ocall_round_with_cap_and_flags(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, status, value, lease_id,
      ocall_count, resume_count);
}

static Keystone::Error
enter_slot_user_ocall_round(Keystone::Enclave& enclave, uintptr_t slot_id,
    uintptr_t* status, uintptr_t* value, uintptr_t* lease_id,
    uintptr_t* ocall_count, uintptr_t* resume_count)
{
  slot_cap_t cap = make_enter_slot_test_cap(slot_id);

  Keystone::Error ret = mint_enter_slot_test_cap(enclave, &cap);
  if (ret != Keystone::Error::Success)
    return ret;

  return enter_slot_user_ocall_round_with_cap(
      enclave, cap, status, value, lease_id, ocall_count, resume_count);
}

static void*
enter_slot_ocall_worker(void* opaque) {
  enter_slot_ocall_worker_arg* arg = (enter_slot_ocall_worker_arg*)opaque;
  Keystone::Enclave enclave;
  uintptr_t lease_id = 0;

  arg->ret = Keystone::Error::DeviceError;
  arg->status = 0;
  arg->value = 0;
  arg->ocall_count = 0;
  arg->resume_count = 0;

  pthread_mutex_lock(&enter_slot_ocall_lock);

  if (enclave.init(arg->eapp_file, arg->rt_file, arg->ld_file, arg->params) !=
      Keystone::Error::Success) {
    pthread_mutex_unlock(&enter_slot_ocall_lock);
    return NULL;
  }

  edge_init(&enclave);

  arg->ret = enter_slot_user_ocall_round(enclave, arg->slot_id, &arg->status,
      &arg->value, &lease_id, &arg->ocall_count, &arg->resume_count);

  enclave.destroy();
  pthread_mutex_unlock(&enter_slot_ocall_lock);
  return NULL;
}

static int
run_enter_slot_lt_user_probe(const char* label, uintptr_t expected_value,
    uintptr_t expected_ocalls, uintptr_t expected_resumes, const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params) {
  pthread_t threads[enter_slot_pool_workers];
  enter_slot_ocall_worker_arg args[enter_slot_pool_workers];

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  printf("%s_worker,slot,status,value,ocalls,resumes\n", label);
  fflush(stdout);

  for (uintptr_t worker = 0; worker < enter_slot_pool_workers; worker++) {
    args[worker].eapp_file = eapp_file;
    args[worker].rt_file = rt_file;
    args[worker].ld_file = ld_file;
    args[worker].params = params;
    args[worker].slot_id = worker + 1;
    args[worker].ret = Keystone::Error::DeviceError;
    args[worker].status = 0;
    args[worker].value = 0;
    args[worker].ocall_count = 0;
    args[worker].resume_count = 0;

    if (pthread_create(&threads[worker], NULL, enter_slot_ocall_worker, &args[worker]) != 0) {
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
    printf("%s_worker,%lu,%lu,%lu,%lu,%lu\n", label,
        args[worker].slot_id, args[worker].status, args[worker].value,
        args[worker].ocall_count, args[worker].resume_count);
    if (expect_enter_slot_status("ENTER_SLOT LT user probe", args[worker].ret,
            args[worker].status, args[worker].value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
        expect_enter_slot_bench_value(label, worker, args[worker].value,
            expected_value)) {
      return 1;
    }
    if (args[worker].ocall_count != expected_ocalls ||
        args[worker].resume_count != expected_resumes) {
      printf("[FAIL] %s worker %lu returned unexpected ocall/resume counts (%lu/%lu != %lu/%lu)\n",
          label, worker, args[worker].ocall_count, args[worker].resume_count,
          expected_ocalls, expected_resumes);
      return 1;
    }
  }

  return 0;
}

static int
run_enter_slot_lt_user_ocall(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_lt_user_probe("lt_user_ocall",
      SLOTTEE_LT_USER_OCALL_MAGIC, 1, 1, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_user_ocall_same_enclave(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  Keystone::Enclave enclave;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t slot1_lease = 0;
  uintptr_t slot2_lease = 0;
  uintptr_t slot1_ocalls = 0;
  uintptr_t slot2_ocalls = 0;
  uintptr_t slot1_resumes = 0;
  uintptr_t slot2_resumes = 0;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT same-enclave LT user ocall failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("same_enclave_lt_user_ocall,slot,status,value,lease,ocalls,resumes\n");
  fflush(stdout);

  if (enter_slot_user_ocall_round(enclave, 1, &status, &value, &slot1_lease,
          &slot1_ocalls, &slot1_resumes) != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT same-enclave LT user ocall slot1",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("same_enclave_lt_user_ocall", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC)) {
    enclave.destroy();
    return 1;
  }
  printf("same_enclave_lt_user_ocall,1,%lu,%lu,%lu,%lu,%lu\n",
      status, value, slot1_lease, slot1_ocalls, slot1_resumes);
  fflush(stdout);

  status = 0;
  value = 0;
  if (enter_slot_user_ocall_round(enclave, 2, &status, &value, &slot2_lease,
          &slot2_ocalls, &slot2_resumes) != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT same-enclave LT user ocall slot2",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("same_enclave_lt_user_ocall", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC)) {
    enclave.destroy();
    return 1;
  }
  printf("same_enclave_lt_user_ocall,2,%lu,%lu,%lu,%lu,%lu\n",
      status, value, slot2_lease, slot2_ocalls, slot2_resumes);
  fflush(stdout);

  if (slot1_lease == 0 || slot2_lease == 0 || slot1_lease == slot2_lease) {
    printf("[FAIL] ENTER_SLOT same-enclave LT user ocall returned invalid lease ids (%lu, %lu)\n",
        slot1_lease, slot2_lease);
    enclave.destroy();
    return 1;
  }

  if (slot1_ocalls != 1 || slot2_ocalls != 1 ||
      slot1_resumes != 1 || slot2_resumes != 1) {
    printf("[FAIL] ENTER_SLOT same-enclave LT user ocall returned unexpected ocall/resume counts (%lu/%lu, %lu/%lu)\n",
        slot1_ocalls, slot1_resumes, slot2_ocalls, slot2_resumes);
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

static int
run_enter_slot_lt_user_illegal(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_lt_user_probe("lt_user_illegal",
      SLOTTEE_LT_USER_ILLEGAL_MAGIC, 0, 0, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_user_page_fault(const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  return run_enter_slot_lt_user_probe("lt_user_page_fault",
      SLOTTEE_LT_USER_PAGE_FAULT_MAGIC, 0, 0, eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_user_fault_cleanup_same_enclave(const char* label,
    uintptr_t expected_fault_value, const char* eapp_file, const char* rt_file,
    const char* ld_file, Keystone::Params params) {
  Keystone::Enclave enclave;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t fault_lease = 0;
  uintptr_t ocall_lease = 0;
  uintptr_t fault_ocalls = 0;
  uintptr_t fault_resumes = 0;
  uintptr_t ocall_ocalls = 0;
  uintptr_t ocall_resumes = 0;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT %s failed to init enclave\n", label);
    return 1;
  }

  edge_init(&enclave);

  printf("%s,slot,status,value,lease,ocalls,resumes\n", label);
  fflush(stdout);

  if (enter_slot_user_ocall_round(enclave, 1, &status, &value, &fault_lease,
          &fault_ocalls, &fault_resumes) != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT same-enclave LT user fault slot1",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value(label, 1, value, expected_fault_value)) {
    enclave.destroy();
    return 1;
  }
  printf("%s,1,%lu,%lu,%lu,%lu,%lu\n",
      label, status, value, fault_lease, fault_ocalls, fault_resumes);
  fflush(stdout);

  status = 0;
  value = 0;
  if (enter_slot_user_ocall_round(enclave, 2, &status, &value, &ocall_lease,
          &ocall_ocalls, &ocall_resumes) != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT same-enclave LT user cleanup slot2",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value(label, 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC)) {
    enclave.destroy();
    return 1;
  }
  printf("%s,2,%lu,%lu,%lu,%lu,%lu\n",
      label, status, value, ocall_lease, ocall_ocalls, ocall_resumes);
  fflush(stdout);

  if (fault_lease == 0 || ocall_lease == 0 || fault_lease == ocall_lease) {
    printf("[FAIL] ENTER_SLOT %s returned invalid lease ids (%lu, %lu)\n",
        label, fault_lease, ocall_lease);
    enclave.destroy();
    return 1;
  }

  if (fault_ocalls != 0 || ocall_ocalls != 1 || ocall_resumes != 1) {
    printf("[FAIL] ENTER_SLOT %s returned unexpected ocall/resume counts (%lu/%lu, %lu/%lu)\n",
        label, fault_ocalls, fault_resumes, ocall_ocalls, ocall_resumes);
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

static int
run_enter_slot_lt_user_illegal_cleanup_same_enclave(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params) {
  return run_enter_slot_lt_user_fault_cleanup_same_enclave(
      "same_enclave_lt_user_illegal_cleanup", SLOTTEE_LT_USER_ILLEGAL_MAGIC,
      eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_user_page_fault_cleanup_same_enclave(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params) {
  return run_enter_slot_lt_user_fault_cleanup_same_enclave(
      "same_enclave_lt_user_page_fault_cleanup", SLOTTEE_LT_USER_PAGE_FAULT_MAGIC,
      eapp_file, rt_file, ld_file, params);
}

static int
run_enter_slot_lt_user_destroy_after_reentry(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params) {
  Keystone::Enclave enclave;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t completed_lease = 0;
  uintptr_t pending_lease = 0;
  uintptr_t recreated_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT destroy-after-reentry failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("lt_user_destroy_after_reentry,phase,ret,status,value,lease,ocalls,resumes\n");
  fflush(stdout);

  ret = enter_slot_user_ocall_round(
      enclave, 1, &status, &value, &completed_lease, &ocalls, &resumes);
  printf("lt_user_destroy_after_reentry,completed,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, completed_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT destroy-after-reentry completed",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("lt_user_destroy_after_reentry", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      completed_lease == 0 || ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  status = 0;
  value = 0;
  ret = enter_slot_request_once(enclave, 2,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value, &pending_lease);
  printf("lt_user_destroy_after_reentry,pending_edgecall,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, pending_lease);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      status != SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST || pending_lease == 0) {
    printf("[FAIL] ENTER_SLOT destroy-after-reentry did not stop at edgecall boundary\n");
    enclave.destroy();
    return 1;
  }

  ret = enclave.destroy();
  printf("lt_user_destroy_after_reentry,destroy,%d,0,0,0,0,0\n", (int)ret);
  fflush(stdout);
  if (ret != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT destroy-after-reentry failed to destroy active slot enclave\n");
    return 1;
  }

  Keystone::Enclave recreated;
  if (recreated.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT destroy-after-reentry failed to recreate enclave\n");
    return 1;
  }

  edge_init(&recreated);
  status = 0;
  value = 0;
  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round(
      recreated, 1, &status, &value, &recreated_lease, &ocalls, &resumes);
  printf("lt_user_destroy_after_reentry,recreated,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, recreated_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT destroy-after-reentry recreated",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("lt_user_destroy_after_reentry", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      recreated_lease == 0 || ocalls != 1 || resumes != 1) {
    recreated.destroy();
    return 1;
  }

  recreated.destroy();
  return 0;
}

static int
run_enter_slot_lt_user_revoke_after_reentry(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params) {
  Keystone::Enclave enclave;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t reentry_lease = 0;
  uintptr_t reserved_lease = 0;
  uintptr_t replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  slot_cap_t cap;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT revoke-after-reentry failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("lt_user_revoke_after_reentry,phase,ret,status,value,lease,ocalls,resumes\n");
  fflush(stdout);

  ret = enter_slot_user_ocall_round(
      enclave, 1, &status, &value, &reentry_lease, &ocalls, &resumes);
  printf("lt_user_revoke_after_reentry,reentry,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, reentry_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT revoke-after-reentry initial",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("lt_user_revoke_after_reentry", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      reentry_lease == 0 || ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  cap = make_enter_slot_test_cap(2);
  cap.max_lease_cycles = SLOTTEE_TEST_MAX_LEASE_CYCLES;
  if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  status = 0;
  value = 0;
  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &reserved_lease);
  printf("lt_user_revoke_after_reentry,reserve,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, reserved_lease);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT revoke-after-reentry reserve", ret,
          status, value, SBI_ERR_SM_NOT_IMPLEMENTED) ||
      reserved_lease == 0) {
    enclave.destroy();
    return 1;
  }

  wait_for_enter_slot_ttl(SLOTTEE_TEST_MAX_LEASE_CYCLES * 32);

  status = 0;
  value = 0;
  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &replay_lease);
  printf("lt_user_revoke_after_reentry,replay,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, replay_lease);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT revoke-after-reentry replay", ret,
          status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    return 1;
  }

  cap = make_enter_slot_test_cap(2);
  cap.epoch = SLOTTEE_INITIAL_EPOCH + 1;
  if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  status = 0;
  value = 0;
  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round_with_cap(
      enclave, cap, &status, &value, &fresh_lease, &ocalls, &resumes);
  printf("lt_user_revoke_after_reentry,new_epoch_ocall,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT revoke-after-reentry new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("lt_user_revoke_after_reentry", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease == 0 || fresh_lease == reserved_lease ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

struct enter_slot_destroy_race_arg {
  Keystone::Enclave* enclave;
  pthread_mutex_t lock;
  pthread_cond_t cond;
  int edge_ready;
  Keystone::Error enter_ret;
  Keystone::Error destroy_ret;
  uintptr_t status;
  uintptr_t value;
  uintptr_t lease;
};

static void*
enter_slot_destroy_race_enter_worker(void* opaque)
{
  enter_slot_destroy_race_arg* arg = (enter_slot_destroy_race_arg*)opaque;

  arg->enter_ret = enter_slot_request_once(*arg->enclave, 2,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &arg->status, &arg->value,
      &arg->lease);

  pthread_mutex_lock(&arg->lock);
  arg->edge_ready = 1;
  pthread_cond_signal(&arg->cond);
  pthread_mutex_unlock(&arg->lock);

  return NULL;
}

static void*
enter_slot_destroy_race_destroy_worker(void* opaque)
{
  enter_slot_destroy_race_arg* arg = (enter_slot_destroy_race_arg*)opaque;

  pthread_mutex_lock(&arg->lock);
  while (!arg->edge_ready)
    pthread_cond_wait(&arg->cond, &arg->lock);
  pthread_mutex_unlock(&arg->lock);

  arg->destroy_ret = arg->enclave->destroy();
  return NULL;
}

static int
run_enter_slot_lt_user_destroy_race(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  Keystone::Enclave recreated;
  enter_slot_destroy_race_arg arg;
  pthread_t enter_thread;
  pthread_t destroy_thread;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT destroy race failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  memset(&arg, 0, sizeof(arg));
  arg.enclave = &enclave;
  arg.enter_ret = Keystone::Error::DeviceError;
  arg.destroy_ret = Keystone::Error::DeviceError;
  pthread_mutex_init(&arg.lock, NULL);
  pthread_cond_init(&arg.cond, NULL);

  printf("lt_user_destroy_race,phase,ret,status,value,lease,ocalls,resumes\n");
  fflush(stdout);

  if (pthread_create(&enter_thread, NULL,
          enter_slot_destroy_race_enter_worker, &arg) != 0 ||
      pthread_create(&destroy_thread, NULL,
          enter_slot_destroy_race_destroy_worker, &arg) != 0) {
    printf("[FAIL] ENTER_SLOT destroy race failed to create workers\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  if (pthread_join(enter_thread, NULL) != 0 ||
      pthread_join(destroy_thread, NULL) != 0) {
    printf("[FAIL] ENTER_SLOT destroy race failed to join workers\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  printf("lt_user_destroy_race,edge,%d,%lu,%lu,%lu,0,0\n",
      (int)arg.enter_ret, arg.status, arg.value, arg.lease);
  printf("lt_user_destroy_race,destroy,%d,0,0,0,0,0\n", (int)arg.destroy_ret);
  fflush(stdout);

  pthread_mutex_destroy(&arg.lock);
  pthread_cond_destroy(&arg.cond);

  if (arg.enter_ret != Keystone::Error::Success ||
      arg.status != SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST || arg.lease == 0 ||
      arg.destroy_ret != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT destroy race returned unexpected edge/destroy result\n");
    return 1;
  }

  if (recreated.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT destroy race failed to recreate enclave\n");
    return 1;
  }

  edge_init(&recreated);
  ret = enter_slot_user_ocall_round(
      recreated, 1, &status, &value, &lease, &ocalls, &resumes);
  printf("lt_user_destroy_race,recreated,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT destroy race recreated",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("lt_user_destroy_race", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      lease == 0 || ocalls != 1 || resumes != 1) {
    recreated.destroy();
    return 1;
  }

  recreated.destroy();
  return 0;
}

static int
run_enter_slot_double_enter_epoch_rollover(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  Keystone::Enclave recreated;
  slot_cap_t cap;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t lease = 0;
  uintptr_t reentry_lease = 0;
  uintptr_t reserved_lease = 0;
  uintptr_t duplicate_lease = 0;
  uintptr_t replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t recreated_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  uintptr_t epoch = SLOTTEE_INITIAL_EPOCH;
  uintptr_t rollover_ttl = SLOTTEE_TEST_MAX_LEASE_CYCLES * 1024 * 1024;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT double-enter epoch failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("double_enter_epoch_rollover,phase,ret,status,value,lease,ocalls,resumes\n");
  fflush(stdout);

  ret = enter_slot_user_ocall_round(
      enclave, 1, &status, &value, &reentry_lease, &ocalls, &resumes);
  printf("double_enter_epoch_rollover,reentry,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, reentry_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT double-enter initial",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("double_enter_epoch_rollover", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC)) {
    enclave.destroy();
    return 1;
  }

  cap = make_enter_slot_test_cap(2);
  cap.max_lease_cycles = rollover_ttl;
  if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &reserved_lease);
  printf("double_enter_epoch_rollover,reserve,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, reserved_lease);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT double-enter reserve", ret,
          status, value, SBI_ERR_SM_NOT_IMPLEMENTED) ||
      reserved_lease == 0) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &duplicate_lease);
  printf("double_enter_epoch_rollover,duplicate,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, duplicate_lease);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT double-enter duplicate", ret,
          status, value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
    enclave.destroy();
    return 1;
  }

  ret = enclave.markRevoke(2, &status, &epoch);
  printf("double_enter_epoch_rollover,rollover,%d,%lu,%lu,0,0,0\n",
      (int)ret, status, epoch);
  fflush(stdout);
  if (ret != Keystone::Error::Success || status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      epoch != SLOTTEE_INITIAL_EPOCH + 1) {
    printf("[FAIL] ENTER_SLOT double-enter epoch rollover failed to revoke busy slot\n");
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &replay_lease);
  printf("double_enter_epoch_rollover,replay,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, replay_lease);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT double-enter replay", ret,
          status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(2);
  fresh_cap.epoch = epoch;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round_with_cap(
      enclave, fresh_cap, &status, &value, &fresh_lease, &ocalls, &resumes);
  printf("double_enter_epoch_rollover,new_epoch,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT double-enter new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("double_enter_epoch_rollover", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease == 0 || fresh_lease == reserved_lease ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  if (enclave.destroy() != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT double-enter failed to destroy first enclave\n");
    return 1;
  }

  if (recreated.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT double-enter failed to recreate enclave\n");
    return 1;
  }

  edge_init(&recreated);
  ret = enter_slot_request_once_with_cap(recreated, fresh_cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  printf("double_enter_epoch_rollover,recreated_old_epoch,%d,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, lease);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT double-enter recreated old epoch", ret,
          status, value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    recreated.destroy();
    return 1;
  }

  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round(
      recreated, 1, &status, &value, &recreated_lease, &ocalls, &resumes);
  printf("double_enter_epoch_rollover,recreated_fresh,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, recreated_lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT double-enter recreated fresh",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("double_enter_epoch_rollover", 3, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      recreated_lease == 0 || ocalls != 1 || resumes != 1) {
    recreated.destroy();
    return 1;
  }

  recreated.destroy();
  return 0;
}

static int
run_enter_slot_mark_revoke(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  slot_cap_t old_cap;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t epoch = 0;
  uintptr_t lease = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  slottee_debug_resp_t debug_resp = {};
  Keystone::Error ret;
  Keystone::Error resume_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT mark revoke failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("mark_revoke,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  ret = enter_slot_user_ocall_round(
      enclave, 1, &status, &value, &lease, &ocalls, &resumes);
  printf("mark_revoke,reentry,%d,%lu,%lu,%lu,0,%lu,%lu\n",
      (int)ret, status, value, lease, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT mark revoke initial",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("mark_revoke", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC)) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once(enclave, 2,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value, &lease);
  printf("mark_revoke,edge,%d,%lu,%lu,%lu,0,0,0\n",
      (int)ret, status, value, lease);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      status != SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST || lease == 0) {
    printf("[FAIL] ENTER_SLOT mark revoke did not stop at edgecall boundary\n");
    enclave.destroy();
    return 1;
  }

  old_cap = make_enter_slot_test_cap(2);
  if (mint_enter_slot_test_cap(enclave, &old_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }

  ret = enclave.markRevoke(2, &status, &epoch);
  printf("mark_revoke,revoke,%d,%lu,0,0,%lu,0,0\n",
      (int)ret, status, epoch);
  fflush(stdout);
  if (ret != Keystone::Error::Success || status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      epoch != SLOTTEE_INITIAL_EPOCH + 1) {
    printf("[FAIL] ENTER_SLOT mark revoke returned unexpected epoch/status\n");
    enclave.destroy();
    return 1;
  }

  resume_ret = enclave.resume(&value);
  printf("mark_revoke,old_resume,%d,0,%lu,0,%lu,0,0\n",
      (int)resume_ret, value, epoch);
  fflush(stdout);
  if (resume_ret != Keystone::Error::EnclaveNotResumable) {
    printf("[FAIL] ENTER_SLOT mark revoke returned unexpected revoked slot resume status\n");
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, old_cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &old_replay_lease);
  printf("mark_revoke,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, old_replay_lease, epoch);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT mark revoke old cap", ret,
          status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(2);
  fresh_cap.epoch = epoch;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round_with_cap(
      enclave, fresh_cap, &status, &value, &fresh_lease, &ocalls, &resumes);
  printf("mark_revoke,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, epoch, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT mark revoke new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("mark_revoke", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease == 0 || fresh_lease == lease ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

static int
run_enter_slot_active_revoke_boundary(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  slot_cap_t old_cap;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t epoch = 0;
  uintptr_t baseline_lease = 0;
  uintptr_t pending_lease = 0;
  uintptr_t duplicate_lease = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;
  Keystone::Error resume_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT active revoke boundary failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("active_revoke_boundary,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  ret = enter_slot_user_ocall_round(
      enclave, 1, &status, &value, &baseline_lease, &ocalls, &resumes);
  printf("active_revoke_boundary,baseline,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, baseline_lease, SLOTTEE_INITIAL_EPOCH,
      ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT active revoke baseline",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("active_revoke_boundary", 1, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      baseline_lease == 0 || ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once(enclave, 2,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &pending_lease);
  printf("active_revoke_boundary,pending_edge,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, pending_lease, SLOTTEE_INITIAL_EPOCH);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      status != SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST || pending_lease == 0) {
    printf("[FAIL] ENTER_SLOT active revoke boundary did not stop at edgecall\n");
    enclave.destroy();
    return 1;
  }

  ret = enclave.markRevoke(2, &status, &epoch);
  printf("active_revoke_boundary,mark_pending,%d,%lu,0,0,%lu,0,0\n",
      (int)ret, status, epoch);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      epoch != SLOTTEE_INITIAL_EPOCH + 1) {
    printf("[FAIL] ENTER_SLOT active revoke boundary markRevoke returned unexpected projected epoch/status\n");
    enclave.destroy();
    return 1;
  }

  old_cap = make_enter_slot_test_cap(2);
  if (mint_enter_slot_test_cap(enclave, &old_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  ret = enter_slot_request_once_with_cap(enclave, old_cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &duplicate_lease);
  printf("active_revoke_boundary,pending_duplicate,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, duplicate_lease, SLOTTEE_INITIAL_EPOCH);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT active revoke pending duplicate", ret,
          status, value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
    enclave.destroy();
    return 1;
  }

  value = 0;
  resume_ret = enclave.resume(&value);
  printf("active_revoke_boundary,old_resume,%d,0,%lu,0,%lu,0,0\n",
      (int)resume_ret, value, epoch);
  fflush(stdout);
  if (resume_ret != Keystone::Error::EnclaveNotResumable) {
    printf("[FAIL] ENTER_SLOT active revoke boundary returned unexpected old resume status\n");
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, old_cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &old_replay_lease);
  printf("active_revoke_boundary,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, old_replay_lease, epoch);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT active revoke old cap", ret,
          status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(2);
  fresh_cap.epoch = epoch;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round_with_cap(
      enclave, fresh_cap, &status, &value, &fresh_lease, &ocalls, &resumes);
  printf("active_revoke_boundary,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, epoch, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT active revoke new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("active_revoke_boundary", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease == 0 || fresh_lease == pending_lease ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

struct enter_slot_active_revoke_timer_arg {
  Keystone::Enclave* enclave;
  slot_cap_t cap;
  uintptr_t slot_id;
  pthread_mutex_t lock;
  pthread_cond_t cond;
  int enter_started;
  int enter_done;
  int mark_done;
  int mark_failed;
  int destroy_after_mark;
  int destroy_done;
  int run_second_slot_after_mark;
  Keystone::Error enter_ret;
  Keystone::Error duplicate_ret;
  Keystone::Error mark_ret;
  Keystone::Error destroy_ret;
  Keystone::Error second_ret;
  Keystone::Error debug_before_second_ret;
  uintptr_t enter_flags;
  slot_cap_t second_cap;
  uintptr_t enter_status;
  uintptr_t enter_value;
  uintptr_t enter_lease;
  uintptr_t duplicate_status;
  uintptr_t duplicate_value;
  uintptr_t duplicate_lease;
  uintptr_t mark_status;
  uintptr_t mark_epoch;
  uintptr_t second_status;
  uintptr_t second_value;
  uintptr_t second_lease;
  uintptr_t second_ocalls;
  uintptr_t second_resumes;
  slottee_debug_resp_t debug_before_second;
};

static void*
enter_slot_active_revoke_timer_enter_worker(void* opaque)
{
  enter_slot_active_revoke_timer_arg* arg =
      (enter_slot_active_revoke_timer_arg*)opaque;

  pthread_mutex_lock(&arg->lock);
  arg->enter_started = 1;
  pthread_cond_broadcast(&arg->cond);
  pthread_mutex_unlock(&arg->lock);

  arg->enter_ret = enter_slot_request_once_with_cap(*arg->enclave, arg->cap,
      arg->enter_flags, &arg->enter_status, &arg->enter_value,
      &arg->enter_lease);

  pthread_mutex_lock(&arg->lock);
  arg->enter_done = 1;
  pthread_cond_broadcast(&arg->cond);
  pthread_mutex_unlock(&arg->lock);

  return NULL;
}

static void*
enter_slot_active_revoke_timer_mark_worker(void* opaque)
{
  enter_slot_active_revoke_timer_arg* arg =
      (enter_slot_active_revoke_timer_arg*)opaque;

  pthread_mutex_lock(&arg->lock);
  while (!arg->enter_started)
    pthread_cond_wait(&arg->cond, &arg->lock);
  pthread_mutex_unlock(&arg->lock);

  usleep(enter_slot_active_revoke_mark_delay_us);

  for (uintptr_t retry = 0; retry < enter_slot_active_revoke_probe_limit;
       retry++) {
    int enter_done;

    pthread_mutex_lock(&arg->lock);
    enter_done = arg->enter_done;
    pthread_mutex_unlock(&arg->lock);
    if (enter_done)
      break;

    if (arg->run_second_slot_after_mark) {
      slottee_debug_resp_t ready_resp = {};
      Keystone::Error ready_ret = slottee_debug_once(*arg->enclave,
          SLOTTEE_DEBUG_OP_REENTRY_STATUS, &ready_resp);

      if (ready_ret != Keystone::Error::Success ||
          ready_resp.status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
          ready_resp.reentry_ready != 1 ||
          ready_resp.n_thread != 1 ||
          ready_resp.busy_slots != 1) {
        sched_yield();
        continue;
      }

      usleep(enter_slot_active_revoke_ready_settle_us);
      pthread_mutex_lock(&arg->lock);
      enter_done = arg->enter_done;
      pthread_mutex_unlock(&arg->lock);
      if (enter_done)
        break;
    }

    arg->duplicate_ret = enter_slot_request_once_with_cap(*arg->enclave,
        arg->cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &arg->duplicate_status,
        &arg->duplicate_value, &arg->duplicate_lease);

    if (arg->duplicate_ret == Keystone::Error::Success &&
        arg->duplicate_status == SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT) {
      pthread_mutex_lock(&arg->lock);
      enter_done = arg->enter_done;
      pthread_mutex_unlock(&arg->lock);
      if (enter_done)
        break;

      arg->mark_ret = arg->enclave->markRevoke(arg->slot_id,
          &arg->mark_status, &arg->mark_epoch);
      if (arg->destroy_after_mark) {
        arg->destroy_ret = arg->enclave->destroy();
        arg->destroy_done = 1;
      }
      if (arg->run_second_slot_after_mark) {
        arg->debug_before_second_ret = slottee_debug_once(*arg->enclave,
            SLOTTEE_DEBUG_OP_REENTRY_STATUS, &arg->debug_before_second);
        arg->second_ret = enter_slot_user_ocall_round_with_cap(*arg->enclave,
            arg->second_cap, &arg->second_status, &arg->second_value,
            &arg->second_lease, &arg->second_ocalls, &arg->second_resumes);
      }

      pthread_mutex_lock(&arg->lock);
      arg->mark_done = 1;
      pthread_cond_broadcast(&arg->cond);
      pthread_mutex_unlock(&arg->lock);
      return NULL;
    }

    sched_yield();
  }

  pthread_mutex_lock(&arg->lock);
  arg->mark_failed = 1;
  pthread_cond_broadcast(&arg->cond);
  pthread_mutex_unlock(&arg->lock);
  return NULL;
}

static int
enter_slot_active_revoke_timer_run_workers(
    const char* label, enter_slot_active_revoke_timer_arg* arg)
{
  pthread_t enter_thread;
  pthread_t mark_thread;

  if (pthread_create(&enter_thread, NULL,
          enter_slot_active_revoke_timer_enter_worker, arg) != 0) {
    printf("[FAIL] %s failed to create enter worker\n", label);
    return 1;
  }

  if (pthread_create(&mark_thread, NULL,
          enter_slot_active_revoke_timer_mark_worker, arg) != 0) {
    printf("[FAIL] %s failed to create mark worker\n", label);
    pthread_join(enter_thread, NULL);
    return 1;
  }

  if (pthread_join(mark_thread, NULL) != 0 ||
      pthread_join(enter_thread, NULL) != 0) {
    printf("[FAIL] %s failed to join workers\n", label);
    return 1;
  }

  return 0;
}

static int
run_enter_slot_active_revoke_timer_stress(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t epoch = SLOTTEE_INITIAL_EPOCH;
  uintptr_t baseline_lease = 0;
  uintptr_t last_lease = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;
  Keystone::Error resume_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT active revoke timer stress failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("active_revoke_timer_stress,round,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  ret = enter_slot_user_ocall_round(
      enclave, 1, &status, &value, &baseline_lease, &ocalls, &resumes);
  printf("active_revoke_timer_stress,0,baseline,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, baseline_lease, epoch, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT active revoke timer baseline",
          Keystone::Error::Success, status, value,
          SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("active_revoke_timer_stress", 0,
          value, SLOTTEE_LT_USER_OCALL_MAGIC) ||
      baseline_lease == 0 || ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }
  last_lease = baseline_lease;

  for (uintptr_t round = 1; round <= enter_slot_active_revoke_timer_rounds;
       round++) {
    enter_slot_active_revoke_timer_arg arg;
    pthread_t enter_thread;
    pthread_t mark_thread;
    slot_cap_t fresh_cap;

    memset(&arg, 0, sizeof(arg));
    arg.enclave = &enclave;
    arg.slot_id = 2;
    arg.cap = make_enter_slot_test_cap(arg.slot_id);
    arg.cap.epoch = epoch;
    if (mint_enter_slot_test_cap(enclave, &arg.cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }
    arg.enter_flags = SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL;
    arg.enter_ret = Keystone::Error::DeviceError;
    arg.duplicate_ret = Keystone::Error::DeviceError;
    arg.mark_ret = Keystone::Error::DeviceError;
    arg.destroy_ret = Keystone::Error::DeviceError;
    pthread_mutex_init(&arg.lock, NULL);
    pthread_cond_init(&arg.cond, NULL);

    if (pthread_create(&enter_thread, NULL,
            enter_slot_active_revoke_timer_enter_worker, &arg) != 0) {
      printf("[FAIL] ENTER_SLOT active revoke timer stress failed to create enter worker\n");
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    if (pthread_create(&mark_thread, NULL,
            enter_slot_active_revoke_timer_mark_worker, &arg) != 0) {
      printf("[FAIL] ENTER_SLOT active revoke timer stress failed to create mark worker\n");
      pthread_join(enter_thread, NULL);
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    if (pthread_join(mark_thread, NULL) != 0 ||
        pthread_join(enter_thread, NULL) != 0) {
      printf("[FAIL] ENTER_SLOT active revoke timer stress failed to join workers\n");
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    printf("active_revoke_timer_stress,%lu,duplicate_probe,%d,%lu,%lu,%lu,%lu,0,0\n",
        round, (int)arg.duplicate_ret, arg.duplicate_status,
        arg.duplicate_value, arg.duplicate_lease, epoch);
    printf("active_revoke_timer_stress,%lu,mark_pending,%d,%lu,0,0,%lu,0,0\n",
        round, (int)arg.mark_ret, arg.mark_status, arg.mark_epoch);
    printf("active_revoke_timer_stress,%lu,active_interrupt,%d,%lu,%lu,%lu,%lu,0,0\n",
        round, (int)arg.enter_ret, arg.enter_status, arg.enter_value,
        arg.enter_lease, epoch);
    fflush(stdout);

    if (arg.mark_failed || !arg.mark_done ||
        arg.duplicate_ret != Keystone::Error::Success ||
        arg.duplicate_status != SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT ||
        arg.mark_ret != Keystone::Error::Success ||
        arg.mark_status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
        arg.mark_epoch != epoch + 1 ||
        arg.enter_ret != Keystone::Error::Success ||
        arg.enter_status != SBI_ERR_SM_ENCLAVE_INTERRUPTED ||
        arg.enter_lease <= last_lease) {
      printf("[FAIL] ENTER_SLOT active revoke timer stress failed active round %lu\n",
          round);
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    value = 0;
    resume_ret = enclave.resume(&value);
    printf("active_revoke_timer_stress,%lu,old_resume,%d,0,%lu,0,%lu,0,0\n",
        round, (int)resume_ret, value, arg.mark_epoch);
    fflush(stdout);
    if (resume_ret != Keystone::Error::EnclaveNotResumable) {
      printf("[FAIL] ENTER_SLOT active revoke timer stress returned unexpected old resume status round %lu\n",
          round);
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    ret = enter_slot_request_once_with_cap(enclave, arg.cap,
        SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
        &old_replay_lease);
    printf("active_revoke_timer_stress,%lu,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
        round, (int)ret, status, value, old_replay_lease, arg.mark_epoch);
    fflush(stdout);
    if (expect_enter_slot_status("ENTER_SLOT active revoke timer old cap", ret,
            status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    fresh_cap = make_enter_slot_test_cap(arg.slot_id);
    fresh_cap.epoch = arg.mark_epoch;
    if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }
    ocalls = 0;
    resumes = 0;
    ret = enter_slot_user_ocall_round_with_cap(enclave, fresh_cap,
        &status, &value, &fresh_lease, &ocalls, &resumes);
    printf("active_revoke_timer_stress,%lu,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
        round, (int)ret, status, value, fresh_lease, fresh_cap.epoch,
        ocalls, resumes);
    fflush(stdout);
    if (ret != Keystone::Error::Success ||
        expect_enter_slot_status("ENTER_SLOT active revoke timer new epoch",
            Keystone::Error::Success, status, value,
            SBI_ERR_SM_ENCLAVE_SUCCESS) ||
        expect_enter_slot_bench_value("active_revoke_timer_stress", round,
            value, SLOTTEE_LT_USER_OCALL_MAGIC) ||
        fresh_lease <= arg.enter_lease ||
        fresh_lease <= last_lease ||
        ocalls != 1 || resumes != 1) {
      printf("[FAIL] ENTER_SLOT active revoke timer stress new epoch failed round %lu\n",
          round);
      enclave.destroy();
      pthread_mutex_destroy(&arg.lock);
      pthread_cond_destroy(&arg.cond);
      return 1;
    }

    epoch = fresh_cap.epoch;
    last_lease = fresh_lease;
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
  }

  enclave.destroy();
  return 0;
}

static int
run_enter_slot_first_active_revoke_template(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  enter_slot_active_revoke_timer_arg arg;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  slottee_debug_resp_t debug_resp = {};
  Keystone::Error ret;
  Keystone::Error resume_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT first active revoke template failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);
  memset(&arg, 0, sizeof(arg));
  arg.enclave = &enclave;
  arg.slot_id = 2;
  arg.cap = make_enter_slot_test_cap(arg.slot_id);
  if (mint_enter_slot_test_cap(enclave, &arg.cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  arg.enter_flags = SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL;
  arg.enter_ret = Keystone::Error::DeviceError;
  arg.duplicate_ret = Keystone::Error::DeviceError;
  arg.mark_ret = Keystone::Error::DeviceError;
  arg.destroy_ret = Keystone::Error::DeviceError;
  pthread_mutex_init(&arg.lock, NULL);
  pthread_cond_init(&arg.cond, NULL);

  printf("first_active_revoke_template,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  if (enter_slot_active_revoke_timer_run_workers(
          "ENTER_SLOT first active revoke template", &arg)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  printf("first_active_revoke_template,duplicate_probe,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.duplicate_ret, arg.duplicate_status, arg.duplicate_value,
      arg.duplicate_lease, SLOTTEE_INITIAL_EPOCH);
  printf("first_active_revoke_template,mark_pending,%d,%lu,0,0,%lu,0,0\n",
      (int)arg.mark_ret, arg.mark_status, arg.mark_epoch);
  printf("first_active_revoke_template,active_interrupt,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.enter_ret, arg.enter_status, arg.enter_value,
      arg.enter_lease, SLOTTEE_INITIAL_EPOCH);
  fflush(stdout);

  if (arg.mark_failed || !arg.mark_done ||
      arg.duplicate_ret != Keystone::Error::Success ||
      arg.duplicate_status != SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT ||
      arg.mark_ret != Keystone::Error::Success ||
      arg.mark_status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      arg.mark_epoch != SLOTTEE_INITIAL_EPOCH + 1 ||
      arg.enter_ret != Keystone::Error::Success ||
      arg.enter_status != SBI_ERR_SM_ENCLAVE_INTERRUPTED ||
      arg.enter_lease == 0) {
    printf("[FAIL] ENTER_SLOT first active revoke template failed active round\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = slottee_debug_once(enclave, SLOTTEE_DEBUG_OP_REENTRY_STATUS,
      &debug_resp);
  if (expect_slottee_debug_row("first_active_revoke_template",
          "debug_after_interrupt", ret, debug_resp, 1, arg.mark_epoch, 0, 0)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  value = 0;
  resume_ret = enclave.resume(&value);
  printf("first_active_revoke_template,old_resume,%d,0,%lu,0,%lu,0,0\n",
      (int)resume_ret, value, arg.mark_epoch);
  fflush(stdout);
  if (resume_ret != Keystone::Error::EnclaveNotResumable) {
    printf("[FAIL] ENTER_SLOT first active revoke template returned unexpected old resume status\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, arg.cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &old_replay_lease);
  printf("first_active_revoke_template,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, old_replay_lease, arg.mark_epoch);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT first active revoke template old cap",
          ret, status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(arg.slot_id);
  fresh_cap.epoch = arg.mark_epoch;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }
  ret = enter_slot_user_ocall_round_with_cap(enclave, fresh_cap,
      &status, &value, &fresh_lease, &ocalls, &resumes);
  printf("first_active_revoke_template,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, fresh_cap.epoch, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT first active revoke template new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("first_active_revoke_template", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease <= arg.enter_lease || ocalls != 1 || resumes != 1) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = slottee_debug_once(enclave, SLOTTEE_DEBUG_OP_REENTRY_STATUS,
      &debug_resp);
  if (expect_slottee_debug_row("first_active_revoke_template",
          "debug_after_new_epoch", ret, debug_resp, 1, fresh_cap.epoch, 0, 0)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  enclave.destroy();
  pthread_mutex_destroy(&arg.lock);
  pthread_cond_destroy(&arg.cond);
  return 0;
}

static int
run_enter_slot_first_active_revoke_diagnostic(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  enter_slot_active_revoke_timer_arg arg;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  slottee_debug_resp_t debug_resp = {};
  Keystone::Error ret;
  Keystone::Error resume_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT first active revoke diagnostic failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);
  memset(&arg, 0, sizeof(arg));
  arg.enclave = &enclave;
  arg.slot_id = 2;
  arg.cap = make_enter_slot_test_cap(arg.slot_id);
  if (mint_enter_slot_test_cap(enclave, &arg.cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  arg.enter_flags = SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL;
  arg.enter_ret = Keystone::Error::DeviceError;
  arg.duplicate_ret = Keystone::Error::DeviceError;
  arg.mark_ret = Keystone::Error::DeviceError;
  arg.destroy_ret = Keystone::Error::DeviceError;
  pthread_mutex_init(&arg.lock, NULL);
  pthread_cond_init(&arg.cond, NULL);

  printf("first_active_revoke_diagnostic,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  if (enter_slot_active_revoke_timer_run_workers(
          "ENTER_SLOT first active revoke diagnostic", &arg)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  printf("first_active_revoke_diagnostic,duplicate_probe,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.duplicate_ret, arg.duplicate_status, arg.duplicate_value,
      arg.duplicate_lease, SLOTTEE_INITIAL_EPOCH);
  printf("first_active_revoke_diagnostic,mark_pending,%d,%lu,0,0,%lu,0,0\n",
      (int)arg.mark_ret, arg.mark_status, arg.mark_epoch);
  printf("first_active_revoke_diagnostic,active_interrupt,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.enter_ret, arg.enter_status, arg.enter_value,
      arg.enter_lease, SLOTTEE_INITIAL_EPOCH);
  fflush(stdout);

  if (arg.mark_failed || !arg.mark_done ||
      arg.duplicate_ret != Keystone::Error::Success ||
      arg.duplicate_status != SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT ||
      arg.mark_ret != Keystone::Error::Success ||
      arg.mark_status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      arg.mark_epoch != SLOTTEE_INITIAL_EPOCH + 1 ||
      arg.enter_ret != Keystone::Error::Success ||
      arg.enter_status != SBI_ERR_SM_ENCLAVE_INTERRUPTED ||
      arg.enter_lease == 0) {
    printf("[FAIL] ENTER_SLOT first active revoke diagnostic failed active round\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = slottee_debug_once(enclave, SLOTTEE_DEBUG_OP_REENTRY_STATUS,
      &debug_resp);
  if (expect_slottee_debug_row("first_active_revoke_diagnostic",
          "debug_before_clear", ret, debug_resp, 1, arg.mark_epoch, 0, 0)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = slottee_debug_once(enclave, SLOTTEE_DEBUG_OP_REENTRY_CLEAR,
      &debug_resp);
  if (expect_slottee_debug_row("first_active_revoke_diagnostic",
          "debug_after_clear", ret, debug_resp, 0, arg.mark_epoch, 0, 0)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  value = 0;
  resume_ret = enclave.resume(&value);
  printf("first_active_revoke_diagnostic,old_resume,%d,0,%lu,0,%lu,0,0\n",
      (int)resume_ret, value, arg.mark_epoch);
  fflush(stdout);
  if (resume_ret != Keystone::Error::EnclaveNotResumable) {
    printf("[FAIL] ENTER_SLOT first active revoke diagnostic returned unexpected old resume status\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, arg.cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &old_replay_lease);
  printf("first_active_revoke_diagnostic,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, old_replay_lease, arg.mark_epoch);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT first active revoke diagnostic old cap",
          ret, status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(arg.slot_id);
  fresh_cap.epoch = arg.mark_epoch;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }
  ret = enter_slot_request_once_with_cap(enclave, fresh_cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &fresh_lease);
  printf("first_active_revoke_diagnostic,new_epoch_no_template,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, fresh_lease, fresh_cap.epoch);
  fflush(stdout);
  if (expect_enter_slot_status(
          "ENTER_SLOT first active revoke diagnostic new epoch without template",
          ret, status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  enclave.destroy();
  pthread_mutex_destroy(&arg.lock);
  pthread_cond_destroy(&arg.cond);
  return 0;
}

static int
run_enter_slot_active_revoke_destroy_race(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  enter_slot_active_revoke_timer_arg arg;
  uintptr_t value = 0;
  Keystone::Error resume_ret;
  Keystone::Error final_destroy_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT active revoke destroy race failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);
  memset(&arg, 0, sizeof(arg));
  arg.enclave = &enclave;
  arg.slot_id = 2;
  arg.cap = make_enter_slot_test_cap(arg.slot_id);
  if (mint_enter_slot_test_cap(enclave, &arg.cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  arg.enter_flags = SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL;
  arg.destroy_after_mark = 1;
  arg.enter_ret = Keystone::Error::DeviceError;
  arg.duplicate_ret = Keystone::Error::DeviceError;
  arg.mark_ret = Keystone::Error::DeviceError;
  arg.destroy_ret = Keystone::Error::DeviceError;
  pthread_mutex_init(&arg.lock, NULL);
  pthread_cond_init(&arg.cond, NULL);

  printf("active_revoke_destroy_race,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  if (enter_slot_active_revoke_timer_run_workers(
          "ENTER_SLOT active revoke destroy race", &arg)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  printf("active_revoke_destroy_race,duplicate_probe,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.duplicate_ret, arg.duplicate_status, arg.duplicate_value,
      arg.duplicate_lease, SLOTTEE_INITIAL_EPOCH);
  printf("active_revoke_destroy_race,mark_pending,%d,%lu,0,0,%lu,0,0\n",
      (int)arg.mark_ret, arg.mark_status, arg.mark_epoch);
  printf("active_revoke_destroy_race,destroy_while_running,%d,0,0,0,%lu,0,0\n",
      (int)arg.destroy_ret, arg.mark_epoch);
  printf("active_revoke_destroy_race,active_interrupt,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.enter_ret, arg.enter_status, arg.enter_value,
      arg.enter_lease, SLOTTEE_INITIAL_EPOCH);
  fflush(stdout);

  if (arg.mark_failed || !arg.mark_done || !arg.destroy_done ||
      arg.duplicate_ret != Keystone::Error::Success ||
      arg.duplicate_status != SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT ||
      arg.mark_ret != Keystone::Error::Success ||
      arg.mark_status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      arg.mark_epoch != SLOTTEE_INITIAL_EPOCH + 1 ||
      arg.destroy_ret == Keystone::Error::Success ||
      arg.enter_ret != Keystone::Error::Success ||
      arg.enter_status != SBI_ERR_SM_ENCLAVE_INTERRUPTED ||
      arg.enter_lease == 0) {
    printf("[FAIL] ENTER_SLOT active revoke destroy race returned unexpected active result\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  resume_ret = enclave.resume(&value);
  printf("active_revoke_destroy_race,old_resume,%d,0,%lu,0,%lu,0,0\n",
      (int)resume_ret, value, arg.mark_epoch);
  fflush(stdout);
  if (resume_ret != Keystone::Error::EnclaveNotResumable) {
    printf("[FAIL] ENTER_SLOT active revoke destroy race returned unexpected old resume status\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  final_destroy_ret = enclave.destroy();
  printf("active_revoke_destroy_race,final_destroy,%d,0,0,0,%lu,0,0\n",
      (int)final_destroy_ret, arg.mark_epoch);
  fflush(stdout);
  if (final_destroy_ret != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT active revoke destroy race failed final destroy\n");
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  pthread_mutex_destroy(&arg.lock);
  pthread_cond_destroy(&arg.cond);
  return 0;
}

static int
run_enter_slot_active_revoke_multislot_stress(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  enter_slot_active_revoke_timer_arg arg;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  slottee_debug_resp_t debug_resp = {};
  Keystone::Error ret;
  Keystone::Error resume_ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT active revoke multislot stress failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);
  memset(&arg, 0, sizeof(arg));
  arg.enclave = &enclave;
  arg.slot_id = 2;
  arg.cap = make_enter_slot_test_cap(arg.slot_id);
  if (mint_enter_slot_test_cap(enclave, &arg.cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  arg.enter_flags = SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL;
  arg.run_second_slot_after_mark = 1;
  arg.second_cap = make_enter_slot_test_cap(3);
  if (mint_enter_slot_test_cap(enclave, &arg.second_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  arg.enter_ret = Keystone::Error::DeviceError;
  arg.duplicate_ret = Keystone::Error::DeviceError;
  arg.mark_ret = Keystone::Error::DeviceError;
  arg.destroy_ret = Keystone::Error::DeviceError;
  arg.second_ret = Keystone::Error::DeviceError;
  arg.debug_before_second_ret = Keystone::Error::DeviceError;
  pthread_mutex_init(&arg.lock, NULL);
  pthread_cond_init(&arg.cond, NULL);

  printf("active_revoke_multislot_stress,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  if (enter_slot_active_revoke_timer_run_workers(
          "ENTER_SLOT active revoke multislot stress", &arg)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  printf("active_revoke_multislot_stress,duplicate_probe,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.duplicate_ret, arg.duplicate_status, arg.duplicate_value,
      arg.duplicate_lease, SLOTTEE_INITIAL_EPOCH);
  printf("active_revoke_multislot_stress,mark_pending,%d,%lu,0,0,%lu,0,0\n",
      (int)arg.mark_ret, arg.mark_status, arg.mark_epoch);
  printf("active_revoke_multislot_stress,debug_before_second,%d,%lu,%lu,%lu,%lu,%lu\n",
      (int)arg.debug_before_second_ret, arg.debug_before_second.status,
      arg.debug_before_second.reentry_ready, arg.debug_before_second.epoch,
      arg.debug_before_second.n_thread, arg.debug_before_second.busy_slots);
  printf("active_revoke_multislot_stress,slot3_ocall,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)arg.second_ret, arg.second_status, arg.second_value,
      arg.second_lease, SLOTTEE_INITIAL_EPOCH, arg.second_ocalls,
      arg.second_resumes);
  printf("active_revoke_multislot_stress,slot2_interrupt,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)arg.enter_ret, arg.enter_status, arg.enter_value,
      arg.enter_lease, SLOTTEE_INITIAL_EPOCH);
  fflush(stdout);

  if (arg.mark_failed || !arg.mark_done ||
      arg.duplicate_ret != Keystone::Error::Success ||
      arg.duplicate_status != SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT ||
      arg.mark_ret != Keystone::Error::Success ||
      arg.mark_status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      arg.mark_epoch != SLOTTEE_INITIAL_EPOCH + 1 ||
      arg.debug_before_second_ret != Keystone::Error::Success ||
      arg.debug_before_second.status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      arg.debug_before_second.reentry_ready != 1 ||
      arg.debug_before_second.epoch != SLOTTEE_INITIAL_EPOCH ||
      arg.debug_before_second.n_thread != 1 ||
      arg.debug_before_second.busy_slots != 1 ||
      arg.second_ret != Keystone::Error::Success ||
      arg.second_status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      arg.second_value != SLOTTEE_LT_USER_OCALL_MAGIC ||
      arg.second_lease == 0 || arg.second_lease == arg.enter_lease ||
      arg.second_ocalls != 1 || arg.second_resumes != 1 ||
      arg.enter_ret != Keystone::Error::Success ||
      arg.enter_status != SBI_ERR_SM_ENCLAVE_INTERRUPTED ||
      arg.enter_lease == 0) {
    printf("[FAIL] ENTER_SLOT active revoke multislot stress returned unexpected active result\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = slottee_debug_once(enclave, SLOTTEE_DEBUG_OP_REENTRY_STATUS,
      &debug_resp);
  if (expect_slottee_debug_row("active_revoke_multislot_stress",
          "debug_after_interleave", ret, debug_resp, 1, arg.mark_epoch, 0, 0)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  value = 0;
  resume_ret = enclave.resume(&value);
  printf("active_revoke_multislot_stress,old_resume,%d,0,%lu,0,%lu,0,0\n",
      (int)resume_ret, value, arg.mark_epoch);
  fflush(stdout);
  if (resume_ret != Keystone::Error::EnclaveNotResumable) {
    printf("[FAIL] ENTER_SLOT active revoke multislot stress returned unexpected old resume status\n");
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, arg.cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value,
      &old_replay_lease);
  printf("active_revoke_multislot_stress,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, old_replay_lease, arg.mark_epoch);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT active revoke multislot old cap",
          ret, status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(arg.slot_id);
  fresh_cap.epoch = arg.mark_epoch;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }
  ret = enter_slot_user_ocall_round_with_cap(enclave, fresh_cap,
      &status, &value, &fresh_lease, &ocalls, &resumes);
  printf("active_revoke_multislot_stress,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, fresh_cap.epoch, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT active revoke multislot new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("active_revoke_multislot_stress", 1,
          value, SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease <= arg.second_lease || fresh_lease <= arg.enter_lease ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    pthread_mutex_destroy(&arg.lock);
    pthread_cond_destroy(&arg.cond);
    return 1;
  }

  enclave.destroy();
  pthread_mutex_destroy(&arg.lock);
  pthread_cond_destroy(&arg.cond);
  return 0;
}

static int
run_enter_slot_rt_revoke_fault(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  slot_cap_t old_cap;
  slot_cap_t fresh_cap;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t fault_lease = 0;
  uintptr_t old_replay_lease = 0;
  uintptr_t fresh_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT RT revoke fault failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("rt_revoke_fault,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  old_cap = make_enter_slot_test_cap(1);
  if (mint_enter_slot_test_cap(enclave, &old_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once(enclave, 1,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT, &status, &value,
      &fault_lease);
  printf("rt_revoke_fault,fault,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, fault_lease, SLOTTEE_INITIAL_EPOCH + 1);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT RT revoke fault",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("rt_revoke_fault", 1, value,
          SLOTTEE_LT_USER_PAGE_FAULT_MAGIC) ||
      fault_lease == 0) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, old_cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT, &status, &value,
      &old_replay_lease);
  printf("rt_revoke_fault,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, old_replay_lease, SLOTTEE_INITIAL_EPOCH + 1);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT RT revoke fault old cap", ret,
          status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    return 1;
  }

  fresh_cap = make_enter_slot_test_cap(1);
  fresh_cap.epoch = SLOTTEE_INITIAL_EPOCH + 1;
  if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }
  ret = enter_slot_user_ocall_round_with_cap_and_flags(enclave, fresh_cap,
      SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT, &status, &value,
      &fresh_lease, &ocalls, &resumes);
  printf("rt_revoke_fault,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, fresh_lease, fresh_cap.epoch, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT RT revoke fault new epoch",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("rt_revoke_fault", 2, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      fresh_lease == 0 || fresh_lease == fault_lease ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

static int
run_enter_slot_revoke_stress(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  Keystone::Enclave recreated;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t epoch = SLOTTEE_INITIAL_EPOCH;
  uintptr_t last_lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  uintptr_t long_ttl = SLOTTEE_TEST_MAX_LEASE_CYCLES * 1024 * 1024;
  slot_cap_t stale_after_recreate_cap = {};
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT revoke stress failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("revoke_stress,round,phase,ret,status,value,lease,epoch,ocalls,resumes\n");
  fflush(stdout);

  for (uintptr_t round = 1; round <= enter_slot_revoke_stress_rounds; round++) {
    slot_cap_t cap = make_enter_slot_test_cap(2);
    slot_cap_t fresh_cap;
    uintptr_t reserved_lease = 0;
    uintptr_t duplicate_lease = 0;
    uintptr_t replay_lease = 0;
    uintptr_t fresh_lease = 0;

    cap.epoch = epoch;
    cap.max_lease_cycles = long_ttl;
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }

    ret = enter_slot_request_once_with_cap(enclave, cap,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &reserved_lease);
    printf("revoke_stress,%lu,reserve,%d,%lu,%lu,%lu,%lu,0,0\n",
        round, (int)ret, status, value, reserved_lease, epoch);
    fflush(stdout);
    if (expect_enter_slot_status("ENTER_SLOT revoke stress reserve", ret,
            status, value, SBI_ERR_SM_NOT_IMPLEMENTED) ||
        reserved_lease <= last_lease) {
      printf("[FAIL] ENTER_SLOT revoke stress reserve lease did not grow (%lu <= %lu)\n",
          reserved_lease, last_lease);
      enclave.destroy();
      return 1;
    }

    ret = enter_slot_request_once_with_cap(enclave, cap,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &duplicate_lease);
    printf("revoke_stress,%lu,duplicate,%d,%lu,%lu,%lu,%lu,0,0\n",
        round, (int)ret, status, value, duplicate_lease, epoch);
    fflush(stdout);
    if (expect_enter_slot_status("ENTER_SLOT revoke stress duplicate", ret,
            status, value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      enclave.destroy();
      return 1;
    }

    ret = enclave.markRevoke(2, &status, &epoch);
    printf("revoke_stress,%lu,mark_revoke,%d,%lu,0,0,%lu,0,0\n",
        round, (int)ret, status, epoch);
    fflush(stdout);
    if (ret != Keystone::Error::Success ||
        status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
        epoch != SLOTTEE_INITIAL_EPOCH + round) {
      printf("[FAIL] ENTER_SLOT revoke stress markRevoke returned unexpected epoch/status\n");
      enclave.destroy();
      return 1;
    }

    ret = enter_slot_request_once_with_cap(enclave, cap,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &replay_lease);
    printf("revoke_stress,%lu,old_cap,%d,%lu,%lu,%lu,%lu,0,0\n",
        round, (int)ret, status, value, replay_lease, epoch);
    fflush(stdout);
    if (expect_enter_slot_status("ENTER_SLOT revoke stress old cap", ret,
            status, value, SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
      enclave.destroy();
      return 1;
    }

    fresh_cap = make_enter_slot_test_cap(2);
    fresh_cap.epoch = epoch;
    if (mint_enter_slot_test_cap(enclave, &fresh_cap) != Keystone::Error::Success) {
      enclave.destroy();
      return 1;
    }
    ret = enter_slot_user_ocall_round_with_cap(enclave, fresh_cap,
        &status, &value, &fresh_lease, &ocalls, &resumes);
    printf("revoke_stress,%lu,new_epoch,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
        round, (int)ret, status, value, fresh_lease, epoch, ocalls, resumes);
    fflush(stdout);
    if (ret != Keystone::Error::Success ||
        expect_enter_slot_status("ENTER_SLOT revoke stress new epoch",
            Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
        expect_enter_slot_bench_value("revoke_stress", round, value,
            SLOTTEE_LT_USER_OCALL_MAGIC) ||
        fresh_lease <= reserved_lease ||
        ocalls != 1 || resumes != 1) {
      printf("[FAIL] ENTER_SLOT revoke stress new epoch failed round %lu\n", round);
      enclave.destroy();
      return 1;
    }

    last_lease = fresh_lease;
    stale_after_recreate_cap = fresh_cap;
  }

  if (enclave.destroy() != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT revoke stress failed to destroy stressed enclave\n");
    return 1;
  }

  if (recreated.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT revoke stress failed to recreate enclave\n");
    return 1;
  }

  edge_init(&recreated);
  ret = enter_slot_request_once_with_cap(recreated, stale_after_recreate_cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &last_lease);
  printf("revoke_stress,0,recreated_old_epoch,%d,%lu,%lu,%lu,%lu,0,0\n",
      (int)ret, status, value, last_lease, stale_after_recreate_cap.epoch);
  fflush(stdout);
  if (expect_enter_slot_status("ENTER_SLOT revoke stress recreated old epoch", ret,
          status, value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    recreated.destroy();
    return 1;
  }

  ocalls = 0;
  resumes = 0;
  ret = enter_slot_user_ocall_round(
      recreated, 1, &status, &value, &last_lease, &ocalls, &resumes);
  printf("revoke_stress,0,recreated_fresh,%d,%lu,%lu,%lu,%lu,%lu,%lu\n",
      (int)ret, status, value, last_lease, SLOTTEE_INITIAL_EPOCH, ocalls, resumes);
  fflush(stdout);
  if (ret != Keystone::Error::Success ||
      expect_enter_slot_status("ENTER_SLOT revoke stress recreated fresh",
          Keystone::Error::Success, status, value, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      expect_enter_slot_bench_value("revoke_stress", 0, value,
          SLOTTEE_LT_USER_OCALL_MAGIC) ||
      last_lease == 0 || ocalls != 1 || resumes != 1) {
    recreated.destroy();
    return 1;
  }

  recreated.destroy();
  return 0;
}

static int
expect_cap_mac_forge_row(const char* phase, Keystone::Error ret, uintptr_t status,
    uintptr_t value, uintptr_t lease, uintptr_t epoch, uintptr_t cap_key_ready,
    uintptr_t ocalls, uintptr_t resumes, uintptr_t expected_status)
{
  printf("cap_mac_forge,%s,%d,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
      phase, (int)ret, status, value, lease, epoch, cap_key_ready, ocalls,
      resumes);
  fflush(stdout);

  if (ret != Keystone::Error::Success || status != expected_status) {
    printf("[FAIL] cap_mac_forge %s returned unexpected ret/status\n", phase);
    return 1;
  }

  return 0;
}

static int
run_enter_slot_cap_mac_forge(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  Keystone::Enclave cross_enclave;
  slottee_debug_resp_t debug_resp = {};
  slot_cap_t cap;
  slot_cap_t tampered;
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT cap MAC forge failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);

  printf("cap_mac_forge,phase,ret,status,value,lease,epoch,cap_key_ready,ocalls,resumes\n");
  fflush(stdout);

  ret = slottee_debug_once(enclave, SLOTTEE_DEBUG_OP_CAP_KEY_STATUS,
      &debug_resp);
  if (expect_cap_mac_forge_row("cap_key_status", ret, debug_resp.status, 0, 0,
          debug_resp.epoch, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      debug_resp.cap_key_ready != 1) {
    enclave.destroy();
    return 1;
  }

  cap = make_enter_slot_test_cap(1);
  if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_user_ocall_round_with_cap(enclave, cap, &status, &value,
      &lease, &ocalls, &resumes);
  if (expect_cap_mac_forge_row("valid", ret, status, value, lease,
          debug_resp.epoch, debug_resp.cap_key_ready, ocalls, resumes,
          SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      value != SLOTTEE_LT_USER_OCALL_MAGIC || lease == 0 ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  cap = make_enter_slot_test_cap(2);
  if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }

  tampered = cap;
  tampered.slot_id = 3;
  ret = enter_slot_request_once_with_cap(enclave, tampered,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("tamper_slot", ret, status, value, lease,
          debug_resp.epoch, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    enclave.destroy();
    return 1;
  }

  tampered = cap;
  tampered.rights ^= 0x2;
  ret = enter_slot_request_once_with_cap(enclave, tampered,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("tamper_rights", ret, status, value, lease,
          debug_resp.epoch, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    enclave.destroy();
    return 1;
  }

  tampered = cap;
  tampered.max_lease_cycles -= 1;
  ret = enter_slot_request_once_with_cap(enclave, tampered,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("tamper_ttl", ret, status, value, lease,
          debug_resp.epoch, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    enclave.destroy();
    return 1;
  }

  tampered = make_enter_slot_test_cap(2);
  for (size_t word = 0; word < SLOTTEE_CAP_MAC_WORDS; word++)
    tampered.cap_mac[word] = (uintptr_t)0x51514d4143550000UL + word;
  ret = enter_slot_request_once_with_cap(enclave, tampered,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("forge_mac", ret, status, value, lease,
          debug_resp.epoch, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    enclave.destroy();
    return 1;
  }

  if (cross_enclave.init(eapp_file, rt_file, ld_file, params) !=
      Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT cap MAC forge failed to init cross enclave\n");
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(cross_enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("cross_enclave", ret, status, value, lease,
          SLOTTEE_INITIAL_EPOCH, 1, 0, 0, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    cross_enclave.destroy();
    enclave.destroy();
    return 1;
  }
  cross_enclave.destroy();

  cap = make_enter_slot_test_cap(2);
  cap.max_lease_cycles = SLOTTEE_TEST_MAX_LEASE_CYCLES;
  if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("old_cap_issue", ret, status, value, lease,
          debug_resp.epoch, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_NOT_IMPLEMENTED) ||
      lease == 0) {
    enclave.destroy();
    return 1;
  }

  wait_for_enter_slot_ttl(SLOTTEE_TEST_MAX_LEASE_CYCLES * 32);

  value = 0;
  ret = enter_slot_request_once_with_cap(enclave, cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_mac_forge_row("old_cap_replay", ret, status, value, lease,
          SLOTTEE_INITIAL_EPOCH + 1, debug_resp.cap_key_ready, 0, 0,
          SBI_ERR_SM_ENCLAVE_NOT_FRESH)) {
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

static int
expect_cap_generation_replay_row(const char* phase, Keystone::Error ret,
    uintptr_t status, uintptr_t value, uintptr_t lease, uintptr_t old_eid,
    uintptr_t new_eid, uintptr_t old_epoch, uintptr_t new_epoch,
    uintptr_t old_generation, uintptr_t new_generation, uintptr_t ocalls,
    uintptr_t resumes, uintptr_t expected_status)
{
  printf("cap_generation_replay,%s,%d,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
      phase, (int)ret, status, value, lease, old_eid, new_eid, old_epoch,
      new_epoch, old_generation, new_generation, ocalls, resumes);
  fflush(stdout);

  if (ret != Keystone::Error::Success || status != expected_status) {
    printf("[FAIL] cap_generation_replay %s returned unexpected ret/status\n",
        phase);
    return 1;
  }

  return 0;
}

static int
run_enter_slot_cap_generation_replay(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  Keystone::Enclave recreated;
  slot_cap_t old_cap = make_enter_slot_test_cap(1);
  slot_cap_t new_cap = make_enter_slot_test_cap(1);
  slottee_debug_resp_t old_mint = {};
  slottee_debug_resp_t new_mint = {};
  uintptr_t status = 0;
  uintptr_t value = 0;
  uintptr_t lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) !=
      Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT cap generation replay failed to init enclave\n");
    return 1;
  }

  if (mint_enter_slot_test_cap_with_resp(enclave, &old_cap, &old_mint) !=
      Keystone::Error::Success) {
    enclave.destroy();
    return 1;
  }

  if (expect_cap_generation_replay_row("mint_old", Keystone::Error::Success,
          old_mint.status, 0, 0, old_cap.eid, 0, old_cap.epoch, 0,
          old_mint.cap_key_generation, 0, 0, 0,
          SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      old_cap.epoch != SLOTTEE_INITIAL_EPOCH ||
      old_mint.cap_key_generation == 0) {
    enclave.destroy();
    return 1;
  }

  if (enclave.destroy() != Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT cap generation replay failed to destroy first enclave\n");
    return 1;
  }

  if (recreated.init(eapp_file, rt_file, ld_file, params) !=
      Keystone::Error::Success) {
    printf("[FAIL] ENTER_SLOT cap generation replay failed to recreate enclave\n");
    return 1;
  }

  edge_init(&recreated);

  if (mint_enter_slot_test_cap_with_resp(recreated, &new_cap, &new_mint) !=
      Keystone::Error::Success) {
    recreated.destroy();
    return 1;
  }

  if (expect_cap_generation_replay_row("mint_new", Keystone::Error::Success,
          new_mint.status, 0, 0, old_cap.eid, new_cap.eid, old_cap.epoch,
          new_cap.epoch, old_mint.cap_key_generation,
          new_mint.cap_key_generation, 0, 0, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      old_cap.eid != new_cap.eid ||
      new_cap.epoch != SLOTTEE_INITIAL_EPOCH ||
      old_mint.cap_key_generation == new_mint.cap_key_generation) {
    printf("[FAIL] cap_generation_replay did not exercise same eid/new generation\n");
    recreated.destroy();
    return 1;
  }

  ret = enter_slot_request_once_with_cap(recreated, old_cap,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_cap_generation_replay_row("old_cap_after_recreate", ret, status,
          value, lease, old_cap.eid, new_cap.eid, old_cap.epoch, new_cap.epoch,
          old_mint.cap_key_generation, new_mint.cap_key_generation, 0, 0,
          SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    recreated.destroy();
    return 1;
  }

  ret = enter_slot_user_ocall_round_with_cap(recreated, new_cap, &status,
      &value, &lease, &ocalls, &resumes);
  if (expect_cap_generation_replay_row("new_cap_after_recreate", ret, status,
          value, lease, old_cap.eid, new_cap.eid, old_cap.epoch, new_cap.epoch,
          old_mint.cap_key_generation, new_mint.cap_key_generation, ocalls,
          resumes, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      value != SLOTTEE_LT_USER_OCALL_MAGIC ||
      lease == 0 || ocalls != 1 || resumes != 1) {
    recreated.destroy();
    return 1;
  }

  recreated.destroy();
  return 0;
}

static int
slot_cap_mac_nonzero(const slot_cap_t& cap)
{
  uintptr_t mac = 0;

  for (size_t word = 0; word < SLOTTEE_CAP_MAC_WORDS; word++)
    mac |= cap.cap_mac[word];

  return mac != 0;
}

static Keystone::Error
run_enclave_ocall_round(Keystone::Enclave& enclave, uintptr_t* value,
    uintptr_t* ocalls, uintptr_t* resumes)
{
  Keystone::Error ret;

  if (ocalls)
    *ocalls = 0;
  if (resumes)
    *resumes = 0;

  ret = enclave.run(value);
  for (uintptr_t retry = 0; ret == Keystone::Error::EdgeCallHost &&
       retry < enter_slot_resume_limit; retry++) {
    incoming_call_dispatch(enclave.getSharedBuffer());
    if (ocalls)
      (*ocalls)++;
    ret = enclave.resume(value);
    if (resumes)
      (*resumes)++;
  }

  return ret;
}

static int
expect_rt_authorized_mint_row(const char* phase, Keystone::Error ret,
    uintptr_t status, uintptr_t value, const slot_cap_t& cap,
    uintptr_t lease, uintptr_t ocalls, uintptr_t resumes,
    uintptr_t expected_status)
{
  printf("rt_authorized_mint,%s,%d,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
      phase, (int)ret, status, value, cap.eid, cap.slot_id, cap.epoch,
      cap.cap_seq, cap.rights, lease, ocalls, resumes);
  fflush(stdout);

  if (ret != Keystone::Error::Success || status != expected_status) {
    printf("[FAIL] rt_authorized_mint %s returned unexpected ret/status\n",
        phase);
    return 1;
  }

  return 0;
}

static int
run_enter_slot_rt_authorized_mint(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  slot_cap_t cap = {};
  slot_cap_t tampered = {};
  uintptr_t status = SBI_ERR_SM_ENCLAVE_SUCCESS;
  uintptr_t value = 0;
  uintptr_t lease = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  copied_slot_cap_ready = 0;
  memset(&copied_slot_cap, 0, sizeof(copied_slot_cap));

  if (enclave.init(eapp_file, rt_file, ld_file, params) !=
      Keystone::Error::Success) {
    printf("[FAIL] RT-authorized mint failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);
  ret = run_enclave_ocall_round(enclave, &value, &ocalls, &resumes);
  if (!copied_slot_cap_ready)
    status = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  cap = copied_slot_cap;

  if (expect_rt_authorized_mint_row("eapp_mint", ret, status, value, cap, 0,
          ocalls, resumes, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      value != SLOTTEE_LT_USER_OCALL_MAGIC ||
      cap.version != SLOTTEE_ENTER_SLOT_VERSION ||
      cap.slot_id != 1 ||
      cap.epoch != SLOTTEE_INITIAL_EPOCH ||
      cap.cap_seq != SLOTTEE_DEFAULT_CAP_SEQ ||
      cap.rights != SLOTTEE_CAP_RIGHT_ENTER ||
      cap.max_lease_cycles != SLOTTEE_DEFAULT_MAX_LEASE_CYCLES ||
      !slot_cap_mac_nonzero(cap)) {
    enclave.destroy();
    return 1;
  }

  copied_slot_cap_ready = 0;
  ret = enter_slot_user_ocall_round_with_cap(enclave, cap, &status, &value,
      &lease, &ocalls, &resumes);
  if (expect_rt_authorized_mint_row("enter_with_rt_cap", ret, status, value,
          cap, lease, ocalls, resumes, SBI_ERR_SM_ENCLAVE_SUCCESS) ||
      value != SLOTTEE_LT_USER_OCALL_MAGIC || lease == 0 ||
      ocalls != 1 || resumes != 1) {
    enclave.destroy();
    return 1;
  }

  tampered = cap;
  tampered.slot_id = 2;
  ret = enter_slot_request_once_with_cap(enclave, tampered,
      SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, &lease);
  if (expect_rt_authorized_mint_row("tamper_rt_cap", ret, status, value,
          tampered, lease, 0, 0, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
    enclave.destroy();
    return 1;
  }

  enclave.destroy();
  return 0;
}

static int
run_slottee_debug_mint_gate(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  Keystone::Enclave enclave;
  slottee_debug_req_t req = {};
  slottee_debug_resp_t resp = {};
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) !=
      Keystone::Error::Success) {
    printf("[FAIL] debug mint gate failed to init enclave\n");
    return 1;
  }

  req.version = SLOTTEE_DEBUG_VERSION;
  req.op = slottee_debug_mint_op_value;
  req.cap = make_enter_slot_test_cap(1);

  ret = enclave.slotteeDebug(req, &resp);
  printf("debug_mint_gate,enabled,ret,status,cap_key_ready,mac0\n");
  printf("debug_mint_gate,%d,%d,%lu,%lu,%lu\n",
#ifdef SLOTTEE_DEBUG_MINT_ENABLE
      1,
#else
      0,
#endif
      (int)ret, resp.status, resp.cap_key_ready, resp.cap.cap_mac[0]);
  fflush(stdout);

  enclave.destroy();

  if (ret != Keystone::Error::Success)
    return 1;

#ifdef SLOTTEE_DEBUG_MINT_ENABLE
  if (resp.status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      !slot_cap_mac_nonzero(resp.cap)) {
    printf("[FAIL] debug mint gate expected enabled mint success\n");
    return 1;
  }
#else
  if (resp.status != SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED) {
    printf("[FAIL] debug mint gate expected SBI_PROHIBITED when disabled\n");
    return 1;
  }
#endif

  return 0;
}

struct slottee_cycle_stats {
  uintptr_t count;
  uintptr_t min;
  uintptr_t max;
  unsigned long long total;
};

static void
slottee_stats_init(slottee_cycle_stats* stats)
{
  stats->count = 0;
  stats->min = ~(uintptr_t)0;
  stats->max = 0;
  stats->total = 0;
}

static void
slottee_stats_add(slottee_cycle_stats* stats, uintptr_t cycles)
{
  if (cycles < stats->min)
    stats->min = cycles;
  if (cycles > stats->max)
    stats->max = cycles;
  stats->total += cycles;
  stats->count++;
}

static double
slottee_stats_avg(const slottee_cycle_stats* stats)
{
  return stats->count ? (double)stats->total / (double)stats->count : 0.0;
}

static double
slottee_null_enter_baseline_avg()
{
  return (double)slottee_null_enter_baseline_total /
      (double)slottee_null_enter_baseline_count;
}

static void
reset_copied_slot_caps()
{
  memset(&copied_slot_cap, 0, sizeof(copied_slot_cap));
  memset(copied_slot_caps, 0, sizeof(copied_slot_caps));
  memset(copied_slot_cap_ready_by_slot, 0, sizeof(copied_slot_cap_ready_by_slot));
  copied_slot_cap_ready = 0;
}

static int
get_copied_slot_cap(uintptr_t slot_id, slot_cap_t* cap)
{
  if (!cap || slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS ||
      !copied_slot_cap_ready_by_slot[slot_id] ||
      !slot_cap_mac_nonzero(copied_slot_caps[slot_id]))
    return 1;

  *cap = copied_slot_caps[slot_id];
  return 0;
}

static Keystone::Error
seed_rt_authorized_caps(Keystone::Enclave& enclave, uintptr_t max_slot,
    uintptr_t* value, uintptr_t* ocalls, uintptr_t* resumes, uintptr_t* cycles)
{
  uintptr_t start;
  uintptr_t end;
  Keystone::Error ret;

  reset_copied_slot_caps();
  suppress_enclave_prints = 1;
  start = read_cycle_counter();
  ret = run_enclave_ocall_round(enclave, value, ocalls, resumes);
  end = read_cycle_counter();
  suppress_enclave_prints = 0;

  if (cycles)
    *cycles = end - start;

  if (ret != Keystone::Error::Success)
    return ret;
  if (value && *value != SLOTTEE_LT_USER_OCALL_MAGIC)
    return Keystone::Error::DeviceError;

  for (uintptr_t slot = 1; slot <= max_slot; slot++) {
    slot_cap_t cap = {};
    if (get_copied_slot_cap(slot, &cap))
      return Keystone::Error::DeviceError;
  }

  return Keystone::Error::Success;
}

static int
init_eval_enclave_with_caps(Keystone::Enclave& enclave, const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params,
    uintptr_t max_slot, uintptr_t* seed_cycles)
{
  uintptr_t value = 0;
  uintptr_t ocalls = 0;
  uintptr_t resumes = 0;
  Keystone::Error ret;

  params.setFreeMemSize(8 * 1024 * 1024);
  params.setUntrustedSize(64 * 1024);

  if (enclave.init(eapp_file, rt_file, ld_file, params) !=
      Keystone::Error::Success) {
    printf("[FAIL] slottee_eval failed to init enclave\n");
    return 1;
  }

  edge_init(&enclave);
  ret = seed_rt_authorized_caps(enclave, max_slot, &value, &ocalls, &resumes,
      seed_cycles);
  if (ret != Keystone::Error::Success) {
    printf("[FAIL] slottee_eval failed to seed RT-authorized caps ret=%d value=%lu ocalls=%lu resumes=%lu\n",
        (int)ret, value, ocalls, resumes);
    enclave.destroy();
    return 1;
  }

  return 0;
}

static int
run_slottee_eval_null_enter(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  slottee_cycle_stats current;

  slottee_stats_init(&current);
  printf("slottee_eval_null_enter,variant,iter,ret,status,value,cycles,baseline_commit\n");
  printf("slottee_eval_null_enter,baseline_no_mac,0,0,100100,1,2520128,%s\n",
      slottee_null_enter_baseline_commit);
  printf("slottee_eval_null_enter,baseline_no_mac,1,0,100100,1,940384,%s\n",
      slottee_null_enter_baseline_commit);
  printf("slottee_eval_null_enter,baseline_no_mac,2,0,100100,1,430912,%s\n",
      slottee_null_enter_baseline_commit);

  for (uintptr_t iter = 0; iter < slottee_paper_eval_iters; iter++) {
    Keystone::Enclave enclave;
    slot_cap_t cap = {};
    uintptr_t seed_cycles = 0;
    uintptr_t status = 0;
    uintptr_t value = 0;

    if (init_eval_enclave_with_caps(enclave, eapp_file, rt_file, ld_file,
            params, 1, &seed_cycles))
      return 1;
    if (get_copied_slot_cap(1, &cap)) {
      enclave.destroy();
      return 1;
    }

    uintptr_t start = read_cycle_counter();
    Keystone::Error ret = enter_slot_request_once_with_cap(enclave, cap,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &status, &value, NULL);
    uintptr_t cycles = read_cycle_counter() - start;
    slottee_stats_add(&current, cycles);

    printf("slottee_eval_null_enter,current_with_mac,%lu,%d,%lu,%lu,%lu,%s\n",
        iter, (int)ret, status, value, cycles,
        slottee_null_enter_baseline_commit);
    fflush(stdout);

    if (ret != Keystone::Error::Success || status != SBI_ERR_SM_NOT_IMPLEMENTED) {
      printf("[FAIL] slottee_eval null_enter iter %lu ret=%d status=%lu\n",
          iter, (int)ret, status);
      enclave.destroy();
      return 1;
    }

    enclave.destroy();
  }

  double baseline_avg = slottee_null_enter_baseline_avg();
  double current_avg = slottee_stats_avg(&current);
  double overhead_cycles = current_avg - baseline_avg;
  double overhead_pct = baseline_avg ?
      (overhead_cycles * 100.0) / baseline_avg : 0.0;

  printf("slottee_eval_null_enter_summary,variant,count,min,avg,max,total,baseline_commit,baseline_cycles,overhead_cycles,overhead_pct\n");
  printf("slottee_eval_null_enter_summary,baseline_no_mac,%lu,%lu,%.2f,%lu,%llu,%s,%.2f,0.00,0.00\n",
      slottee_null_enter_baseline_count, slottee_null_enter_baseline_min,
      baseline_avg, slottee_null_enter_baseline_max,
      slottee_null_enter_baseline_total,
      slottee_null_enter_baseline_commit);
  printf("slottee_eval_null_enter_summary,current_with_mac,%lu,%lu,%.2f,%lu,%llu,%s,%.2f,%.2f,%.2f\n",
      current.count, current.min, current_avg, current.max,
      current.total, slottee_null_enter_baseline_commit,
      baseline_avg, overhead_cycles, overhead_pct);
  fflush(stdout);
  return 0;
}

static int
run_slottee_eval_ocall_roundtrip(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  slottee_cycle_stats mint_stats;
  slottee_cycle_stats reenter_stats;
  slottee_cycle_stats total_stats;

  slottee_stats_init(&mint_stats);
  slottee_stats_init(&reenter_stats);
  slottee_stats_init(&total_stats);
  printf("slottee_eval_ocall_roundtrip,iter,mint_export_cycles,reenter_cycles,total_cycles,mint_ocalls,mint_resumes,reenter_ocalls,reenter_resumes,status,value,lease\n");

  for (uintptr_t iter = 0; iter < slottee_paper_eval_iters; iter++) {
    Keystone::Enclave enclave;
    slot_cap_t cap = {};
    uintptr_t seed_cycles = 0;
    uintptr_t seed_value = 0;
    uintptr_t seed_ocalls = 0;
    uintptr_t seed_resumes = 0;
    uintptr_t status = 0;
    uintptr_t value = 0;
    uintptr_t lease = 0;
    uintptr_t ocalls = 0;
    uintptr_t resumes = 0;

    params.setFreeMemSize(8 * 1024 * 1024);
    params.setUntrustedSize(64 * 1024);
    if (enclave.init(eapp_file, rt_file, ld_file, params) !=
        Keystone::Error::Success) {
      printf("[FAIL] slottee_eval ocall failed to init enclave\n");
      return 1;
    }
    edge_init(&enclave);
    Keystone::Error ret = seed_rt_authorized_caps(enclave, 1, &seed_value,
        &seed_ocalls, &seed_resumes, &seed_cycles);
    if (ret != Keystone::Error::Success || get_copied_slot_cap(1, &cap)) {
      printf("[FAIL] slottee_eval ocall failed to seed cap ret=%d\n", (int)ret);
      enclave.destroy();
      return 1;
    }

    suppress_enclave_prints = 1;
    uintptr_t start = read_cycle_counter();
    ret = enter_slot_user_ocall_round_with_cap(enclave, cap, &status, &value,
        &lease, &ocalls, &resumes);
    uintptr_t reenter_cycles = read_cycle_counter() - start;
    suppress_enclave_prints = 0;
    uintptr_t total_cycles = seed_cycles + reenter_cycles;
    slottee_stats_add(&mint_stats, seed_cycles);
    slottee_stats_add(&reenter_stats, reenter_cycles);
    slottee_stats_add(&total_stats, total_cycles);

    printf("slottee_eval_ocall_roundtrip,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
        iter, seed_cycles, reenter_cycles, total_cycles,
        seed_ocalls, seed_resumes, ocalls, resumes, status, value, lease);
    fflush(stdout);

    if (ret != Keystone::Error::Success ||
        status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
        value != SLOTTEE_LT_USER_OCALL_MAGIC || lease == 0) {
      printf("[FAIL] slottee_eval ocall roundtrip iter %lu ret=%d status=%lu value=%lu lease=%lu\n",
          iter, (int)ret, status, value, lease);
      enclave.destroy();
      return 1;
    }

    enclave.destroy();
  }

  printf("slottee_eval_ocall_roundtrip_summary,count,mint_avg,reenter_avg,total_min,total_avg,total_max,total_cycles\n");
  printf("slottee_eval_ocall_roundtrip_summary,%lu,%.2f,%.2f,%lu,%.2f,%lu,%llu\n",
      total_stats.count, slottee_stats_avg(&mint_stats),
      slottee_stats_avg(&reenter_stats), total_stats.min,
      slottee_stats_avg(&total_stats), total_stats.max, total_stats.total);
  fflush(stdout);
  return 0;
}

static int
run_slottee_eval_revoke_latency(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  slottee_cycle_stats mark_stats;
  slottee_cycle_stats cleanup_stats;
  slottee_cycle_stats total_stats;

  slottee_stats_init(&mark_stats);
  slottee_stats_init(&cleanup_stats);
  slottee_stats_init(&total_stats);
  printf("slottee_eval_revoke_latency,iter,enter_ret,enter_status,mark_ret,mark_status,epoch,resume_ret,mark_cycles,cleanup_cycles,total_cycles\n");

  for (uintptr_t iter = 0; iter < slottee_paper_eval_iters; iter++) {
    Keystone::Enclave enclave;
    slot_cap_t cap = {};
    uintptr_t seed_cycles = 0;
    uintptr_t status = 0;
    uintptr_t value = 0;
    uintptr_t lease = 0;
    uintptr_t epoch = 0;

    if (init_eval_enclave_with_caps(enclave, eapp_file, rt_file, ld_file,
            params, 2, &seed_cycles))
      return 1;
    if (get_copied_slot_cap(2, &cap)) {
      enclave.destroy();
      return 1;
    }

    suppress_enclave_prints = 1;
    Keystone::Error enter_ret = enter_slot_request_once_with_cap(enclave, cap,
        SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL, &status, &value, &lease);
    suppress_enclave_prints = 0;
    if (enter_ret != Keystone::Error::Success ||
        status != SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST || lease == 0) {
      printf("[FAIL] slottee_eval revoke setup iter %lu ret=%d status=%lu lease=%lu\n",
          iter, (int)enter_ret, status, lease);
      enclave.destroy();
      return 1;
    }

    uintptr_t start = read_cycle_counter();
    Keystone::Error mark_ret = enclave.markRevoke(2, &status, &epoch);
    uintptr_t after_mark = read_cycle_counter();
    Keystone::Error resume_ret = enclave.resume(&value);
    uintptr_t end = read_cycle_counter();
    uintptr_t mark_cycles = after_mark - start;
    uintptr_t cleanup_cycles = end - after_mark;
    uintptr_t total_cycles = end - start;
    slottee_stats_add(&mark_stats, mark_cycles);
    slottee_stats_add(&cleanup_stats, cleanup_cycles);
    slottee_stats_add(&total_stats, total_cycles);

    printf("slottee_eval_revoke_latency,%lu,%d,%lu,%d,%lu,%lu,%d,%lu,%lu,%lu\n",
        iter, (int)enter_ret, SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST,
        (int)mark_ret, status, epoch, (int)resume_ret,
        mark_cycles, cleanup_cycles, total_cycles);
    fflush(stdout);

    if (mark_ret != Keystone::Error::Success ||
        status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
        epoch != SLOTTEE_INITIAL_EPOCH + 1 ||
        resume_ret != Keystone::Error::EnclaveNotResumable) {
      printf("[FAIL] slottee_eval revoke latency iter %lu mark_ret=%d status=%lu epoch=%lu resume_ret=%d\n",
          iter, (int)mark_ret, status, epoch, (int)resume_ret);
      enclave.destroy();
      return 1;
    }

    enclave.destroy();
  }

  printf("slottee_eval_revoke_latency_summary,count,mark_avg,cleanup_avg,total_min,total_avg,total_max,total_cycles\n");
  printf("slottee_eval_revoke_latency_summary,%lu,%.2f,%.2f,%lu,%.2f,%lu,%llu\n",
      total_stats.count, slottee_stats_avg(&mark_stats),
      slottee_stats_avg(&cleanup_stats), total_stats.min,
      slottee_stats_avg(&total_stats), total_stats.max, total_stats.total);
  fflush(stdout);
  return 0;
}

struct slottee_ticket_worker_arg {
  Keystone::Enclave* enclave;
  slot_cap_t cap;
  uintptr_t slot_id;
  uintptr_t tickets_total;
  uintptr_t* next_ticket;
  pthread_mutex_t* ticket_lock;
  pthread_mutex_t* ioctl_lock;
  uintptr_t sold;
  uintptr_t retries;
  uintptr_t failures;
  uintptr_t cycles;
  Keystone::Error last_ret;
  uintptr_t last_status;
  uintptr_t last_value;
};

static void*
slottee_ticket_worker(void* opaque)
{
  slottee_ticket_worker_arg* arg = (slottee_ticket_worker_arg*)opaque;

  arg->sold = 0;
  arg->retries = 0;
  arg->failures = 0;
  arg->cycles = 0;
  arg->last_ret = Keystone::Error::Success;
  arg->last_status = 0;
  arg->last_value = 0;

  while (1) {
    pthread_mutex_lock(arg->ticket_lock);
    if (*arg->next_ticket >= arg->tickets_total) {
      pthread_mutex_unlock(arg->ticket_lock);
      break;
    }
    pthread_mutex_unlock(arg->ticket_lock);

    uintptr_t status = 0;
    uintptr_t value = 0;
    uintptr_t start = read_cycle_counter();
    if (arg->ioctl_lock)
      pthread_mutex_lock(arg->ioctl_lock);
    Keystone::Error ret = arg->enclave->enterSlotWithCap(
        arg->cap, SLOTTEE_ENTER_SLOT_FLAG_REAL, &status, &value);
    if (arg->ioctl_lock)
      pthread_mutex_unlock(arg->ioctl_lock);
    uintptr_t cycles = read_cycle_counter() - start;

    arg->cycles += cycles;

    if (ret == Keystone::Error::Success &&
        status == SBI_ERR_SM_ENCLAVE_SUCCESS &&
        value == SLOTTEE_SLOT_MAGIC) {
      pthread_mutex_lock(arg->ticket_lock);
      if (*arg->next_ticket < arg->tickets_total) {
        ++(*arg->next_ticket);
        arg->sold++;
        arg->last_ret = ret;
        arg->last_status = status;
        arg->last_value = value;
      }
      pthread_mutex_unlock(arg->ticket_lock);
    } else {
      arg->retries++;
      if (arg->retries > slottee_ticket_retry_limit) {
        arg->failures++;
        arg->last_ret = ret;
        arg->last_status = status;
        arg->last_value = value;
        break;
      }
      sched_yield();
    }
  }

  return NULL;
}

static int
run_slottee_ticket_demo_case(const char* mode, uintptr_t workers,
    const char* eapp_file, const char* rt_file, const char* ld_file,
    Keystone::Params params)
{
  Keystone::Enclave enclave;
  pthread_t threads[slottee_ticket_windows];
  slottee_ticket_worker_arg args[slottee_ticket_windows];
  pthread_mutex_t ticket_lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_t ioctl_lock = PTHREAD_MUTEX_INITIALIZER;
  uintptr_t next_ticket = 0;
  uintptr_t total_sold = 0;
  uintptr_t total_retries = 0;
  uintptr_t total_failures = 0;
  uintptr_t worker_cycles = 0;
  long online_harts = sysconf(_SC_NPROCESSORS_ONLN);

  if (workers == 0 || workers > slottee_ticket_windows)
    return 1;

  if (init_eval_enclave_with_caps(enclave, eapp_file, rt_file, ld_file,
          params, workers, NULL))
    return 1;

  printf("slottee_eval_ticket_worker,mode,harts,slot,sold,retries,failures,cycles,last_ret,last_status,last_value\n");
  uintptr_t start = read_cycle_counter();
  for (uintptr_t worker = 0; worker < workers; worker++) {
    slot_cap_t cap = {};
    if (get_copied_slot_cap(worker + 1, &cap)) {
      enclave.destroy();
      return 1;
    }

    memset(&args[worker], 0, sizeof(args[worker]));
    args[worker].enclave = &enclave;
    args[worker].cap = cap;
    args[worker].slot_id = worker + 1;
    args[worker].tickets_total = slottee_ticket_total;
    args[worker].next_ticket = &next_ticket;
    args[worker].ticket_lock = &ticket_lock;
    args[worker].ioctl_lock = workers == 1 ? &ioctl_lock : NULL;

    if (pthread_create(&threads[worker], NULL, slottee_ticket_worker,
            &args[worker]) != 0) {
      printf("[FAIL] slottee ticket demo failed to create worker %lu\n", worker);
      enclave.destroy();
      return 1;
    }
  }

  for (uintptr_t worker = 0; worker < workers; worker++) {
    if (pthread_join(threads[worker], NULL) != 0) {
      printf("[FAIL] slottee ticket demo failed to join worker %lu\n", worker);
      enclave.destroy();
      return 1;
    }
  }
  uintptr_t total_cycles = read_cycle_counter() - start;

  for (uintptr_t worker = 0; worker < workers; worker++) {
    total_sold += args[worker].sold;
    total_retries += args[worker].retries;
    total_failures += args[worker].failures;
    worker_cycles += args[worker].cycles;
    printf("slottee_eval_ticket_worker,%s,%ld,%lu,%lu,%lu,%lu,%lu,%d,%lu,%lu\n",
        mode, online_harts, args[worker].slot_id, args[worker].sold,
        args[worker].retries, args[worker].failures, args[worker].cycles,
        (int)args[worker].last_ret, args[worker].last_status,
        args[worker].last_value);
  }

  double throughput = total_cycles ?
      ((double)total_sold * 1000000.0) / (double)total_cycles : 0.0;
  printf("slottee_eval_ticket_demo,mode,harts,workers,tickets,total_cycles,worker_cycles,throughput_tickets_per_mcycle,retries,failures\n");
  printf("slottee_eval_ticket_demo,%s,%ld,%lu,%lu,%lu,%lu,%.6f,%lu,%lu\n",
      mode, online_harts, workers, total_sold, total_cycles, worker_cycles,
      throughput, total_retries, total_failures);
  fflush(stdout);

  enclave.destroy();
  pthread_mutex_destroy(&ticket_lock);
  pthread_mutex_destroy(&ioctl_lock);

  if (total_sold != slottee_ticket_total || total_failures != 0) {
    printf("[FAIL] slottee ticket demo mode=%s sold=%lu failures=%lu\n",
        mode, total_sold, total_failures);
    return 1;
  }

  return 0;
}

static int
run_slottee_ticket_demo(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  if (run_slottee_ticket_demo_case("single_window", 1, eapp_file, rt_file,
          ld_file, params))
    return 1;
  return run_slottee_ticket_demo_case("three_window", slottee_ticket_windows,
      eapp_file, rt_file, ld_file, params);
}

static int
run_slottee_paper_eval(const char* eapp_file,
    const char* rt_file, const char* ld_file, Keystone::Params params)
{
  if (run_slottee_eval_null_enter(eapp_file, rt_file, ld_file, params))
    return 1;
  if (run_slottee_eval_ocall_roundtrip(eapp_file, rt_file, ld_file, params))
    return 1;
  if (run_slottee_eval_revoke_latency(eapp_file, rt_file, ld_file, params))
    return 1;
  return run_slottee_ticket_demo(eapp_file, rt_file, ld_file, params);
}

int
main(int argc, char** argv) {
  if (argc < 4 || argc > 24) {
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
        "[--enter-slot-lt-ecall] [--enter-slot-lt-user] "
        "[--enter-slot-same-enclave-multislot] "
        "[--enter-slot-lt-user-ocall] "
        "[--enter-slot-lt-user-ocall-same-enclave] "
        "[--enter-slot-lt-user-illegal] "
        "[--enter-slot-lt-user-illegal-cleanup-same-enclave] "
        "[--enter-slot-lt-user-page-fault] "
        "[--enter-slot-lt-user-page-fault-cleanup-same-enclave] "
        "[--enter-slot-lt-user-destroy-after-reentry] "
        "[--enter-slot-lt-user-revoke-after-reentry] "
        "[--enter-slot-lt-user-destroy-race] "
        "[--enter-slot-double-enter-epoch-rollover] "
        "[--enter-slot-mark-revoke] "
        "[--enter-slot-active-revoke-boundary] "
        "[--enter-slot-active-revoke-timer-stress] "
        "[--enter-slot-first-active-revoke-template] "
        "[--enter-slot-first-active-revoke-diagnostic] "
        "[--enter-slot-active-revoke-destroy-race] "
        "[--enter-slot-active-revoke-multislot-stress] "
        "[--enter-slot-rt-revoke-fault] "
        "[--enter-slot-revoke-stress] "
        "[--enter-slot-cap-mac-forge] "
        "[--enter-slot-cap-generation-replay] "
        "[--enter-slot-rt-authorized-mint] "
        "[--slottee-debug-mint-gate] "
        "[--slottee-paper-eval] [--slottee-ticket-demo] "
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
  int enter_slot_lt_user = 0;
  int enter_slot_same_enclave_multislot = 0;
  int enter_slot_lt_user_ocall = 0;
  int enter_slot_lt_user_ocall_same_enclave = 0;
  int enter_slot_lt_user_illegal = 0;
  int enter_slot_lt_user_illegal_cleanup_same_enclave = 0;
  int enter_slot_lt_user_page_fault = 0;
  int enter_slot_lt_user_page_fault_cleanup_same_enclave = 0;
  int enter_slot_lt_user_destroy_after_reentry = 0;
  int enter_slot_lt_user_revoke_after_reentry = 0;
  int enter_slot_lt_user_destroy_race = 0;
  int enter_slot_double_enter_epoch_rollover = 0;
  int enter_slot_mark_revoke = 0;
  int enter_slot_active_revoke_boundary = 0;
  int enter_slot_active_revoke_timer_stress = 0;
  int enter_slot_first_active_revoke_template = 0;
  int enter_slot_first_active_revoke_diagnostic = 0;
  int enter_slot_active_revoke_destroy_race = 0;
  int enter_slot_active_revoke_multislot_stress = 0;
  int enter_slot_rt_revoke_fault = 0;
  int enter_slot_revoke_stress = 0;
  int enter_slot_cap_mac_forge = 0;
  int enter_slot_cap_generation_replay = 0;
  int enter_slot_rt_authorized_mint = 0;
  int slottee_debug_mint_gate = 0;
  int slottee_paper_eval = 0;
  int slottee_ticket_demo = 0;

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
      {"enter-slot-lt-user", no_argument, &enter_slot_lt_user, 1},
      {"enter-slot-same-enclave-multislot", no_argument,
       &enter_slot_same_enclave_multislot, 1},
      {"enter-slot-lt-user-ocall", no_argument, &enter_slot_lt_user_ocall, 1},
      {"enter-slot-lt-user-ocall-same-enclave", no_argument,
       &enter_slot_lt_user_ocall_same_enclave, 1},
      {"enter-slot-lt-user-illegal", no_argument, &enter_slot_lt_user_illegal, 1},
      {"enter-slot-lt-user-illegal-cleanup-same-enclave", no_argument,
       &enter_slot_lt_user_illegal_cleanup_same_enclave, 1},
      {"enter-slot-lt-user-page-fault", no_argument, &enter_slot_lt_user_page_fault, 1},
      {"enter-slot-lt-user-page-fault-cleanup-same-enclave", no_argument,
       &enter_slot_lt_user_page_fault_cleanup_same_enclave, 1},
      {"enter-slot-lt-user-destroy-after-reentry", no_argument,
       &enter_slot_lt_user_destroy_after_reentry, 1},
      {"enter-slot-lt-user-revoke-after-reentry", no_argument,
       &enter_slot_lt_user_revoke_after_reentry, 1},
      {"enter-slot-lt-user-destroy-race", no_argument,
       &enter_slot_lt_user_destroy_race, 1},
      {"enter-slot-double-enter-epoch-rollover", no_argument,
       &enter_slot_double_enter_epoch_rollover, 1},
      {"enter-slot-mark-revoke", no_argument, &enter_slot_mark_revoke, 1},
      {"enter-slot-active-revoke-boundary", no_argument,
       &enter_slot_active_revoke_boundary, 1},
      {"enter-slot-active-revoke-timer-stress", no_argument,
       &enter_slot_active_revoke_timer_stress, 1},
      {"enter-slot-first-active-revoke-template", no_argument,
       &enter_slot_first_active_revoke_template, 1},
      {"enter-slot-first-active-revoke-diagnostic", no_argument,
       &enter_slot_first_active_revoke_diagnostic, 1},
      {"enter-slot-active-revoke-destroy-race", no_argument,
       &enter_slot_active_revoke_destroy_race, 1},
      {"enter-slot-active-revoke-multislot-stress", no_argument,
       &enter_slot_active_revoke_multislot_stress, 1},
      {"enter-slot-rt-revoke-fault", no_argument, &enter_slot_rt_revoke_fault, 1},
      {"enter-slot-revoke-stress", no_argument, &enter_slot_revoke_stress, 1},
      {"enter-slot-cap-mac-forge", no_argument, &enter_slot_cap_mac_forge, 1},
      {"enter-slot-cap-generation-replay", no_argument,
       &enter_slot_cap_generation_replay, 1},
      {"enter-slot-rt-authorized-mint", no_argument,
       &enter_slot_rt_authorized_mint, 1},
      {"slottee-debug-mint-gate", no_argument, &slottee_debug_mint_gate, 1},
      {"slottee-paper-eval", no_argument, &slottee_paper_eval, 1},
      {"slottee-ticket-demo", no_argument, &slottee_ticket_demo, 1},
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

  if (enter_slot_lt_user) {
    return run_enter_slot_lt_user(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_same_enclave_multislot) {
    return run_enter_slot_same_enclave_multislot(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_ocall) {
    return run_enter_slot_lt_user_ocall(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_ocall_same_enclave) {
    return run_enter_slot_lt_user_ocall_same_enclave(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_illegal) {
    return run_enter_slot_lt_user_illegal(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_illegal_cleanup_same_enclave) {
    return run_enter_slot_lt_user_illegal_cleanup_same_enclave(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_page_fault) {
    return run_enter_slot_lt_user_page_fault(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_page_fault_cleanup_same_enclave) {
    return run_enter_slot_lt_user_page_fault_cleanup_same_enclave(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_destroy_after_reentry) {
    return run_enter_slot_lt_user_destroy_after_reentry(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_revoke_after_reentry) {
    return run_enter_slot_lt_user_revoke_after_reentry(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_lt_user_destroy_race) {
    return run_enter_slot_lt_user_destroy_race(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_double_enter_epoch_rollover) {
    return run_enter_slot_double_enter_epoch_rollover(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_mark_revoke) {
    return run_enter_slot_mark_revoke(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_active_revoke_boundary) {
    return run_enter_slot_active_revoke_boundary(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_active_revoke_timer_stress) {
    return run_enter_slot_active_revoke_timer_stress(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_first_active_revoke_template) {
    return run_enter_slot_first_active_revoke_template(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_first_active_revoke_diagnostic) {
    return run_enter_slot_first_active_revoke_diagnostic(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_active_revoke_destroy_race) {
    return run_enter_slot_active_revoke_destroy_race(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_active_revoke_multislot_stress) {
    return run_enter_slot_active_revoke_multislot_stress(
        eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_rt_revoke_fault) {
    return run_enter_slot_rt_revoke_fault(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_revoke_stress) {
    return run_enter_slot_revoke_stress(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_cap_mac_forge) {
    return run_enter_slot_cap_mac_forge(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_cap_generation_replay) {
    return run_enter_slot_cap_generation_replay(eapp_file, rt_file, ld_file, params);
  }

  if (enter_slot_rt_authorized_mint) {
    return run_enter_slot_rt_authorized_mint(eapp_file, rt_file, ld_file, params);
  }

  if (slottee_debug_mint_gate) {
    return run_slottee_debug_mint_gate(eapp_file, rt_file, ld_file, params);
  }

  if (slottee_paper_eval) {
    return run_slottee_paper_eval(eapp_file, rt_file, ld_file, params);
  }

  if (slottee_ticket_demo) {
    return run_slottee_ticket_demo(eapp_file, rt_file, ld_file, params);
  }

  Keystone::Enclave enclave;

  if (self_timing) {
    asm volatile("rdcycle %0" : "=r"(cycles1));
  }

  enclave.init(eapp_file, rt_file, ld_file, params);

  if (enter_slot_stub) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    Keystone::Error enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value, NULL);
    if (expect_enter_slot_status("ENTER_SLOT stub", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
  }

  if (enter_slot_real) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    Keystone::Error enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_REAL, &enter_slot_status, &enter_slot_value, NULL);
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
        1, SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT + 1,
        &enter_slot_status, &enter_slot_value);
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
    Keystone::Error enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &first_lease, NULL);
    if (expect_enter_slot_status("ENTER_SLOT lease first", enter_slot_ret, enter_slot_status,
            first_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (first_lease == 0) {
      printf("[FAIL] ENTER_SLOT lease first returned zero lease id\n");
      return 1;
    }

    uintptr_t second_value = 0;
    enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &second_value, NULL);
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
            enter_slot_value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
      return 1;
    }

    enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value, NULL);
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

    Keystone::Error enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &slot1_lease, NULL);
    if (expect_enter_slot_status("ENTER_SLOT multislot slot1", enter_slot_ret,
            enter_slot_status, slot1_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (slot1_lease == 0) {
      printf("[FAIL] ENTER_SLOT multislot slot1 returned zero lease id\n");
      return 1;
    }

    enter_slot_ret = enter_slot_request_once(enclave, 2,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &slot2_lease, NULL);
    if (expect_enter_slot_status("ENTER_SLOT multislot slot2", enter_slot_ret,
            enter_slot_status, slot2_lease, SBI_ERR_SM_NOT_IMPLEMENTED)) {
      return 1;
    }
    if (slot2_lease == 0 || slot2_lease == slot1_lease) {
      printf("[FAIL] ENTER_SLOT multislot slot2 returned invalid lease id\n");
      return 1;
    }

    enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &slot1_lease, NULL);
    if (expect_enter_slot_status("ENTER_SLOT multislot duplicate", enter_slot_ret,
            enter_slot_status, slot1_lease, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }
  }

  if (enter_slot_capability) {
    uintptr_t enter_slot_status = 0;
    uintptr_t enter_slot_value = 0;
    slot_cap_t cap = make_enter_slot_test_cap(1);

    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success)
      return 1;
    cap.rights = 0;
    Keystone::Error enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap rights", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success)
      return 1;
    cap.cap_seq = 0;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap seq", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success)
      return 1;
    cap.max_lease_cycles = 0;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap lease", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success)
      return 1;
    cap.cap_mac[0] ^= 1;
    enter_slot_ret = enclave.enterSlotWithCap(
        cap, SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT cap mac", enter_slot_ret,
            enter_slot_status, enter_slot_value, SBI_ERR_SM_ENCLAVE_BAD_CAP)) {
      return 1;
    }

    cap = make_enter_slot_test_cap(1);
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success)
      return 1;
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
    if (mint_enter_slot_test_cap(enclave, &cap) != Keystone::Error::Success)
      return 1;

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
    Keystone::Error enter_slot_ret = enter_slot_request_once(enclave, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &first_lease, NULL);
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
    enter_slot_ret = enter_slot_request_once(recreated, 1,
        SLOTTEE_ENTER_SLOT_FLAG_NONE, &enter_slot_status, &recreated_lease, NULL);
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
