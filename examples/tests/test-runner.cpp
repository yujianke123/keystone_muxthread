//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
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

int
main(int argc, char** argv) {
  if (argc < 4 || argc > 10) {
    printf(
        "Usage: %s <eapp> <runtime> [--utm-size SIZE(K)] [--freemem-size "
        "SIZE(K)] [--time] [--load-only] [--enter-slot-stub] "
        "[--enter-slot-negative] [--enter-slot-lease] "
        "[--enter-slot-destroy-recreate] [--utm-ptr 0xPTR] "
        "[--retval EXPECTED]\n",
        argv[0]);
    return 0;
  }

  int self_timing = 0;
  int load_only   = 0;
  int enter_slot_stub = 0;
  int enter_slot_negative = 0;
  int enter_slot_lease = 0;
  int enter_slot_destroy_recreate = 0;

  size_t untrusted_size = 2 * 1024 * 1024;
  size_t freemem_size   = 48 * 1024 * 1024;
  bool retval_exist = false;
  unsigned long retval = 0;

  static struct option long_options[] = {
      {"time", no_argument, &self_timing, 1},
      {"load-only", no_argument, &load_only, 1},
      {"enter-slot-stub", no_argument, &enter_slot_stub, 1},
      {"enter-slot-negative", no_argument, &enter_slot_negative, 1},
      {"enter-slot-lease", no_argument, &enter_slot_lease, 1},
      {"enter-slot-destroy-recreate", no_argument, &enter_slot_destroy_recreate, 1},
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

  Keystone::Enclave enclave;
  Keystone::Params params;
  unsigned long cycles1, cycles2, cycles3, cycles4;

  params.setFreeMemSize(freemem_size);
  params.setUntrustedSize(untrusted_size);

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
        1, SLOTTEE_ENTER_SLOT_FLAG_NONE + 1, &enter_slot_status, &enter_slot_value);
    if (expect_enter_slot_status("ENTER_SLOT flags", enter_slot_ret, enter_slot_status,
            enter_slot_value, SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT)) {
      return 1;
    }

    enter_slot_ret = enclave.enterSlotWithVersion(
        SLOTTEE_ENTER_SLOT_VERSION + 1, 1, SLOTTEE_ENTER_SLOT_FLAG_NONE,
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
