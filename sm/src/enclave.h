//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

#include "sm.h"
#include "pmp.h"
#include "thread.h"
#include <crypto.h>

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

#define ATTEST_DATA_MAXLEN  1024
#define MAX_ENCL_THREADS SLOTTEE_MAX_SLOTS

typedef enum {
  INVALID = -1,
  DESTROYING = 0,
  ALLOCATED,
  FRESH,
  STOPPED,
  RUNNING,
} enclave_state;

/* For now, eid's are a simple unsigned int */
typedef unsigned int enclave_id;

typedef enum {
  SLOT_LEASE_FREE = 0,
  SLOT_LEASE_RESERVED = 1,
  SLOT_LEASE_ACTIVE = 2,
  SLOT_LEASE_EXITING = 3,
  SLOT_LEASE_REVOKED = 4,
} slot_lease_state;

struct slot_lease_t
{
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t epoch;
  uintptr_t cap_seq;
  uintptr_t rights;
  uintptr_t max_lease_cycles;
  uintptr_t bound_hart;
  uintptr_t expiry_cycle;
  uintptr_t entry_pc;
  uintptr_t exit_reason;
  uintptr_t active_hart;
  uintptr_t thread_index;
  uintptr_t revoke_pending;
  slot_lease_state state;
};

/* Metadata around memory regions associate with this enclave
 * EPM is the 'home' for the enclave, contains runtime code/etc
 * UTM is the untrusted shared pages
 * OTHER is managed by some other component (e.g. platform_)
 * INVALID is an unused index
 */
enum enclave_region_type{
  REGION_INVALID,
  REGION_EPM,
  REGION_UTM,
  REGION_OTHER,
};

struct enclave_region
{
  region_id pmp_rid;
  enum enclave_region_type type;
};

/* enclave metadata */
struct enclave
{
  //spinlock_t lock; //local enclave lock. we don't need this until we have multithreaded enclave
  enclave_id eid; //enclave id
  unsigned long encl_satp; // enclave's page table base
  enclave_state state; // global state of the enclave

  /* Physical memory regions associate with this enclave */
  struct enclave_region regions[ENCLAVE_REGIONS_MAX];

  /* measurement */
  byte hash[MDSIZE];
  byte sign[SIGNATURE_SIZE];

  /* parameters */
  struct runtime_params_t params;

  /* enclave execution context */
  unsigned int n_thread;
  uintptr_t stopped_thread_index;
  struct thread_state threads[MAX_ENCL_THREADS];
  int slot_reentry_ready;
  struct csrs slot_reentry_csrs;
  uintptr_t slot_reentry_mstatus;

  uintptr_t next_slot_lease_id;
  uintptr_t current_slot_epoch;
  struct slot_lease_t slot_leases[SLOTTEE_MAX_SLOTS];
  byte cap_key[MDSIZE];
  uintptr_t cap_key_ready;
  uintptr_t cap_key_generation;

  struct platform_enclave_data ped;
};

/* attestation reports */
struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};
struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};
struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

/* sealing key structure */
#define SEALING_KEY_SIZE 128
struct sealing_key
{
  uint8_t key[SEALING_KEY_SIZE];
  uint8_t signature[SIGNATURE_SIZE];
};

/*** SBI functions & external functions ***/
// callables from the host
unsigned long create_enclave(unsigned long *eid, struct keystone_sbi_create_t create_args);
unsigned long destroy_enclave(enclave_id eid);
unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long reserve_enclave_slot(
    enclave_id eid, const struct slot_cap_t *cap, struct enter_slot_resp_t *resp);
unsigned long activate_enclave_slot(
    enclave_id eid, const struct slot_cap_t *cap, struct enter_slot_resp_t *resp);
unsigned long mark_revoke_enclave_slot(
    enclave_id eid, const struct mark_revoke_req_t *req, struct mark_revoke_resp_t *resp);
unsigned long debug_enclave_slot_state(
    enclave_id eid, const struct slottee_debug_req_t *req, struct slottee_debug_resp_t *resp);
void enter_activated_enclave_slot(
    struct sbi_trap_regs *regs, enclave_id eid, uintptr_t slot_id, uintptr_t lease_id,
    uintptr_t slot_mode);
// callables from the enclave
unsigned long mint_enclave_slot_cap(
    enclave_id eid, const struct mint_slot_cap_req_t *req, struct mint_slot_cap_resp_t *resp);
unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long exit_enclave_slot(
    struct sbi_trap_regs *regs, enclave_id eid, uintptr_t slot_id, uintptr_t lease_id,
    uintptr_t exit_reason, uintptr_t value);
unsigned long init_enclave_slot_reentry_template(
    struct sbi_trap_regs *regs, enclave_id eid);
unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid);
unsigned long attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size, enclave_id eid);
// attestation
unsigned long validate_and_hash_enclave(struct enclave* enclave);
// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata(void);
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest);
int get_enclave_region_index(enclave_id eid, enum enclave_region_type type);
uintptr_t get_enclave_region_base(enclave_id eid, int memid);
uintptr_t get_enclave_region_size(enclave_id eid, int memid);
unsigned long get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size, enclave_id eid);
// interrupt handlers
void sbi_trap_handler_keystone_enclave(struct sbi_trap_regs *regs);
#endif
