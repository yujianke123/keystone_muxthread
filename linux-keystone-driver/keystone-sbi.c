#include "keystone-sbi.h"

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_CREATE_ENCLAVE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_run_enclave(unsigned long eid) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_RUN_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_destroy_enclave(unsigned long eid) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_DESTROY_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_resume_enclave(unsigned long eid) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_RESUME_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_enter_slot(
    unsigned long eid, struct enter_slot_req_t *req, struct enter_slot_resp_t *resp) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_ENTER_SLOT,
      eid, (unsigned long) req, (unsigned long) resp, 0, 0, 0);
}

struct sbiret sbi_sm_mark_revoke(
    unsigned long eid, struct mark_revoke_req_t *req, struct mark_revoke_resp_t *resp) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_MARK_REVOKE,
      eid, (unsigned long) req, (unsigned long) resp, 0, 0, 0);
}

struct sbiret sbi_sm_slottee_debug(
    unsigned long eid, struct slottee_debug_req_t *req, struct slottee_debug_resp_t *resp) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_SLOTTEE_DEBUG,
      eid, (unsigned long) req, (unsigned long) resp, 0, 0, 0);
}

struct sbiret sbi_sm_lease_watchdog_check(unsigned long eid) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_LEASE_WATCHDOG_CHECK,
      eid, 0, 0, 0, 0, 0);
}
