#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"

#define OCALL_PRINT_VALUE 2

enum {
  SLOTTEE_POLICY_REQ1_OK = 1u << 0,
  SLOTTEE_POLICY_REQ2_OK = 1u << 1,
  SLOTTEE_POLICY_REQ3_OK = 1u << 2,
  SLOTTEE_POLICY_LIMIT_OK = 1u << 3,
  SLOTTEE_POLICY_RELEASE_OK = 1u << 4,
  SLOTTEE_POLICY_REUSE_OK = 1u << 5,
};

void EAPP_ENTRY
eapp_entry()
{
  struct slottee_slot_policy policy = {3, 1, 7};
  uintptr_t report = 0;
  int slot1 = slottee_slot_request(&policy);
  int slot2 = slottee_slot_request(&policy);
  int slot3 = slottee_slot_request(&policy);
  int slot4 = slottee_slot_request(&policy);
  int slot5;

  if (slot1 > 0)
    report |= SLOTTEE_POLICY_REQ1_OK;
  if (slot2 > 0 && slot2 != slot1)
    report |= SLOTTEE_POLICY_REQ2_OK;
  if (slot3 > 0 && slot3 != slot1 && slot3 != slot2)
    report |= SLOTTEE_POLICY_REQ3_OK;
  if (slot4 == SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE)
    report |= SLOTTEE_POLICY_LIMIT_OK;

  if (slot2 > 0 &&
      slottee_slot_release((uintptr_t)slot2) == SBI_ERR_SM_ENCLAVE_SUCCESS)
    report |= SLOTTEE_POLICY_RELEASE_OK;

  slot5 = slottee_slot_request(&policy);
  if (slot5 == slot2)
    report |= SLOTTEE_POLICY_REUSE_OK;

  if (slot1 > 0)
    slottee_slot_release((uintptr_t)slot1);
  if (slot3 > 0)
    slottee_slot_release((uintptr_t)slot3);
  if (slot5 > 0)
    slottee_slot_release((uintptr_t)slot5);

  if (ocall(OCALL_PRINT_VALUE, &report, sizeof(report), 0, 0) != 0)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  EAPP_RETURN(report == (SLOTTEE_POLICY_REQ1_OK |
                         SLOTTEE_POLICY_REQ2_OK |
                         SLOTTEE_POLICY_REQ3_OK |
                         SLOTTEE_POLICY_LIMIT_OK |
                         SLOTTEE_POLICY_RELEASE_OK |
                         SLOTTEE_POLICY_REUSE_OK) ?
      SLOTTEE_LT_USER_OCALL_MAGIC : SLOTTEE_LT_USER_ILLEGAL_MAGIC);
}
