#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "shared/sm_call.h"
#include "shared/sm_err.h"

#define OCALL_COPY_SLOT_CAP 5

static int
slottee_cap_mac_nonzero(const struct slot_cap_t* cap)
{
  uintptr_t mac = 0;
  size_t word;

  for (word = 0; word < SLOTTEE_CAP_MAC_WORDS; word++)
    mac |= cap->cap_mac[word];

  return mac != 0;
}

void EAPP_ENTRY
eapp_entry()
{
  struct mint_slot_cap_req_t req = {
      SLOTTEE_MINT_CAP_VERSION,
      1,
      SLOTTEE_DEFAULT_CAP_SEQ,
      SLOTTEE_CAP_RIGHT_ENTER,
      SLOTTEE_SM_WATCHDOG_TTL_CYCLES,
  };
  struct mint_slot_cap_resp_t resp = {0};

  if (slottee_mint_cap(&req, &resp) != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      resp.status != SBI_ERR_SM_ENCLAVE_SUCCESS ||
      resp.cap.version != SLOTTEE_ENTER_SLOT_VERSION ||
      resp.cap.slot_id != req.slot_id ||
      resp.cap.epoch != SLOTTEE_INITIAL_EPOCH ||
      resp.cap.rights != SLOTTEE_CAP_RIGHT_ENTER ||
      resp.cap.cap_seq != SLOTTEE_DEFAULT_CAP_SEQ ||
      resp.cap.max_lease_cycles != SLOTTEE_SM_WATCHDOG_TTL_CYCLES ||
      !slottee_cap_mac_nonzero(&resp.cap)) {
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);
  }

  if (ocall(OCALL_COPY_SLOT_CAP, &resp.cap, sizeof(resp.cap), 0, 0) != 0)
    EAPP_RETURN(SLOTTEE_LT_USER_ILLEGAL_MAGIC);

  EAPP_RETURN(SLOTTEE_LT_USER_OCALL_MAGIC);
}
