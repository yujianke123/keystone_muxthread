//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "KeystoneDevice.hpp"
#include "shared/sm_err.h"
#include <sys/mman.h>

namespace Keystone {

KeystoneDevice::KeystoneDevice() { eid = -1; }

static slot_cap_t
makeEnterSlotCap(uintptr_t version, uintptr_t epoch, uintptr_t slotId) {
  slot_cap_t cap;
  memset(&cap, 0, sizeof(cap));
  cap.version = version;
  cap.slot_id = slotId;
  cap.epoch = epoch;
  cap.cap_seq = SLOTTEE_DEFAULT_CAP_SEQ;
  cap.rights = SLOTTEE_CAP_RIGHT_ENTER;
  cap.max_lease_cycles = SLOTTEE_DEFAULT_MAX_LEASE_CYCLES;
  return cap;
}

static enter_slot_req_t
makeEnterSlotReq(const slot_cap_t& cap, uintptr_t flags) {
  enter_slot_req_t req;
  memset(&req, 0, sizeof(req));
  req.version = cap.version;
  req.cap = cap;
  req.flags = flags;
  return req;
}

static bool
isSlotCapMacZero(const slot_cap_t& cap) {
  for (size_t word = 0; word < SLOTTEE_CAP_MAC_WORDS; word++) {
    if (cap.cap_mac[word] != 0) {
      return false;
    }
  }
  return true;
}

Error
KeystoneDevice::create(uint64_t minPages) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.min_pages = minPages;

  if (ioctl(fd, KEYSTONE_IOC_CREATE_ENCLAVE, &encl)) {
    perror("ioctl error");
    eid = -1;
    return Error::IoctlErrorCreate;
  }

  eid      = encl.eid;
  physAddr = encl.epm_paddr;

  return Error::Success;
}

uintptr_t
KeystoneDevice::initUTM(size_t size) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid      = eid;
  encl.utm_size = size;
  if (ioctl(fd, KEYSTONE_IOC_UTM_INIT, &encl)) {
    return 0;
  }

  return encl.utm_paddr;
}

Error
KeystoneDevice::finalize(
    uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
    uintptr_t freeRequested) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid            = eid;
  encl.runtime_paddr  = runtimePhysAddr;
  encl.user_paddr     = eappPhysAddr;
  encl.free_paddr     = freePhysAddr;
  encl.free_requested = freeRequested;
  encl.slot_entry     = 0;

  if (ioctl(fd, KEYSTONE_IOC_FINALIZE_ENCLAVE, &encl)) {
    perror("ioctl error");
    return Error::IoctlErrorFinalize;
  }
  return Error::Success;
}

Error
KeystoneDevice::destroy() {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid = eid;

  /* if the enclave has never created */
  if (eid < 0) {
    return Error::Success;
  }

  if (ioctl(fd, KEYSTONE_IOC_DESTROY_ENCLAVE, &encl)) {
    perror("ioctl error");
    return Error::IoctlErrorDestroy;
  }

  eid = -1;
  return Error::Success;
}

Error
KeystoneDevice::__run(bool resume, uintptr_t* ret) {
  struct keystone_ioctl_run_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid = eid;

  Error error;
  uint64_t request;

  if (resume) {
    error   = Error::IoctlErrorResume;
    request = KEYSTONE_IOC_RESUME_ENCLAVE;
  } else {
    error   = Error::IoctlErrorRun;
    request = KEYSTONE_IOC_RUN_ENCLAVE;
  }

  if (ioctl(fd, request, &encl)) {
    return error;
  }

  switch (encl.error) {
    case SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST:
      return Error::EdgeCallHost;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      if (ret) {
        *ret = encl.value;
      }
      return Error::Success;
    default:
      ERROR(
          "Unknown SBI error (%d) returned by %s_enclave\n", encl.error,
          resume ? "resume" : "run");
      return error;
  }
}

Error
KeystoneDevice::run(uintptr_t* ret) {
  return __run(false, ret);
}

Error
KeystoneDevice::resume(uintptr_t* ret) {
  return __run(true, ret);
}

Error
KeystoneDevice::enterSlot(uintptr_t slotId, uintptr_t* status, uintptr_t* value) {
  return enterSlotWithEpoch(
      SLOTTEE_INITIAL_EPOCH, slotId, SLOTTEE_ENTER_SLOT_FLAG_NONE, status, value);
}

Error
KeystoneDevice::enterSlot(
    uintptr_t slotId, uintptr_t flags, uintptr_t* status, uintptr_t* value) {
  return enterSlotWithEpoch(SLOTTEE_INITIAL_EPOCH, slotId, flags, status, value);
}

Error
KeystoneDevice::enterSlotWithEpoch(
    uintptr_t epoch, uintptr_t slotId, uintptr_t flags, uintptr_t* status,
    uintptr_t* value) {
  return enterSlotWithVersion(
      SLOTTEE_ENTER_SLOT_VERSION, epoch, slotId, flags, status, value);
}

Error
KeystoneDevice::enterSlotWithVersion(
    uintptr_t version, uintptr_t epoch, uintptr_t slotId, uintptr_t flags,
    uintptr_t* status, uintptr_t* value) {
  slot_cap_t cap = makeEnterSlotCap(version, epoch, slotId);
  return enterSlotWithCap(cap, flags, status, value);
}

Error
KeystoneDevice::enterSlotWithCap(
    const slot_cap_t& cap, uintptr_t flags, uintptr_t* status, uintptr_t* value) {
  enter_slot_req_t req = makeEnterSlotReq(cap, flags);
  enter_slot_resp_t resp;

  Error ret = enterSlotWithRequest(req, &resp);
  if (status) {
    *status = resp.status;
  }
  if (value) {
    *value = resp.value;
  }

  return ret;
}

Error
KeystoneDevice::enterSlotWithRequest(const enter_slot_req_t& req, enter_slot_resp_t* resp) {
  struct keystone_ioctl_enter_slot encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid = eid;
  encl.req = req;

  if (ioctl(fd, KEYSTONE_IOC_ENTER_SLOT, &encl)) {
    return Error::IoctlErrorEnterSlot;
  }

  if (resp) {
    *resp = encl.resp;
  }

  return Error::Success;
}

void*
KeystoneDevice::map(uintptr_t addr, size_t size) {
  assert(fd >= 0);
  void* ret;
  ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, addr);
  assert(ret != MAP_FAILED);
  return ret;
}

bool
KeystoneDevice::initDevice(Params params) { // TODO: why does this need params
  /* open device driver */
  fd = open(KEYSTONE_DEV_PATH, O_RDWR);
  if (fd < 0) {
    PERROR("cannot open device file");
    return false;
  }
  return true;
}

Error
MockKeystoneDevice::create(uint64_t minPages) {
  eid = -1;
  return Error::Success;
}

uintptr_t
MockKeystoneDevice::initUTM(size_t size) {
  return 0;
}

Error
MockKeystoneDevice::finalize(
    uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
    uintptr_t freeRequested) {
  return Error::Success;
}

Error
MockKeystoneDevice::destroy() {
  return Error::Success;
}

Error
MockKeystoneDevice::run(uintptr_t* ret) {
  return Error::Success;
}

Error
MockKeystoneDevice::resume(uintptr_t* ret) {
  return Error::Success;
}

Error
MockKeystoneDevice::enterSlot(uintptr_t slotId, uintptr_t* status, uintptr_t* value) {
  return enterSlotWithEpoch(
      SLOTTEE_INITIAL_EPOCH, slotId, SLOTTEE_ENTER_SLOT_FLAG_NONE, status, value);
}

Error
MockKeystoneDevice::enterSlot(
    uintptr_t slotId, uintptr_t flags, uintptr_t* status, uintptr_t* value) {
  return enterSlotWithEpoch(SLOTTEE_INITIAL_EPOCH, slotId, flags, status, value);
}

Error
MockKeystoneDevice::enterSlotWithEpoch(
    uintptr_t epoch, uintptr_t slotId, uintptr_t flags, uintptr_t* status,
    uintptr_t* value) {
  return enterSlotWithVersion(
      SLOTTEE_ENTER_SLOT_VERSION, epoch, slotId, flags, status, value);
}

Error
MockKeystoneDevice::enterSlotWithVersion(
    uintptr_t version, uintptr_t epoch, uintptr_t slotId, uintptr_t flags,
    uintptr_t* status, uintptr_t* value) {
  slot_cap_t cap = makeEnterSlotCap(version, epoch, slotId);
  return enterSlotWithCap(cap, flags, status, value);
}

Error
MockKeystoneDevice::enterSlotWithCap(
    const slot_cap_t& cap, uintptr_t flags, uintptr_t* status, uintptr_t* value) {
  enter_slot_req_t req = makeEnterSlotReq(cap, flags);
  enter_slot_resp_t resp;

  Error ret = enterSlotWithRequest(req, &resp);
  if (status) {
    *status = resp.status;
  }
  if (value) {
    *value = resp.value;
  }

  return ret;
}

Error
MockKeystoneDevice::enterSlotWithRequest(const enter_slot_req_t& req, enter_slot_resp_t* resp) {
  enter_slot_resp_t local_resp;
  memset(&local_resp, 0, sizeof(local_resp));

  if (req.version != SLOTTEE_ENTER_SLOT_VERSION ||
      req.cap.version != SLOTTEE_ENTER_SLOT_VERSION || req.cap.slot_id == 0 ||
      req.cap.slot_id >= SLOTTEE_MAX_SLOTS ||
      (req.flags != SLOTTEE_ENTER_SLOT_FLAG_NONE &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT &&
       req.flags != SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD)) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  } else if (req.cap.epoch != SLOTTEE_INITIAL_EPOCH) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  } else if (req.cap.rights != SLOTTEE_CAP_RIGHT_ENTER || req.cap.cap_seq == 0 ||
             req.cap.max_lease_cycles == 0 || !isSlotCapMacZero(req.cap)) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  } else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_SUCCESS;
    local_resp.value = SLOTTEE_SLOT_MAGIC;
    local_resp.lease_id = 1;
    local_resp.expiry_cycle = req.cap.max_lease_cycles;
  } else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_SUCCESS;
    local_resp.value = SLOTTEE_LT_SCHED_MAGIC;
    local_resp.lease_id = 1;
    local_resp.expiry_cycle = req.cap.max_lease_cycles;
  } else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_SUCCESS;
    local_resp.value = SLOTTEE_LT_CONTEXT_MAGIC;
    local_resp.lease_id = 1;
    local_resp.expiry_cycle = req.cap.max_lease_cycles;
  } else if (req.flags == SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD) {
    local_resp.status = SBI_ERR_SM_ENCLAVE_SUCCESS;
    local_resp.value = SLOTTEE_LT_YIELD_MAGIC;
    local_resp.lease_id = 1;
    local_resp.expiry_cycle = req.cap.max_lease_cycles;
  } else {
    local_resp.status = SBI_ERR_SM_NOT_IMPLEMENTED;
    local_resp.value = 1;
    local_resp.lease_id = 1;
    local_resp.expiry_cycle = req.cap.max_lease_cycles;
  }

  if (resp) {
    *resp = local_resp;
  }
  return Error::Success;
}

bool
MockKeystoneDevice::initDevice(Params params) {
  return true;
}

void*
MockKeystoneDevice::map(uintptr_t addr, size_t size) {
  sharedBuffer = malloc(size);
  return sharedBuffer;
}

MockKeystoneDevice::~MockKeystoneDevice() {
  if (sharedBuffer) free(sharedBuffer);
}

}  // namespace Keystone
