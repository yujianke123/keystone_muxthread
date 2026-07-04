//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "./common.h"
#include "Error.hpp"
#include "Params.hpp"
#include "shared/keystone_user.h"

namespace Keystone {

class KeystoneDevice {
 protected:
  int eid;
  uintptr_t physAddr;

 private:
  int fd;
  Error __run(bool resume, uintptr_t* ret);

 public:
  virtual uintptr_t getPhysAddr() { return physAddr; }

  KeystoneDevice();
  virtual ~KeystoneDevice() {}
  virtual bool initDevice(Params params);
  virtual Error create(uint64_t minPages);
  virtual uintptr_t initUTM(size_t size);
  virtual Error finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested, uintptr_t slotEntry = 0);
  virtual Error destroy();
  virtual Error run(uintptr_t* ret);
  virtual Error resume(uintptr_t* ret);
  virtual Error enterSlot(uintptr_t slotId, uintptr_t* status, uintptr_t* value);
  virtual Error enterSlot(
      uintptr_t slotId, uintptr_t flags, uintptr_t* status, uintptr_t* value);
  virtual Error enterSlotWithEpoch(
      uintptr_t epoch, uintptr_t slotId, uintptr_t flags, uintptr_t* status,
      uintptr_t* value);
  virtual Error enterSlotWithVersion(
      uintptr_t version, uintptr_t epoch, uintptr_t slotId, uintptr_t flags, uintptr_t* status,
      uintptr_t* value);
  virtual Error enterSlotWithCap(
      const slot_cap_t& cap, uintptr_t flags, uintptr_t* status, uintptr_t* value);
  virtual Error enterSlotWithRequest(const enter_slot_req_t& req, enter_slot_resp_t* resp);
  virtual Error markRevoke(uintptr_t slotId, uintptr_t* status, uintptr_t* epoch);
  virtual Error slotteeDebug(const slottee_debug_req_t& req, slottee_debug_resp_t* resp);
  virtual Error leaseWatchdogCheck(uintptr_t* status, uintptr_t* reclaimed);
  virtual void* map(uintptr_t addr, size_t size);
};

class MockKeystoneDevice : public KeystoneDevice {
 private:
  /* allocated buffer with map() */
  void* sharedBuffer;

 public:
  MockKeystoneDevice() {}
  ~MockKeystoneDevice();
  bool initDevice(Params params);
  Error create(uint64_t minPages);
  uintptr_t initUTM(size_t size);
  Error finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested, uintptr_t slotEntry = 0);
  Error destroy();
  Error run(uintptr_t* ret);
  Error resume(uintptr_t* ret);
  Error enterSlot(uintptr_t slotId, uintptr_t* status, uintptr_t* value);
  Error enterSlot(uintptr_t slotId, uintptr_t flags, uintptr_t* status, uintptr_t* value);
  Error enterSlotWithEpoch(
      uintptr_t epoch, uintptr_t slotId, uintptr_t flags, uintptr_t* status,
      uintptr_t* value);
  Error enterSlotWithVersion(
      uintptr_t version, uintptr_t epoch, uintptr_t slotId, uintptr_t flags, uintptr_t* status,
      uintptr_t* value);
  Error enterSlotWithCap(
      const slot_cap_t& cap, uintptr_t flags, uintptr_t* status, uintptr_t* value);
  Error enterSlotWithRequest(const enter_slot_req_t& req, enter_slot_resp_t* resp);
  Error markRevoke(uintptr_t slotId, uintptr_t* status, uintptr_t* epoch);
  Error slotteeDebug(const slottee_debug_req_t& req, slottee_debug_resp_t* resp);
  Error leaseWatchdogCheck(uintptr_t* status, uintptr_t* reclaimed);
  void* map(uintptr_t addr, size_t size);
};

}  // namespace Keystone
