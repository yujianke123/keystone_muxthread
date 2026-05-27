//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>

struct enclave enclaves[ENCL_MAX];

// Enclave IDs are unsigned ints, so we do not need to check if eid is
// greater than or equal to 0
#define ENCLAVE_EXISTS(eid) (eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

static int enclave_has_busy_slot_leases(enclave_id eid);

static uintptr_t read_cycle(void)
{
  uintptr_t cycle;

  asm volatile ("rdcycle %0" : "=r" (cycle));
  return cycle;
}

static uintptr_t slot_lease_expiry(uintptr_t now, uintptr_t ttl)
{
  if (((uintptr_t)-1) - now < ttl)
    return (uintptr_t)-1;

  return now + ttl;
}

static uintptr_t enclave_slot_thread_index(uintptr_t slot_id)
{
  if (slot_id < MAX_ENCL_THREADS)
    return slot_id;

  return 0;
}

static int enclave_slot_state_is_activatable(enclave_id eid)
{
  if (enclaves[eid].state == FRESH)
    return 1;

  return enclaves[eid].state == STOPPED &&
      enclaves[eid].n_thread == 0 &&
      enclaves[eid].slot_reentry_ready &&
      enclaves[eid].params.slot_entry != enclaves[eid].params.dram_base &&
      !enclave_has_busy_slot_leases(eid);
}

static void clear_enclave_slot_leases(enclave_id eid)
{
  size_t slot;

  enclaves[eid].next_slot_lease_id = 1;
  enclaves[eid].current_slot_epoch = SLOTTEE_INITIAL_EPOCH;
  for(slot = 0; slot < SLOTTEE_MAX_SLOTS; slot++) {
    enclaves[eid].slot_leases[slot].slot_id = slot;
    enclaves[eid].slot_leases[slot].lease_id = 0;
    enclaves[eid].slot_leases[slot].epoch = 0;
    enclaves[eid].slot_leases[slot].cap_seq = 0;
    enclaves[eid].slot_leases[slot].rights = 0;
    enclaves[eid].slot_leases[slot].max_lease_cycles = 0;
    enclaves[eid].slot_leases[slot].bound_hart = 0;
    enclaves[eid].slot_leases[slot].expiry_cycle = 0;
    enclaves[eid].slot_leases[slot].entry_pc = 0;
    enclaves[eid].slot_leases[slot].exit_reason = 0;
    enclaves[eid].slot_leases[slot].active_hart = 0;
    enclaves[eid].slot_leases[slot].thread_index = 0;
    enclaves[eid].slot_leases[slot].revoke_pending = 0;
    enclaves[eid].slot_leases[slot].state = SLOT_LEASE_FREE;
  }
}

static void revoke_enclave_slot_lease(struct slot_lease_t *lease)
{
  lease->rights = 0;
  lease->max_lease_cycles = 0;
  lease->active_hart = 0;
  lease->thread_index = 0;
  lease->revoke_pending = 0;
  lease->state = SLOT_LEASE_REVOKED;
}

static void free_enclave_slot_lease(struct slot_lease_t *lease)
{
  uintptr_t slot_id = lease->slot_id;

  lease->slot_id = slot_id;
  lease->lease_id = 0;
  lease->epoch = 0;
  lease->cap_seq = 0;
  lease->rights = 0;
  lease->max_lease_cycles = 0;
  lease->bound_hart = 0;
  lease->expiry_cycle = 0;
  lease->entry_pc = 0;
  lease->exit_reason = 0;
  lease->active_hart = 0;
  lease->thread_index = 0;
  lease->revoke_pending = 0;
  lease->state = SLOT_LEASE_FREE;
}

static int slot_lease_is_busy(const struct slot_lease_t *lease)
{
  return lease->state == SLOT_LEASE_RESERVED ||
         lease->state == SLOT_LEASE_ACTIVE ||
         lease->state == SLOT_LEASE_EXITING;
}

static int slot_lease_has_pending_revoke(const struct slot_lease_t *lease)
{
  return lease &&
      lease->state == SLOT_LEASE_ACTIVE &&
      lease->revoke_pending;
}

static void mark_slot_lease_revoke_pending(struct slot_lease_t *lease)
{
  if (lease && lease->state == SLOT_LEASE_ACTIVE)
    lease->revoke_pending = 1;
}

static void complete_pending_revoke_enclave_slot(
    enclave_id eid, struct slot_lease_t *lease)
{
  if (!slot_lease_has_pending_revoke(lease))
    return;

  lease->exit_reason = SLOTTEE_SLOT_EXIT_REVOKE;
  revoke_enclave_slot_lease(lease);
  enclaves[eid].current_slot_epoch++;
}

static int enclave_has_busy_slot_leases(enclave_id eid)
{
  size_t slot;

  for(slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    if (slot_lease_is_busy(&enclaves[eid].slot_leases[slot]))
      return 1;
  }

  return 0;
}

static void save_enclave_slot_reentry_template(enclave_id eid, uintptr_t thread_index)
{
  if (thread_index == 0 || thread_index >= MAX_ENCL_THREADS ||
      enclaves[eid].params.slot_entry == enclaves[eid].params.dram_base)
    return;

  enclaves[eid].slot_reentry_csrs = enclaves[eid].threads[thread_index].prev_csrs;
  enclaves[eid].slot_reentry_mstatus =
      enclaves[eid].threads[thread_index].prev_mstatus;
  enclaves[eid].slot_reentry_ready = 1;
}

static int prepare_enclave_slot_reentry(
    enclave_id eid, uintptr_t thread_index, uintptr_t slot_token)
{
  struct thread_state *thread;

  if (!enclaves[eid].slot_reentry_ready ||
      thread_index == 0 || thread_index >= MAX_ENCL_THREADS ||
      enclaves[eid].params.slot_entry == enclaves[eid].params.dram_base)
    return 0;

  thread = &enclaves[eid].threads[thread_index];
  clean_state(thread);
  thread->prev_csrs = enclaves[eid].slot_reentry_csrs;
  thread->prev_mstatus = enclaves[eid].slot_reentry_mstatus;
  thread->prev_mepc = enclaves[eid].params.slot_entry - 4;
  thread->prev_state.t6 = slot_token;

  return 1;
}

static struct slot_lease_t *find_active_slot_lease_by_thread_index(
    enclave_id eid, uintptr_t thread_index)
{
  size_t slot;

  for(slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    struct slot_lease_t *lease = &enclaves[eid].slot_leases[slot];

    if (lease->state == SLOT_LEASE_ACTIVE &&
        lease->thread_index == thread_index)
      return lease;
  }

  return NULL;
}

static void revoke_all_enclave_slot_leases(enclave_id eid)
{
  size_t slot;
  int revoked = 0;

  for(slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    if (slot_lease_is_busy(&enclaves[eid].slot_leases[slot])) {
      revoke_enclave_slot_lease(&enclaves[eid].slot_leases[slot]);
      revoked = 1;
    }
  }

  if (revoked)
    enclaves[eid].current_slot_epoch++;
}

static void reclaim_expired_enclave_slot_leases(enclave_id eid, uintptr_t now)
{
  size_t slot;
  int revoked = 0;

  for(slot = 1; slot < SLOTTEE_MAX_SLOTS; slot++) {
    struct slot_lease_t *lease = &enclaves[eid].slot_leases[slot];

    if (lease->state == SLOT_LEASE_RESERVED && now >= lease->expiry_cycle) {
      revoke_enclave_slot_lease(lease);
      revoked = 1;
    }
  }

  if (revoked)
    enclaves[eid].current_slot_epoch++;
}

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                uintptr_t thread_index,
                                                int load_parameters,
                                                uintptr_t entry_arg){
  struct thread_state *thread = &enclaves[eid].threads[thread_index];

  /* save host context */
  swap_prev_state(thread, regs, 1);
  swap_prev_mepc(thread, regs, regs->mepc);
  swap_prev_mstatus(thread, regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    uintptr_t entry_pc = enclaves[eid].params.dram_base;
    regs->mepc = entry_pc - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a0: SlotTEE slot token. Zero preserves the original slot 0 run path.
    regs->a0 = entry_arg;
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].params.dram_base;
    // $a2: DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].params.free_base;
    // $a6: (PA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_base;
    // $a7: utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;

    // enclave will only have physical addresses in the first run
    csr_write(satp, 0);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid, thread_index);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    uintptr_t thread_index,
    int return_on_resume){
  struct thread_state *thread = &enclaves[eid].threads[thread_index];

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(thread, regs, return_on_resume);
  swap_prev_mepc(thread, regs, regs->mepc);
  swap_prev_mstatus(thread, regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(void){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    clear_enclave_slot_leases(eid);
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create_t));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create_t* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;
  
  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create_t create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;
  size_t thread;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set params */
  struct runtime_params_t params;
  params.dram_base = base;
  params.dram_size = size;
  params.runtime_base = create_args.runtime_paddr;
  params.user_base = create_args.user_paddr;
  params.free_base = create_args.free_paddr;
  params.untrusted_base = utbase;
  params.untrusted_size = utsize;
  params.free_requested = create_args.free_requested;
  params.slot_entry = create_args.slot_entry ? create_args.slot_entry : base;


  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].stopped_thread_index = 0;
  enclaves[eid].slot_reentry_ready = 0;
  enclaves[eid].slot_reentry_csrs = (struct csrs) {0};
  enclaves[eid].slot_reentry_mstatus = 0;
  enclaves[eid].params = params;
  clear_enclave_slot_leases(eid);

  /* Init enclave state (regs etc) */
  for (thread = 0; thread < MAX_ENCL_THREADS; thread++)
    clean_state(&enclaves[eid].threads[thread]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
 
  ret = validate_and_hash_enclave(&enclaves[eid]);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;

  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;

  spin_lock(&encl_lock);
  revoke_all_enclave_slot_leases(eid);
  spin_unlock(&encl_lock);

  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].stopped_thread_index = 0;
  enclaves[eid].slot_reentry_ready = 0;
  enclaves[eid].slot_reentry_csrs = (struct csrs) {0};
  enclaves[eid].slot_reentry_mstatus = 0;
  enclaves[eid].params = (struct runtime_params_t) {0};
  clear_enclave_slot_leases(eid);
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }
  for(i=0; i < MAX_ENCL_THREADS; i++){
    clean_state(&enclaves[eid].threads[i]);
  }

  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_slot_cap_mac_zero(const struct slot_cap_t *cap)
{
  size_t word;

  for (word = 0; word < SLOTTEE_CAP_MAC_WORDS; word++) {
    if (cap->cap_mac[word] != 0)
      return 0;
  }

  return 1;
}

unsigned long reserve_enclave_slot(
    enclave_id eid, const struct slot_cap_t *cap, struct enter_slot_resp_t *resp)
{
  unsigned long ret = SBI_ERR_SM_NOT_IMPLEMENTED;
  struct slot_lease_t *lease;
  uintptr_t now;

  if (!cap)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (cap->slot_id == 0 || cap->slot_id >= SLOTTEE_MAX_SLOTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);

  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state < FRESH) {
    ret = SBI_ERR_SM_ENCLAVE_INVALID_ID;
    goto out;
  }

  now = read_cycle();
  reclaim_expired_enclave_slot_leases(eid, now);

  if (cap->eid != eid || cap->epoch != enclaves[eid].current_slot_epoch) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_FRESH;
    goto out;
  }

  if (cap->rights != SLOTTEE_CAP_RIGHT_ENTER || cap->cap_seq == 0 ||
      cap->max_lease_cycles == 0 || !is_slot_cap_mac_zero(cap)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  lease = &enclaves[eid].slot_leases[cap->slot_id];
  if (slot_lease_is_busy(lease)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  lease->slot_id = cap->slot_id;
  lease->lease_id = enclaves[eid].next_slot_lease_id++;
  lease->epoch = cap->epoch;
  lease->cap_seq = cap->cap_seq;
  lease->rights = cap->rights;
  lease->max_lease_cycles = cap->max_lease_cycles;
  lease->bound_hart = csr_read(mhartid);
  lease->expiry_cycle = slot_lease_expiry(now, cap->max_lease_cycles);
  lease->entry_pc = enclaves[eid].params.slot_entry;
  lease->exit_reason = 0;
  lease->active_hart = 0;
  lease->thread_index = enclave_slot_thread_index(cap->slot_id);
  lease->state = SLOT_LEASE_RESERVED;

  if (resp) {
    resp->value = lease->lease_id;
    resp->lease_id = lease->lease_id;
    resp->bound_hart = lease->bound_hart;
    resp->expiry_cycle = lease->expiry_cycle;
  }

out:
  if (resp)
    resp->status = ret;
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long activate_enclave_slot(
    enclave_id eid, const struct slot_cap_t *cap, struct enter_slot_resp_t *resp)
{
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  struct slot_lease_t *lease;
  uintptr_t now;

  if (!cap)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (cap->slot_id == 0 || cap->slot_id >= SLOTTEE_MAX_SLOTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);

  if (!ENCLAVE_EXISTS(eid) || !enclave_slot_state_is_activatable(eid)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_FRESH;
    goto out;
  }

  now = read_cycle();
  reclaim_expired_enclave_slot_leases(eid, now);

  if (cap->eid != eid || cap->epoch != enclaves[eid].current_slot_epoch) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_FRESH;
    goto out;
  }

  if (cap->rights != SLOTTEE_CAP_RIGHT_ENTER || cap->cap_seq == 0 ||
      cap->max_lease_cycles == 0 || !is_slot_cap_mac_zero(cap)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  lease = &enclaves[eid].slot_leases[cap->slot_id];
  if (slot_lease_is_busy(lease)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  lease->slot_id = cap->slot_id;
  lease->lease_id = enclaves[eid].next_slot_lease_id++;
  lease->epoch = cap->epoch;
  lease->cap_seq = cap->cap_seq;
  lease->rights = cap->rights;
  lease->max_lease_cycles = cap->max_lease_cycles;
  lease->bound_hart = csr_read(mhartid);
  lease->expiry_cycle = slot_lease_expiry(now, cap->max_lease_cycles);
  lease->entry_pc = enclaves[eid].params.slot_entry;
  lease->exit_reason = 0;
  lease->active_hart = csr_read(mhartid);
  lease->thread_index = enclave_slot_thread_index(cap->slot_id);
  lease->state = SLOT_LEASE_ACTIVE;
  enclaves[eid].state = RUNNING;
  enclaves[eid].n_thread++;
  clean_state(&enclaves[eid].threads[lease->thread_index]);

  if (resp) {
    resp->status = SBI_ERR_SM_ENCLAVE_SUCCESS;
    resp->value = lease->lease_id;
    resp->lease_id = lease->lease_id;
    resp->bound_hart = lease->bound_hart;
    resp->expiry_cycle = lease->expiry_cycle;
  }

out:
  if (resp)
    resp->status = ret;
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long mark_revoke_enclave_slot(
    enclave_id eid, const struct mark_revoke_req_t *req, struct mark_revoke_resp_t *resp)
{
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  struct slot_lease_t *lease;

  if (!req || req->version != SLOTTEE_ENTER_SLOT_VERSION ||
      req->slot_id == 0 || req->slot_id >= SLOTTEE_MAX_SLOTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);

  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state < FRESH) {
    ret = SBI_ERR_SM_ENCLAVE_INVALID_ID;
    goto out;
  }

  lease = &enclaves[eid].slot_leases[req->slot_id];
  if (lease->state == SLOT_LEASE_ACTIVE) {
    mark_slot_lease_revoke_pending(lease);
    if (resp)
      resp->epoch = enclaves[eid].current_slot_epoch + 1;
    goto out;
  }

  if (slot_lease_is_busy(lease))
    revoke_enclave_slot_lease(lease);

  enclaves[eid].current_slot_epoch++;
  if (resp)
    resp->epoch = enclaves[eid].current_slot_epoch;

out:
  if (resp) {
    resp->status = ret;
    if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
      resp->epoch = 0;
  }
  spin_unlock(&encl_lock);
  return ret;
}

void enter_activated_enclave_slot(
    struct sbi_trap_regs *regs, enclave_id eid, uintptr_t slot_id, uintptr_t lease_id,
    uintptr_t slot_mode)
{
  uintptr_t thread_index = enclave_slot_thread_index(slot_id);
  uintptr_t slot_token = SLOTTEE_MAKE_SLOT_TOKEN(slot_id, lease_id, slot_mode);

  if (prepare_enclave_slot_reentry(eid, thread_index, slot_token))
    context_switch_to_enclave(regs, eid, thread_index, 0, 0);
  else
    context_switch_to_enclave(regs, eid, thread_index, 1, slot_token);
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 0, 1, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;
  uintptr_t thread_index = cpu_get_enclave_thread_index();

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING && thread_index < MAX_ENCL_THREADS;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, thread_index, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave_slot(
    struct sbi_trap_regs *regs, enclave_id eid, uintptr_t slot_id, uintptr_t lease_id,
    uintptr_t exit_reason, uintptr_t value)
{
  int exitable;
  struct slot_lease_t *lease;
  uintptr_t thread_index;

  if (slot_id == 0 || slot_id >= SLOTTEE_MAX_SLOTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  exitable = ENCLAVE_EXISTS(eid) && enclaves[eid].state == RUNNING;
  if (!exitable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
  }

  lease = &enclaves[eid].slot_leases[slot_id];
  if (lease->state != SLOT_LEASE_ACTIVE ||
      lease->lease_id != lease_id ||
      lease->active_hart != csr_read(mhartid)) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  thread_index = lease->thread_index;
  lease->exit_reason = exit_reason;
  lease->state = SLOT_LEASE_EXITING;
  enclaves[eid].n_thread--;
  if(enclaves[eid].n_thread == 0)
    enclaves[eid].state = STOPPED;
  spin_unlock(&encl_lock);

  context_switch_to_host(regs, eid, thread_index, 0);

  spin_lock(&encl_lock);
  save_enclave_slot_reentry_template(eid, thread_index);
  free_enclave_slot_lease(lease);
  if (exit_reason == SLOTTEE_SLOT_EXIT_REVOKE)
    enclaves[eid].current_slot_epoch++;
  spin_unlock(&encl_lock);

  (void)value;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;
  int complete_timer_revoke = 0;
  uintptr_t thread_index = cpu_get_enclave_thread_index();
  struct slot_lease_t *lease = NULL;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING && thread_index < MAX_ENCL_THREADS;
  if (stoppable) {
    lease = find_active_slot_lease_by_thread_index(eid, thread_index);
    complete_timer_revoke =
        request == STOP_TIMER_INTERRUPT && slot_lease_has_pending_revoke(lease);
    enclaves[eid].stopped_thread_index = thread_index;
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, thread_index, request == STOP_EDGE_CALL_HOST);

  if (complete_timer_revoke) {
    spin_lock(&encl_lock);
    lease = find_active_slot_lease_by_thread_index(eid, thread_index);
    if (slot_lease_has_pending_revoke(lease)) {
      save_enclave_slot_reentry_template(eid, thread_index);
      complete_pending_revoke_enclave_slot(eid, lease);
    }
    spin_unlock(&encl_lock);
  }

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;
  uintptr_t thread_index;
  struct slot_lease_t *lease = NULL;

  spin_lock(&encl_lock);
  thread_index = enclaves[eid].stopped_thread_index;
  if (thread_index != 0)
    lease = find_active_slot_lease_by_thread_index(eid, thread_index);

  if (slot_lease_has_pending_revoke(lease)) {
    save_enclave_slot_reentry_template(eid, thread_index);
    complete_pending_revoke_enclave_slot(eid, lease);
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  }

  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS
               && thread_index < MAX_ENCL_THREADS
               && (thread_index == 0 || lease));

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    if (lease)
      lease->active_hart = csr_read(mhartid);
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, thread_index, 0, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
