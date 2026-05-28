#ifndef __SM_CALL_H__
#define __SM_CALL_H__

// BKE (Berkeley Keystone Enclave)
#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2

/* 0-1999 are not used (deprecated) */
#define FID_RANGE_DEPRECATED      1999
/* 2000-2999 are called by host */
#define SBI_SM_CREATE_ENCLAVE    2001
#define SBI_SM_DESTROY_ENCLAVE   2002
#define SBI_SM_RUN_ENCLAVE       2003
#define SBI_SM_RESUME_ENCLAVE    2005
#define SBI_SM_ENTER_SLOT        2006
#define SBI_SM_MARK_REVOKE       2007
#define SBI_SM_SLOTTEE_DEBUG     2008
#define FID_RANGE_HOST           2999

#define SLOTTEE_ENTER_SLOT_VERSION     1
#define SLOTTEE_INITIAL_EPOCH          1
#define SLOTTEE_ENTER_SLOT_FLAG_NONE   0
#define SLOTTEE_ENTER_SLOT_FLAG_REAL   1
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT 2
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_CONTEXT 3
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_YIELD 4
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_BIND 5
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_TRAP_SAFE 6
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_ECALL 7
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER 8
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_OCALL 9
#define SLOTTEE_ENTER_SLOT_FLAG_REAL_LT_USER_REVOKE_FAULT 10
#define SLOTTEE_CAP_RIGHT_ENTER        1
#define SLOTTEE_DEFAULT_CAP_SEQ        1
#define SLOTTEE_DEFAULT_MAX_LEASE_CYCLES ((uintptr_t)-1 / 4)
#define SLOTTEE_TEST_MAX_LEASE_CYCLES  1024
#define SLOTTEE_CAP_MAC_WORDS          4
#define SLOTTEE_MAX_SLOTS              8
#define SLOTTEE_SLOT_TOKEN_SLOT_BITS   8
#define SLOTTEE_SLOT_TOKEN_MODE_BITS   8
#define SLOTTEE_SLOT_TOKEN_MODE_SHIFT  SLOTTEE_SLOT_TOKEN_SLOT_BITS
#define SLOTTEE_SLOT_TOKEN_LEASE_SHIFT \
  (SLOTTEE_SLOT_TOKEN_SLOT_BITS + SLOTTEE_SLOT_TOKEN_MODE_BITS)
#define SLOTTEE_SLOT_TOKEN_SLOT_MASK   (((uintptr_t)1 << SLOTTEE_SLOT_TOKEN_SLOT_BITS) - 1)
#define SLOTTEE_SLOT_TOKEN_MODE_MASK   (((uintptr_t)1 << SLOTTEE_SLOT_TOKEN_MODE_BITS) - 1)
#define SLOTTEE_SLOT_TOKEN_MODE_TRAMPOLINE 0
#define SLOTTEE_SLOT_TOKEN_MODE_LT_SCHED   1
#define SLOTTEE_SLOT_TOKEN_MODE_LT_CONTEXT 2
#define SLOTTEE_SLOT_TOKEN_MODE_LT_YIELD   3
#define SLOTTEE_SLOT_TOKEN_MODE_LT_BIND    4
#define SLOTTEE_SLOT_TOKEN_MODE_LT_TRAP_SAFE 5
#define SLOTTEE_SLOT_TOKEN_MODE_LT_ECALL   6
#define SLOTTEE_SLOT_TOKEN_MODE_LT_USER    7
#define SLOTTEE_SLOT_TOKEN_MODE_LT_USER_OCALL 8
#define SLOTTEE_SLOT_TOKEN_MODE_LT_USER_REVOKE_FAULT 9
#define SLOTTEE_MAKE_SLOT_TOKEN(slot_id, lease_id, mode) \
  ((((uintptr_t)(lease_id)) << SLOTTEE_SLOT_TOKEN_LEASE_SHIFT) | \
   (((uintptr_t)(mode)) << SLOTTEE_SLOT_TOKEN_MODE_SHIFT) | ((uintptr_t)(slot_id)))
#define SLOTTEE_SLOT_TOKEN_SLOT_ID(token) \
  ((uintptr_t)(token) & SLOTTEE_SLOT_TOKEN_SLOT_MASK)
#define SLOTTEE_SLOT_TOKEN_MODE(token) \
  (((uintptr_t)(token) >> SLOTTEE_SLOT_TOKEN_MODE_SHIFT) & SLOTTEE_SLOT_TOKEN_MODE_MASK)
#define SLOTTEE_SLOT_TOKEN_LEASE_ID(token) \
  ((uintptr_t)(token) >> SLOTTEE_SLOT_TOKEN_LEASE_SHIFT)
#define SLOTTEE_SLOT_EXIT_NORMAL       0
#define SLOTTEE_SLOT_EXIT_REVOKE       1
#define SLOTTEE_SLOT_MAGIC             0x51515151
#define SLOTTEE_LT_SCHED_MAGIC         0x51515152
#define SLOTTEE_LT_CONTEXT_MAGIC       0x51515153
#define SLOTTEE_LT_YIELD_MAGIC         0x51515154
#define SLOTTEE_LT_BIND_MAGIC          0x51515155
#define SLOTTEE_LT_TRAP_SAFE_MAGIC     0x51515156
#define SLOTTEE_LT_ECALL_MAGIC         0x51515157
#define SLOTTEE_LT_USER_OCALL_MAGIC    0x51515158
#define SLOTTEE_LT_USER_ILLEGAL_MAGIC  0x51515159
#define SLOTTEE_LT_USER_PAGE_FAULT_MAGIC 0x5151515a
#define SLOTTEE_LT_ECALL_REQ_MAGIC     0x51580000
#define SLOTTEE_LT_ECALL_REPLY_MAGIC   0x51590000
#define SLOTTEE_LT_ECALL_TOKEN_SHIFT   8
#define SLOTTEE_LT_ECALL_TOKEN_MASK    0xff
#define SLOTTEE_LT_ECALL_MAKE_REQUEST(slot_id, lease_id) \
  (SLOTTEE_LT_ECALL_REQ_MAGIC | \
   (((uintptr_t)(slot_id)) << SLOTTEE_LT_ECALL_TOKEN_SHIFT) | \
   ((uintptr_t)(lease_id) & SLOTTEE_LT_ECALL_TOKEN_MASK))
#define SLOTTEE_LT_ECALL_MAKE_REPLY(slot_id, lease_id) \
  (SLOTTEE_LT_ECALL_REPLY_MAGIC | \
   (((uintptr_t)(slot_id)) << SLOTTEE_LT_ECALL_TOKEN_SHIFT) | \
   ((uintptr_t)(lease_id) & SLOTTEE_LT_ECALL_TOKEN_MASK))

/* 3000-3999 are called by enclave */
#define SBI_SM_RANDOM            3001
#define SBI_SM_ATTEST_ENCLAVE    3002
#define SBI_SM_GET_SEALING_KEY   3003
#define SBI_SM_STOP_ENCLAVE      3004
#define SBI_SM_EXIT_SLOT         3005
#define SBI_SM_EXIT_ENCLAVE      3006
#define SBI_SM_LT_ECALL_PROBE    3007
#define SBI_SM_INIT_REENTRY_TEMPLATE 3008
#define SBI_SM_MINT_SLOT_CAP     3009
#define FID_RANGE_ENCLAVE        3999

/* 4000-4999 are experimental */
#define SBI_SM_CALL_PLUGIN        4000
#define FID_RANGE_CUSTOM          4999

/* Plugin IDs and Call IDs */
#define SM_MULTIMEM_PLUGIN_ID   0x01
#define SM_MULTIMEM_CALL_GET_SIZE 0x01
#define SM_MULTIMEM_CALL_GET_ADDR 0x02

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2

/* Structs for interfacing into the SM */
struct runtime_params_t {
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
  uintptr_t untrusted_base;
  uintptr_t untrusted_size;
  uintptr_t free_requested; // for attestation
  uintptr_t slot_entry;
};

struct keystone_sbi_pregion_t {
  uintptr_t paddr;
  size_t size;
};

struct keystone_sbi_create_t {
  struct keystone_sbi_pregion_t epm_region;
  struct keystone_sbi_pregion_t utm_region;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;
  uintptr_t slot_entry;
};

struct slot_cap_t {
  uintptr_t version;
  uintptr_t eid;
  uintptr_t slot_id;
  uintptr_t epoch;
  uintptr_t cap_seq;
  uintptr_t rights;
  uintptr_t max_lease_cycles;
  uintptr_t cap_mac[SLOTTEE_CAP_MAC_WORDS];
};

struct enter_slot_req_t {
  uintptr_t version;
  struct slot_cap_t cap;
  uintptr_t flags;
  uintptr_t host_nonce;
  uintptr_t rt_nonce;
};

struct enter_slot_resp_t {
  uintptr_t status;
  uintptr_t value;
  uintptr_t lease_id;
  uintptr_t bound_hart;
  uintptr_t expiry_cycle;
};

struct exit_slot_req_t {
  uintptr_t version;
  uintptr_t slot_id;
  uintptr_t lease_id;
  uintptr_t exit_reason;
  uintptr_t value;
};

struct exit_slot_resp_t {
  uintptr_t status;
  uintptr_t value;
};

struct mark_revoke_req_t {
  uintptr_t version;
  uintptr_t slot_id;
};

struct mark_revoke_resp_t {
  uintptr_t status;
  uintptr_t epoch;
};

#define SLOTTEE_MINT_CAP_VERSION 1

struct mint_slot_cap_req_t {
  uintptr_t version;
  uintptr_t slot_id;
  uintptr_t cap_seq;
  uintptr_t rights;
  uintptr_t max_lease_cycles;
};

struct mint_slot_cap_resp_t {
  uintptr_t status;
  struct slot_cap_t cap;
};

#define SLOTTEE_DEBUG_VERSION              1
#define SLOTTEE_DEBUG_OP_REENTRY_STATUS    1
#define SLOTTEE_DEBUG_OP_REENTRY_CLEAR     2
#define SLOTTEE_DEBUG_OP_CAP_KEY_STATUS    3
/* Legacy host-side debug/test mint. Production mint is RT-authorized and SM-signed. */
#ifdef SLOTTEE_DEBUG_MINT_ENABLE
#define SLOTTEE_DEBUG_OP_MINT_CAP          4
#endif

struct slottee_debug_req_t {
  uintptr_t version;
  uintptr_t op;
  struct slot_cap_t cap;
};

struct slottee_debug_resp_t {
  uintptr_t status;
  uintptr_t reentry_ready;
  uintptr_t epoch;
  uintptr_t n_thread;
  uintptr_t busy_slots;
  uintptr_t cap_key_ready;
  uintptr_t cap_key_generation;
  struct slot_cap_t cap;
};

#endif  // __SM_CALL_H__
