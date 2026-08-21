#ifndef HEADER_fd_src_disco_fd_txn_p_h
#define HEADER_fd_src_disco_fd_txn_p_h

#include "../ballet/txn/fd_txn.h"

struct __attribute__((aligned(64))) fd_txn_p {
  uchar payload[FD_TPU_MTU];
  ulong payload_sz;
  union {
   struct {
     uint non_execution_cus;
     uint requested_exec_plus_acct_data_cus;
   } pack_cu; /* Populated by pack. Execle reads these to populate the other struct of the union. */
   struct {
     uint rebated_cus; /* requested_exec_plus_acct_data_cus-actual used CUs. Pack reads this for CU rebating. */
     uint actual_consumed_cus; /* non_execution_cus+real execution CUs+real account data cus. PoH reads this for block CU counting. */
   } execle_cu; /* Populated by execle. */
   ulong blockhash_slot; /* Slot provided by resolv tile when txn arrives at the pack tile. Used when txn is in extra storage in pack. */
  };
  /* Wallclock nanoseconds at which the transaction arrived to the pack tile. Set by pack and intended to be read from a transaction on a pack->execle link. */
  long scheduler_arrival_time_nanos;

  /* Wallclock nanoseconds at which the validator first saw the
     transaction. */
  long first_seen_nanos;

  union {
    struct {
      /* set by replay scheduler for use by monitoring tools */
      ushort start_shred_idx; /* the shred index of the shred containing the first byte of this transaction */
      ushort end_shred_idx; /* the shred index of the shred containing the byte after the last byte of this transaction, capped at the maximum shred index for this block */
    };
    /* pack populates pack_alloc based on an estimate of how many bytes
       of account data the transaction may allocate.  There should be a
       field called rebate_alloc, similar to the CU variables, but
       actually the rebated alloc bytes don't really depend on
       execution. */
    uint pack_alloc;
  };

  /* Source ipv4 address and tpu pipeline for this transaction. TPU is one of FD_TXN_M_TPU_SOURCE_* */
  uchar source_tpu;
  uint  source_ipv4;

  /* Populated by pack, execle.  A combination of the bitfields
     FD_TXN_P_FLAGS_* defined above.  The execle sets the high byte with
     the transaction result code. */
  uint  flags;
  /* union {
    This would be ideal but doesn't work because of the flexible array member
    uchar _[FD_TXN_MAX_SZ];
    fd_txn_t txn;
  }; */
  /* Access with TXN macro below */
  uchar _[FD_TXN_MAX_SZ] __attribute__((aligned(alignof(fd_txn_t))));
};

typedef struct fd_txn_p fd_txn_p_t;

#define TXN(txn_p) ((fd_txn_t *)( (txn_p)->_ ))

/* fd_txn_e_t: An fd_txn_p_t with expanded address lookup tables.
   Legacy and V0 payloads are at most FD_TXN_MTU_V0 and V1 does not support
   ALTs, so the ALT addresses can share the otherwise unused V1 payload
   tail.  Start at the next cache line because pack copies the first
   1280 payload bytes with aligned AVX-512 stores. */
#define FD_TXN_E_ALT_ACCTS_OFF (1280UL)

struct __attribute__((aligned(64))) fd_txn_e {
  union {
    fd_txn_p_t txnp[1];
    struct {
      uchar          _payload_prefix[ FD_TXN_E_ALT_ACCTS_OFF ];
      fd_acct_addr_t alt_accts[ FD_TXN_ACCT_ADDR_MAX ]; /* The used account count is in the fd_txn_t */
    };
  };
};

typedef struct fd_txn_e fd_txn_e_t;

FD_STATIC_ASSERT( FD_TXN_E_ALT_ACCTS_OFF==FD_ULONG_ALIGN_UP( FD_TXN_MTU_V0, 64UL ), fd_txn_e_alt_accts_off );
FD_STATIC_ASSERT( __builtin_offsetof(fd_txn_e_t, alt_accts)==FD_TXN_E_ALT_ACCTS_OFF, fd_txn_e_alt_accts_off );
FD_STATIC_ASSERT( FD_TXN_E_ALT_ACCTS_OFF+FD_TXN_ACCT_ADDR_MAX*sizeof(fd_acct_addr_t)<=FD_TPU_MTU, fd_txn_e_alt_accts );
FD_STATIC_ASSERT( sizeof(fd_txn_e_t)==sizeof(fd_txn_p_t),                          fd_txn_e_footprint );

#endif /* HEADER_fd_src_disco_fd_txn_p_h */
