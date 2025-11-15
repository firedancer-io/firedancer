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
   } pack_cu; /* Populated by pack. Bank reads these to populate the other struct of the union. */
   struct {
     uint rebated_cus; /* requested_exec_plus_acct_data_cus-actual used CUs. Pack reads this for CU rebating. */
     uint actual_consumed_cus; /* non_execution_cus+real execution CUs+real account data cus. PoH reads this for block CU counting. */
   } bank_cu; /* Populated by bank. */
   ulong reference_block_height; /* Block height provided by resolv tile when txn arrives at the pack tile. */
  };
  /* The time that the transaction arrived to the pack tile in ticks. Set by pack and intended to be read from a transaction on a pack->bank link. */
  long scheduler_arrival_time_nanos;

  /* set by replay scheduler for use by monitoring tools */
  ushort start_shred_idx; /* the shred index of the shred containing the first byte of this transaction */
  ushort end_shred_idx; /* the shred index of the shred containing the byte after the last byte of this transaction, capped at the maximum shred index for this block */

  /* Source ipv4 address and tpu pipeline for this transaction. TPU is one of FD_TXN_M_TPU_SOURCE_* */
  uchar source_tpu;
  uint  source_ipv4;

  /* Populated by pack, bank.  A combination of the bitfields
     FD_TXN_P_FLAGS_* defined above.  The bank sets the high byte with
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

/* fd_txn_e_t: An fd_txn_p_t with expanded address lookup tables */
struct __attribute__((aligned(64))) fd_txn_e {
   fd_txn_p_t     txnp[1];
   fd_acct_addr_t alt_accts[FD_TXN_ACCT_ADDR_MAX]; /* The used account is in the fd_txn_t*/
};

typedef struct fd_txn_e fd_txn_e_t;

#endif /* HEADER_fd_src_disco_fd_txn_p_h */
