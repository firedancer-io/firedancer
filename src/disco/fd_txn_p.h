#ifndef HEADER_fd_src_disco_fd_txn_p_h
#define HEADER_fd_src_disco_fd_txn_p_h

#include "../ballet/txn/fd_txn.h"
#include <stddef.h>

struct __attribute__((aligned(64))) fd_txn_p {
  uchar payload[FD_TPU_MTU];

  /* Keep metadata within 40 bytes so fd_txn_p_t fits in 4992 bytes. */

  /* Size of payload in bytes, at most FD_TPU_MTU. */
  ushort payload_sz;

  /* Source ipv4 address and tpu pipeline for this transaction. TPU is
     one of FD_TXN_M_TPU_SOURCE_* */
  uchar source_tpu;
  uint  source_ipv4;

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

FD_STATIC_ASSERT( FD_TPU_MTU<=USHORT_MAX, fd_txn_p_payload_sz );
FD_STATIC_ASSERT( sizeof(fd_txn_p_t)==4992UL, fd_txn_p_layout );

#define TXN(txn_p) ((fd_txn_t *)( (txn_p)->_ ))

static inline void
fd_txn_p_copy( fd_txn_p_t *       dst,
               fd_txn_p_t const * src ) {
  fd_txn_t const * txn = TXN( src );
  ulong meta_off = offsetof(fd_txn_p_t, payload_sz);
  ulong desc_sz  = fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt );
  fd_memcpy( dst->payload, src->payload, src->payload_sz );
  fd_memcpy( (uchar *)dst+meta_off, (uchar const *)src+meta_off, offsetof(fd_txn_p_t, _)-meta_off );
  fd_memcpy( dst->_, src->_, desc_sz );
}

/* fd_txn_e_t: An fd_txn_p_t with expanded address lookup tables */
struct __attribute__((aligned(64))) fd_txn_e {
   fd_txn_p_t     txnp[1];
   fd_acct_addr_t alt_accts[FD_TXN_ACCT_ADDR_MAX]; /* The used account is in the fd_txn_t*/
};

typedef struct fd_txn_e fd_txn_e_t;

#endif /* HEADER_fd_src_disco_fd_txn_p_h */
