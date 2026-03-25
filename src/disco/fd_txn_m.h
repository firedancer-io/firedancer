#ifndef HEADER_fd_src_disco_fd_txn_m_h
#define HEADER_fd_src_disco_fd_txn_m_h

/* A fd_txn_m_t is a parsed meta transaction, containing not just the
   payload */

#include "../ballet/txn/fd_txn.h"

#define FD_TXN_M_TPU_SOURCE_QUIC   (1UL)
#define FD_TXN_M_TPU_SOURCE_UDP    (2UL)
#define FD_TXN_M_TPU_SOURCE_GOSSIP (3UL)
#define FD_TXN_M_TPU_SOURCE_BUNDLE (4UL)
#define FD_TXN_M_TPU_SOURCE_TXSEND (5UL)

struct fd_txn_m {
  /* The computed slot that this transaction is referencing, aka. the
     slot number of the reference_blockhash.  If it could not be
     determined, this will be the current slot. */
  ulong    reference_slot;

  ushort   payload_sz;

  /* Can be computed from the txn_t but it's expensive to parse again,
     so we just store this redundantly. */
  ushort    txn_t_sz;

  /* Source tpu and IP address for this transaction.  Note that
     source_ipv4 is in big endian. */
  uint     source_ipv4;
  uchar    source_tpu;

  /* 7 bytes of padding here */

  struct {
    /* If the transaction is part of a bundle, the bundle_id will be
       non-zero, and if this transaction is the first one in the
       bundle, bundle_txn_cnt will be non-zero.

       The pack tile can accumulate transactions from a bundle until
       it has all of them, at which point the bundle is schedulable.

       Bundles will not arrive to pack interleaved with other bundles
       (although might be interleaved with other non-bundle
       transactions), so if pack sees the bundle_id change before
       collecting all the bundle_txn_cnt transactions, it should
       abandon the bundle, as one or more of the transactions failed
       to signature verify or resolve.

       The commission and commission_pubkey fields are provided by
       the block engine, and the validator will crank the tip payment
       program with these values, if it is not using them already.
       These fields are only provided on the first transaction in a
       bundle. */
    ulong bundle_id;
    ulong bundle_txn_cnt;
    uchar commission;
    uchar commission_pubkey[ 32 ];

    /* alignof is 8, so 7 bytes of padding here */

  } block_engine;

  /* There are three additional fields at the end here, which are
     variable length and not included in the size of this struct. txn_t
     and alut are only found in frags after the verify step.
  uchar          payload[ ]
  fd_txn_t       txn_t[ ]
  fd_acct_addr_t alut[ ] */
};

typedef struct fd_txn_m fd_txn_m_t;

static FD_FN_CONST inline ulong
fd_txn_m_align( void ) {
  return alignof(fd_txn_m_t);
}

static inline ulong
fd_txn_m_footprint( ulong payload_sz,
                    ulong instr_cnt,
                    ulong addr_table_lookup_cnt,
                    ulong addr_table_adtl_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_txn_m_t),     sizeof(fd_txn_m_t) );
  l = FD_LAYOUT_APPEND( l, 1UL,                     payload_sz );
  l = FD_LAYOUT_APPEND( l, fd_txn_align(),          fd_txn_footprint( instr_cnt, addr_table_lookup_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_acct_addr_t), addr_table_adtl_cnt*sizeof(fd_acct_addr_t) );
  return FD_LAYOUT_FINI( l, fd_txn_m_align() );
}

static inline uchar *
fd_txn_m_payload( fd_txn_m_t * txnm ) {
  return (uchar *)(txnm+1UL);
}

static inline uchar const *
fd_txn_m_payload_const( fd_txn_m_t const * txnm ) {
  return (uchar const *)(txnm+1UL);
}

static inline fd_txn_t *
fd_txn_m_txn_t( fd_txn_m_t * txnm ) {
  return (fd_txn_t *)fd_ulong_align_up( (ulong)(txnm+1UL) + txnm->payload_sz, alignof( fd_txn_t ) );
}

static inline fd_txn_t const *
fd_txn_m_txn_t_const( fd_txn_m_t const * txnm ) {
  return (fd_txn_t const *)fd_ulong_align_up( (ulong)(txnm+1UL) + txnm->payload_sz, alignof( fd_txn_t ) );
}

static inline fd_acct_addr_t *
fd_txn_m_alut( fd_txn_m_t * txnm ) {
  return (fd_acct_addr_t *)fd_ulong_align_up( fd_ulong_align_up( (ulong)(txnm+1UL) + txnm->payload_sz, alignof( fd_txn_t ) )+txnm->txn_t_sz, alignof( fd_acct_addr_t ) );
}

static inline ulong
fd_txn_m_realized_footprint( fd_txn_m_t const * txnm,
                             int                include_txn_t,
                             int                include_alut ) {
  if( FD_LIKELY( include_txn_t ) ) {
    ulong l = FD_LAYOUT_INIT;
    l = FD_LAYOUT_APPEND( l, alignof(fd_txn_m_t),     sizeof(fd_txn_m_t) );
    l = FD_LAYOUT_APPEND( l, 1UL,                     txnm->payload_sz );
    l = FD_LAYOUT_APPEND( l, fd_txn_align(),          fd_txn_footprint( fd_txn_m_txn_t_const( txnm )->instr_cnt, fd_txn_m_txn_t_const( txnm )->addr_table_lookup_cnt ) );
    l = FD_LAYOUT_APPEND( l, alignof(fd_acct_addr_t), fd_uchar_if(include_alut, fd_txn_m_txn_t_const( txnm )->addr_table_adtl_cnt, 0U)*sizeof(fd_acct_addr_t) );

    /* FD_LAYOUT_FINI is not included since the _realized_ footprint
       should not include the extra padding typically added after the
       last struct used to align the entire footprint. */
    return l;
  } else {
    ulong l = FD_LAYOUT_INIT;
    l = FD_LAYOUT_APPEND( l, alignof(fd_txn_m_t), sizeof(fd_txn_m_t) );
    l = FD_LAYOUT_APPEND( l, 1UL, txnm->payload_sz );
    return l;
  }
}

#define FD_TPU_RAW_MTU FD_ULONG_ALIGN_UP(                 \
                           sizeof(fd_txn_m_t)+FD_TPU_MTU, \
                           alignof(fd_txn_m_t) )

#define FD_TPU_PARSED_MTU FD_ULONG_ALIGN_UP(                    \
                              FD_ULONG_ALIGN_UP(                \
                                 sizeof(fd_txn_m_t)+FD_TPU_MTU, \
                                 alignof(fd_txn_t) )            \
                              +FD_TXN_MAX_SZ,                   \
                              alignof(fd_txn_m_t) )

#define FD_TPU_RESOLVED_MTU FD_ULONG_ALIGN_UP(                     \
                              FD_ULONG_ALIGN_UP(                   \
                                 FD_ULONG_ALIGN_UP(                \
                                    sizeof(fd_txn_m_t)+FD_TPU_MTU, \
                                    alignof(fd_txn_t) )            \
                                 +FD_TXN_MAX_SZ,                   \
                                 alignof(fd_acct_addr_t) )         \
                              +256UL*sizeof(fd_acct_addr_t),       \
                              alignof(fd_txn_m_t) )

#endif /* HEADER_fd_src_disco_fd_txn_m_h */
