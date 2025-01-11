#ifndef HEADER_fd_src_app_fdctl_run_tiles_h
#define HEADER_fd_src_app_fdctl_run_tiles_h

#include "stem/fd_stem.h"
#include "shred/fd_shredder.h"
#include "../ballet/shred/fd_shred.h"
#include "../ballet/pack/fd_pack.h"
#include "topo/fd_topo.h"

#include <linux/filter.h>

/* fd_shred34 is a collection of up to 34 shreds batched in a way that's
   convenient for use in a dcache and for access from Rust. The limit of
   34 comes so that sizeof( fd_shred34_t ) < USHORT_MAX. */

struct __attribute__((aligned(FD_CHUNK_ALIGN))) fd_shred34 {
  ulong shred_cnt;

  /* est_txn_cnt: An estimate of the number of transactions contained in this
     shred34_t.  The true value might not be a whole number, but this is
     helpful for diagnostic purposes. */
  ulong est_txn_cnt;
  ulong stride;
  ulong offset;
  ulong shred_sz; /* The size of each shred */
  /* For i in [0, shred_cnt), shred i's payload spans bytes
     [i*stride+offset, i*stride+offset+shred_sz ), counting from the
     start of the struct, not this point. */
  union {
    fd_shred_t shred;
    uchar      buffer[ FD_SHRED_MAX_SZ ];
  } pkts[ 34 ];
};
typedef struct fd_shred34 fd_shred34_t;

struct fd_became_leader {
  /* Start and end time of the slot in nanoseconds (from
     fd_log_wallclock()). */
  long   slot_start_ns;
  long   slot_end_ns;

  /* An opaque pointer to a Rust Arc<Bank> object, which should only
     be used with fd_ext_* functions to execute transactions or drop
     the bank.  The ownership is complicated, but basically any bank
     tile that receives this frag has a strong refcnt to the bank and
     should release it when done, other tiles should ignore and never
     use the bank. */
  void const * bank;

  /* The maximum number of microblocks that pack is allowed to put
     into the block. This allows PoH to accurately track and make sure
     microblocks do not need to be dropped. */
  ulong max_microblocks_in_slot;

  /* The number of ticks (effectively empty microblocks) that the PoH
     tile will put in the block.  This is used to adjust some pack
     limits. */
  ulong ticks_per_slot;

  /* The number of ticks that the PoH tile has skipped, but needs to
     publish to show peers they were skipped correctly.  This is used
     to adjust some pack limits. */
  ulong total_skipped_ticks;
};
typedef struct fd_became_leader fd_became_leader_t;

struct fd_rooted_bank {
  void * bank;
  ulong  slot;
};

typedef struct fd_rooted_bank fd_rooted_bank_t;

struct fd_completed_bank {
   ulong slot;
   uchar hash[32];
};

typedef struct fd_completed_bank fd_completed_bank_t;

struct fd_microblock_trailer {
  /* The hash of the transactions in the microblock, ready to be
     mixed into PoH. */
  uchar hash[ 32UL ];
};
typedef struct fd_microblock_trailer fd_microblock_trailer_t;

struct fd_done_packing {
   ulong microblocks_in_slot;
};
typedef struct fd_done_packing fd_done_packing_t;

struct fd_microblock_bank_trailer {
  /* An opaque pointer to the bank to use when executing and committing
     transactions.  The lifetime of the bank is owned by the PoH tile,
     which guarantees it is valid while pack or bank tiles might be
     using it. */
  void const * bank;

  /* The sequentially increasing index of the microblock, across all
     banks.  This is used by PoH to ensure microblocks get committed
     in the same order they are executed. */
  ulong microblock_idx;

  /* If the microblock is a bundle, with a set of potentially
     conflciting transactions that should be executed in order, and
     all either commit or fail atomically. */
  int is_bundle;
};
typedef struct fd_microblock_bank_trailer fd_microblock_bank_trailer_t;

typedef struct __attribute__((packed)) {
  ulong  tick_duration_ns;
  ulong  hashcnt_per_tick;
  ulong  ticks_per_slot;
  ulong  tick_height;
  uchar  last_entry_hash[32];
} fd_poh_init_msg_t;

/* A fd_txn_m_t is a parsed meta transaction, containing not just the
   payload */

struct fd_txn_m {
   /* The computed slot that this transaction is referencing, aka. the
      slot number of the reference_blockhash.  If it could not be
      determined, this will be the current slot. */
   ulong    reference_slot;

   /* Can be computed from the txn_t but it's expensive to parse again,
      so we just store this redundantly. */
   ulong    txn_t_sz;

   ushort   payload_sz;

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
   } block_engine;

   /* There are three additional fields at the end here, which are
      variable length and not included in the size of this struct.
   uchar          payload[ ]
   fd_txn_t       txn_t[ ]
   fd_acct_addr_t alut[ ] */
};

typedef struct fd_txn_m fd_txn_m_t;

static FD_FN_CONST inline ulong
fd_txn_m_align( void ) {
   return alignof( fd_txn_m_t );
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
      return fd_txn_m_footprint( txnm->payload_sz,
                                 fd_txn_m_txn_t_const( txnm )->instr_cnt,
                                 fd_txn_m_txn_t_const( txnm )->addr_table_lookup_cnt,
                                 include_alut ? fd_txn_m_txn_t_const( txnm )->addr_table_adtl_cnt : 0UL );
   } else {
      ulong l = FD_LAYOUT_INIT;
      l = FD_LAYOUT_APPEND( l, alignof(fd_txn_m_t), sizeof(fd_txn_m_t) );
      l = FD_LAYOUT_APPEND( l, 1UL,                 txnm->payload_sz );
      return FD_LAYOUT_FINI( l, fd_txn_m_align() );
   }
}

#define FD_TPU_RAW_MTU FD_ULONG_ALIGN_UP(                 \
                           sizeof(fd_txn_m_t)+FD_TPU_MTU, \
                           alignof(fd_txn_t) )            \

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

#endif /* HEADER_fd_src_app_fdctl_run_tiles_h */
