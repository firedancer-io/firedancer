#ifndef HEADER_fd_src_ballet_shred_fd_shredder_h
#define HEADER_fd_src_ballet_shred_fd_shredder_h

#include "../sha256/fd_sha256.h"
#include "../chacha20/fd_chacha20rng.h"
#include "../wsample/fd_wsample.h"
#include "../ed25519/fd_ed25519.h"
#include "../reedsol/fd_reedsol.h"
#include "../bmtree/fd_bmtree.h"
#include "fd_fec_set.h"

#define FD_SHREDDER_MAX_STAKE_WEIGHTS (1UL<<20)


#define FD_FEC_SET_MAX_BMTREE_DEPTH (9UL) /* ceil(log2(DATA_SHREDS_MAX + PARITY_SHREDS_MAX)) */

#define FD_SHREDDER_ALIGN     (     128UL)
#define FD_SHREDDER_FOOTPRINT (67135360UL) /* == sizeof(fd_shredder_t) */

#define FD_SHREDDER_MAGIC (0xF17EDA2547EDDE70UL) /* FIREDAN SHREDDER V0 */



struct fd_entry_batch_meta {
  ulong slot;
  ulong parent_offset;
  ulong bank_max_tick_height;
  ulong reference_tick;
  ulong tick;
};
typedef struct fd_entry_batch_meta fd_entry_batch_meta_t;

static ulong const fd_shredder_data_to_parity_cnt[ 33UL ] = {
   0UL, 17UL, 18UL, 19UL, 19UL, 20UL, 21UL, 21UL,
  22UL, 23UL, 23UL, 24UL, 24UL, 25UL, 25UL, 26UL,
  26UL, 26UL, 27UL, 27UL, 28UL, 28UL, 29UL, 29UL,
  29UL, 30UL, 30UL, 31UL, 31UL, 31UL, 32UL, 32UL, 32UL };

struct __attribute__((aligned(FD_SHREDDER_ALIGN))) fd_shredder_private {
  ulong  magic;
  ushort shred_version;

  fd_sha512_t       sha512 [ 1 ]; /* Needed for signing */
  fd_reedsol_t      reedsol[ 1 ];
  fd_sha256_batch_t sha256 [ 1 ];
  union __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN))) {
    fd_bmtree_commit_t bmtree;
    uchar _bmtree_footprint[ FD_BMTREE_COMMIT_FOOTPRINT( FD_FEC_SET_MAX_BMTREE_DEPTH ) ];
  };
  fd_bmtree_node_t bmtree_leaves[ FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX ];

  void const * entry_batch;
  ulong        sz;
  ulong        offset;

  fd_wsample_t *    sampler;
  ulong             stake_weight_cnt;
  fd_chacha20rng_t  sampling_rng [  1 ];
  uchar             leader_pubkey[ 32 ];

  fd_entry_batch_meta_t meta;
  ulong data_idx_offset;
  ulong parity_idx_offset;

  uchar _sampler_footprint [ FD_WSAMPLE_FOOTPRINT( FD_SHREDDER_MAX_STAKE_WEIGHTS ) ] __attribute__((aligned(FD_WSAMPLE_ALIGN)));
};

typedef struct fd_shredder_private fd_shredder_t;

FD_FN_CONST static inline ulong fd_shredder_align    ( void ) { return FD_SHREDDER_ALIGN;     }
FD_FN_CONST static inline ulong fd_shredder_footprint( void ) { return FD_SHREDDER_FOOTPRINT; }

/* fd_shredder_new formats a region of memory as a shredder object.
   pubkey must point to the first byte of 32 bytes containing the public
   key of the validator that will sign the shreds this shredder
   produces.  The value provided for shred_version will be stored in the
   shred_version field of each shred that this shredder produces. */
void          * fd_shredder_new(  void * mem, void const * pubkey, ushort shred_version );
fd_shredder_t * fd_shredder_join( void * mem );
void *          fd_shredder_leave(  fd_shredder_t * shredder );
void *          fd_shredder_delete( void *          mem      );


/* fd_shredder_set_stake_weights sets the stake weights that this
   shredder uses to compute shred destination for subsequent FEC sets.
   This should not be called while the shredder is in a batch.
   shredder should be a local join of an fd_shredder_t.  weights is
   indexed [0, weight_cnt).  weights==NULL is okay if weight_cnt==0.
   weights must be sorted largest to smallest.  The mapping between
   indexes and contact info should be maintained externally.  This
   function does not retain a read interest in weights after it returns.
   */
void fd_shredder_set_stake_weights( fd_shredder_t * shredder, ulong * weights, ulong weight_cnt );

/* fd_shredder_count_{data_shreds, parity_shreds, fec_sets}: returns the
   number of data shreds, parity shreds, or FEC sets (respectively)
   required to send an entry batch of size sz_bytes bytes.  For data and
   parity shred counts, this is the total count across all FEC sets.

   We use the same policy for shredding that the Labs validator uses,
   even though it's a bit strange.  If the entry batch size is an exact
   multiple of the default FEC set total data size of 31840, then we
   make sz_byte/31840 FEC sets, where each FEC set has 32 data shreds,
   and each data shred contains 995 bytes of payload.  Otherwise, we
   make 31840 B FEC sets until we have less than 63680 bytes left, and
   we make one oddly sized FEC set for the remaining payload.

   Computing this "oddly sized" FEC set is a bit strange because the
   number of shreds in the set depends on the amount of payload in each
   shred, which depends on the depth of the Merkle tree required to
   store all the shreds in the set, which depends on the number of
   shreds in the set.  The spec gives the formula:
   payload_bytes_per_shred = 1115 - 20*ceiling( log2( num_shreds ) )
   where num_shreds = num_data_shreds + num_parity_shreds, and
   num_data_shreds = payload_sz_remaining/payload_bytes_per_shred and
   num_parity_shreds is a non-decreasing function of num_data_shreds.

   The Solana Labs validator solves this formula by brute force.
   Instead, we'll do the computation ahead of time to build a nice
   table:
           Case               payload_bytes_per_shred
        1 <= D <=  9135               1015
     8956 <= D <= 31840                995
    31201 <= D <= 62400                975
    61121 <= D <= 63984                955

   Where D is the remaining payload size in bytes.  You may notice the
   cases overlap.  That's the gross outcome of using a gross formula.
   There are two legitimate ways to send certain payload sizes.  We
   always pick the larger value of payload_bytes_per_shred. */

#define NORMAL_FEC_SET_PAYLOAD_SZ (31840UL)

FD_FN_CONST static inline ulong
fd_shredder_count_fec_sets(      ulong sz_bytes ) {
  /* if sz_bytes < 2*31840, we make 1 FEC set.  If sz_bytes is a
     multiple of 31840, we make exactly sz_bytes/31840 sets.  Otherwise,
     we make floor(sz_bytes/31840)-1 normal set + one odd-sized set.
     These cases can be simplified to make it branchless: */
  return fd_ulong_max( sz_bytes, 2UL*NORMAL_FEC_SET_PAYLOAD_SZ - 1UL ) / NORMAL_FEC_SET_PAYLOAD_SZ;
}
FD_FN_CONST static inline ulong
fd_shredder_count_data_shreds(   ulong sz_bytes ) {
  ulong normal_sets = fd_shredder_count_fec_sets( sz_bytes ) - 1UL;
  ulong remaining_bytes = sz_bytes - normal_sets * NORMAL_FEC_SET_PAYLOAD_SZ;
  ulong shreds = normal_sets * 32UL;
  if(      FD_UNLIKELY( remaining_bytes <=  9135UL ) ) shreds += fd_ulong_max( 1UL, (remaining_bytes + 1014UL)/1015UL );
  else if( FD_LIKELY(   remaining_bytes <= 31840UL ) ) shreds +=                    (remaining_bytes +  994UL)/ 995UL;
  else if( FD_LIKELY(   remaining_bytes <= 62400UL ) ) shreds +=                    (remaining_bytes +  974UL)/ 975UL;
  else                                                 shreds +=                    (remaining_bytes +  954UL)/ 955UL;
  return shreds;
}
FD_FN_CONST static inline ulong
fd_shredder_count_parity_shreds( ulong sz_bytes ) {
  ulong normal_sets = fd_shredder_count_fec_sets( sz_bytes ) - 1UL;
  ulong remaining_bytes = sz_bytes - normal_sets * NORMAL_FEC_SET_PAYLOAD_SZ;
  ulong shreds = normal_sets * 32UL;
  if(      FD_UNLIKELY( remaining_bytes <=  9135UL ) ) shreds += fd_shredder_data_to_parity_cnt[ fd_ulong_max( 1UL, (remaining_bytes + 1014UL)/1015UL ) ];
  else if( FD_LIKELY(   remaining_bytes <= 31840UL ) ) shreds += fd_shredder_data_to_parity_cnt[                    (remaining_bytes +  994UL)/ 995UL   ];
  else if( FD_LIKELY(   remaining_bytes <= 62400UL ) ) shreds +=                                                    (remaining_bytes +  974UL)/ 975UL;
  else                                                 shreds +=                                                    (remaining_bytes +  954UL)/ 955UL;
  return shreds;
}
#undef NORMAL_FEC_SET_PAYLOAD_SZ

/* fd_shredder_init_batch begins the computation of shreds for an entry
   batch.  shredder must be a valid local join.  entry_batch points to
   the first byte of a region of memory entry_batch_sz bytes long.
   entry_batch_sz must be strictly positive.  The shredder object
   retains a read interest in the region of memory [entry_batch,
   entry_batch+entry_batch_sz) that lasts until fd_shredder_fini_batch
   is called.  This region of memory should not be modified while in use
   by the shredder.  meta contains the metadata for the batch that is
   necessary for shred production.  The shredder object does not retain
   a read interest in the memory pointed to by meta.

   Returns shredder, which will be in a new batch when the function
   returns. */
fd_shredder_t * fd_shredder_init_batch( fd_shredder_t               * shredder,
                                        void const                  * entry_batch,
                                        ulong                         entry_batch_sz,
                                        fd_entry_batch_meta_t const * meta );

/* fd_shredder_next_fec_set extracts the next FEC set from the in
   progress batch.  Computes the entirety of both data and parity
   shreds, including the parity information, Merkle proofs, and
   signatures.  Additionally computes the destination index for each
   shred.  Stores the generated FEC set in result, which is clobbered.
   Populates all fields of result except for {data,parity}_shred_present
   (which is only used for reconstruction).

   shredder must be a valid local join, and signing_private_key must
   point to the first byte of an Ed25519 private key that will be used
   to sign the shreds.  It must correspond to the public key passed in
   the shredder constructor.

   Returns result on success and NULL if all of the entry batch's data
   has been consumed already by previous calls to this function.  On
   success, advances the position of the shredder within the batch
   without finishing the batch. */
fd_fec_set_t * fd_shredder_next_fec_set( fd_shredder_t * shredder, void const * signing_private_key, fd_fec_set_t * result );

/* fd_shredder_fini_batch finishes the in process batch.  shredder must
   be a valid local join that is currently in a batch.  Upon return,
   shredder will no longer be in a batch and will be ready to begin a
   new batch with init_batch.  Returns shredder. */
fd_shredder_t * fd_shredder_fini_batch( fd_shredder_t * shredder );

#endif /* HEADER_fd_src_ballet_shred_fd_shredder_h */
