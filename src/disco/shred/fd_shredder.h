#ifndef HEADER_fd_src_disco_shred_fd_shredder_h
#define HEADER_fd_src_disco_shred_fd_shredder_h

#include "../keyguard/fd_keyguard_client.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../ballet/wsample/fd_wsample.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/reedsol/fd_reedsol.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "fd_fec_set.h"
#include "../../ballet/shred/fd_shred.h"

#define FD_SHREDDER_MAX_STAKE_WEIGHTS (1UL<<20)


#define FD_FEC_SET_MAX_BMTREE_DEPTH (7UL) /* 1+ceil(log2(DATA_SHREDS_MAX + PARITY_SHREDS_MAX)) */

#define FD_SHREDDER_ALIGN     (  128UL)
/* FD_SHREDDER_FOOTPRINT is not provided because it depends on the footprint
   of fd_sha256_batch_t, which is not invariant (the latter depends on the
   underlying implementation). Instead, a static inline function is provided. */

#define FD_SHREDDER_MAGIC (0xF17EDA2547EDDE70UL) /* FIREDAN SHREDDER V0 */

typedef void (fd_shredder_sign_fn)( void * ctx, uchar * sig, uchar const * merkle_root );

#define FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT      (2UL)
#define FD_SHRED_FEATURES_ACTIVATION_SLOT_SZ       (8UL)
#define FD_SHRED_FEATURES_ACTIVATION_SLOT_DISABLED (ULONG_MAX)

union fd_shred_features_activation_private {
   /* slots for features of interest - update cnt as needed in the future. */
   ulong slots[ FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT ];
   struct {
      /* 0 */ ulong enforce_fixed_fec_set;
      /* 1 */ ulong switch_to_chacha8_turbine;
   };
};
typedef union fd_shred_features_activation_private fd_shred_features_activation_t;


struct __attribute__((aligned(FD_SHREDDER_ALIGN))) fd_shredder_private {
  ulong  magic;
  ushort shred_version;

  fd_sha256_batch_t sha256 [ 1 ];
  fd_reedsol_t      reedsol[ 1 ];
  union __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN))) {
    fd_bmtree_commit_t bmtree;
    uchar _bmtree_footprint[ FD_BMTREE_COMMIT_FOOTPRINT( FD_FEC_SET_MAX_BMTREE_DEPTH ) ];
  };
  fd_bmtree_node_t bmtree_leaves[ FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX ];

  void const * entry_batch;
  ulong        sz;
  ulong        offset;

  void *                signer_ctx;
  fd_shredder_sign_fn * signer;

  fd_entry_batch_meta_t meta;
  ulong slot;
  ulong data_idx_offset;
  ulong parity_idx_offset;
};

typedef struct fd_shredder_private fd_shredder_t;

FD_FN_CONST static inline ulong fd_shredder_align    ( void ) { return FD_SHREDDER_ALIGN;     }
FD_FN_CONST static inline ulong fd_shredder_footprint( void ) { return sizeof(fd_shredder_t); }

/* fd_shredder_new formats a region of memory as a shredder object.
   pubkey must point to the first byte of 32 bytes containing the public
   key of the validator that will sign the shreds this shredder
   produces.  The value provided for shred_version will be stored in the
   shred_version field of each shred that this shredder produces. */
void          * fd_shredder_new(  void * mem, fd_shredder_sign_fn * signer, void * signer_ctx );
fd_shredder_t * fd_shredder_join( void * mem );
void *          fd_shredder_leave(  fd_shredder_t * shredder );
void *          fd_shredder_delete( void *          mem      );

static inline void fd_shredder_set_shred_version( fd_shredder_t * shredder, ushort shred_version ) { shredder->shred_version = shred_version; }


/* fd_shredder_count_{data_shreds, parity_shreds, fec_sets}: returns the
   number of data shreds, parity shreds, or FEC sets (respectively)
   required to send an entry batch of size `sz_bytes` bytes.  It uses
   chained unsigned Merkle shreds except for that when block_complete is
   non-zero, the last FEC set uses chained resigned Merkle shreds.
   DATA_CHAINED, DATA_CHAINED_RESIGNED}.  For data and parity shred
   counts, this is the total count across all FEC sets.

   We only produce FEC sets with 32 data and 32 parity shreds, so this
   form of counting is much simpler than before.  The only strangeness
   is with the last entry batch because resigned shreds hold less
   payload than chained shreds. Thus, we might be in a situation where
   an entry batch would fit in one chained FEC set but requires two
   resigned FEC sets.  In this case, Agave produces a chained FEC set
   with extra padding at the end followed by a full resigned FEC set.
   We'll follow the same approach.

   Let C=FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ and
   R=FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ.  Then when

   sz_bytes <= R:     a signle resigned FEC set, possibly with padding

   sz_bytes >  R:     ceiling( (sz_bytes-R)/C ) chained FEC sets, with
                      the last one possibly having padding, followed by
                      one full resigned FEC set

   The nice part is that the normal C way of computing ceiling division,
   floor( (sz_bytes-R+C-1)/C ), gives 0 when sz_bytes<=R, which means we
   can combine these two cases. */

#define FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ   (31840UL)
#define FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ  (30816UL) /* -32 bytes * 32 shreds */
#define FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ (28768UL) /* -64 bytes * 32 shreds */

#define FD_SHREDDER_NORMAL_FEC_SET_RAW_BUF_SZ   (63679UL) /* 2 * ...PAYLOAD_SZ - 1 */
#define FD_SHREDDER_CHAINED_FEC_SET_RAW_BUF_SZ  (61631UL) /* 2 * ...PAYLOAD_SZ - 1 */
#define FD_SHREDDER_RESIGNED_FEC_SET_RAW_BUF_SZ (57535UL) /* 2 * ...PAYLOAD_SZ - 1 */

FD_FN_CONST static inline ulong
fd_shredder_count_fec_sets(      ulong sz_bytes, int block_complete ) {
  return fd_ulong_if( block_complete,
      1UL + (sz_bytes + FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ - 1UL)/FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ,
      (sz_bytes + FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - 1UL )/FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ );
}
FD_FN_CONST static inline ulong
fd_shredder_count_data_shreds(   ulong sz_bytes, int block_complete ) {
  return 32UL*fd_shredder_count_fec_sets( sz_bytes, block_complete );
}
FD_FN_CONST static inline ulong
fd_shredder_count_parity_shreds( ulong sz_bytes, int block_complete ) {
  return 32UL*fd_shredder_count_fec_sets( sz_bytes, block_complete );
}

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
                                        ulong                         slot,
                                        fd_entry_batch_meta_t const * meta );

/* fd_shredder_skip_batch updates the shredder state as necessary
   to skip processing this current batch.  shredder must be a valid
   local join.  entry_batch_sz must be strictly positive.

   Returns shredder, which will have data and parity shred indices
   updated as if the caller had called fd_shredder_init_batch with
   a batch of the specified size and meta.block_complete set to
   block_complete, followed by fd_shredder_next_fec_set exactly
   fd_shredder_count_fec_sets( entry_batch_sz ) times. */
fd_shredder_t * fd_shredder_skip_batch( fd_shredder_t * shredder,
                                        ulong           entry_batch_sz,
                                        ulong           slot,
                                        int             block_complete );

/* fd_shredder_next_fec_set extracts the next FEC set from the in
   progress batch.  Computes the entirety of both data and parity
   shreds, including the parity information, Merkle proofs, and
   signatures.  Stores the generated FEC set in result, which is
   clobbered.  Populates all fields of result except for
   {data,parity}_shred_present (which is only used for reconstruction).

   shredder must be a valid local join.  chained_merkle_root is a
   pointer to a 32-byte buffer containing the chained merkle root (the
   merkle root of the previous FEC set).  Upon return,
   chained_merkle_root is updated with the new root.

   Returns result on success and NULL if all of the entry batch's data
   has been consumed already by previous calls to this function.  On
   success, advances the position of the shredder within the batch
   without finishing the batch. */
fd_fec_set_t *
fd_shredder_next_fec_set( fd_shredder_t * shredder,
                          fd_fec_set_t *  result,
                          uchar *         chained_merkle_root );

/* fd_shredder_fini_batch finishes the in process batch.  shredder must
   be a valid local join that is currently in a batch.  Upon return,
   shredder will no longer be in a batch and will be ready to begin a
   new batch with init_batch.  Returns shredder. */
fd_shredder_t * fd_shredder_fini_batch( fd_shredder_t * shredder );

#endif /* HEADER_fd_src_disco_shred_fd_shredder_h */
