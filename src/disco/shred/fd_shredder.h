#ifndef HEADER_fd_src_disco_shred_fd_shredder_h
#define HEADER_fd_src_disco_shred_fd_shredder_h

#include "../keyguard/fd_keyguard_client.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../ballet/wsample/fd_wsample.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/reedsol/fd_reedsol.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/shred/fd_fec_set.h"
#include "../../ballet/shred/fd_shred.h"

#define FD_SHREDDER_MAX_STAKE_WEIGHTS (1UL<<20)


#define FD_FEC_SET_MAX_BMTREE_DEPTH (9UL) /* ceil(log2(DATA_SHREDS_MAX + PARITY_SHREDS_MAX)) */

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

static ulong const fd_shredder_data_to_parity_cnt[ 33UL ] = {
   0UL, 17UL, 18UL, 19UL, 19UL, 20UL, 21UL, 21UL,
  22UL, 23UL, 23UL, 24UL, 24UL, 25UL, 25UL, 26UL,
  26UL, 26UL, 27UL, 27UL, 28UL, 28UL, 29UL, 29UL,
  29UL, 30UL, 30UL, 31UL, 31UL, 31UL, 32UL, 32UL, 32UL };

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
   required to send an entry batch of size `sz_bytes` bytes, with shreds
   of type `type`. `type` must be one of FD_SHRED_TYPE_MERKLE_{DATA,
   DATA_CHAINED, DATA_CHAINED_RESIGNED}.  For data and parity shred counts,
   this is the total count across all FEC sets.

   We use the same policy for shredding that the Agave validator uses,
   even though it's a bit strange.  If the entry batch size is an exact
   multiple of the default FEC set total data size of 31840, then we
   make sz_byte/31840 FEC sets, where each FEC set has 32 data shreds,
   and each data shred contains 995 bytes of payload.  Otherwise, we
   make 31840 B FEC sets until we have less than 63680 bytes left, and
   we make one oddly sized FEC set for the remaining payload.

   (Note: while this is true for the logic of the shredder, the way our
   shred tile works with watermark implies that this never happens, and
   the only case that happens in practice is the "oddly sized" FEC set
   described below.)

   Computing this "oddly sized" FEC set is a bit strange because the
   number of shreds in the set depends on the amount of payload in each
   shred, which depends on the depth of the Merkle tree required to
   store all the shreds in the set, which depends on the number of
   shreds in the set.  The spec gives the formula:
   payload_bytes_per_shred = 1115 - 20*ceiling( log2( num_shreds ) )
   where num_shreds = num_data_shreds + num_parity_shreds, and
   num_data_shreds = payload_sz_remaining/payload_bytes_per_shred and
   num_parity_shreds is a non-decreasing function of num_data_shreds.

   The Agave validator solves this formula by brute force.
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
   always pick the larger value of payload_bytes_per_shred.

   In short, the relationship between the constants that appear in the
   code below is as follow:

   Unchained Merkle Shreds.
   - data_sz:  9135 == payload_sz: 1015 *  9 shreds (merkle tree height: 5)
   - data_sz: 31840 == payload_sz:  995 * 32 shreds (merkle tree height: 6)
   - data_sz: 62400 == payload_sz:  975 * 64 shreds (merkle tree height: 7)
   -                   payload_sz:  955             (merkle tree height: 8)
   note: payload_sz decreases by 20 bytes as the merkle tree height increases.
   note 2: in the first entry, 9 data shreds + 23 corresponding parity shreds
           total to 32 shreds, hence a merkle tree of height 5.

   Chained Merkle Shreds.
   - data_sz:  8847 == payload_sz:  983 *  9 shreds (merkle tree height: 5)
   - data_sz: 30816 == payload_sz:  963 * 32 shreds (merkle tree height: 6)
   - data_sz: 60352 == payload_sz:  943 * 64 shreds (merkle tree height: 7)
   -                   payload_sz:  923             (merkle tree height: 8)
   note: payload_sz is the unchained payload_sz - 32 bytes (for chained merkle root).

   Resigned Chained Merkle Shreds.
   - data_sz:  8271 == payload_sz:  919 *  9 shreds (merkle tree height: 5)
   - data_sz: 28768 == payload_sz:  899 * 32 shreds (merkle tree height: 6)
   - data_sz: 56256 == payload_sz:  879 * 64 shreds (merkle tree height: 7)
   -                   payload_sz:  859             (merkle tree height: 8)
   note: payload_sz is the chained payload_sz - 64 bytes (for signature). */

#define FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ   (31840UL)
#define FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ  (30816UL) /* -32 bytes * 32 shreds */
#define FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ (28768UL) /* -64 bytes * 32 shreds */

#define FD_SHREDDER_NORMAL_FEC_SET_RAW_BUF_SZ   (63679UL) /* 2 * ...PAYLOAD_SZ - 1 */
#define FD_SHREDDER_CHAINED_FEC_SET_RAW_BUF_SZ  (61631UL) /* 2 * ...PAYLOAD_SZ - 1 */
#define FD_SHREDDER_RESIGNED_FEC_SET_RAW_BUF_SZ (57535UL) /* 2 * ...PAYLOAD_SZ - 1 */

FD_FN_CONST static inline ulong
fd_shredder_count_fec_sets(      ulong sz_bytes, ulong type ) {
  /* In the case of normal fec_sets, if sz_bytes < 2*31840, we make 1 FEC set.
      If sz_bytes is a multiple of 31840, we make exactly sz_bytes/31840 sets.
      Otherwise, we make floor(sz_bytes/31840)-1 normal set + one odd-sized set.
     In the case of chained and (chained+)resigned fec_sets, the thresholds are
      adjusted accordingly. */
  if( FD_UNLIKELY( fd_shred_is_resigned( type ) ) ) {
    return fd_ulong_max( sz_bytes, 2UL*FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ - 1UL ) / FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ;
  } else if( FD_LIKELY( fd_shred_is_chained( type ) ) ) {
    return fd_ulong_max( sz_bytes, 2UL*FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ - 1UL ) / FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
  }
  return fd_ulong_max( sz_bytes, 2UL*FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ - 1UL ) / FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ;
}
FD_FN_CONST static inline ulong
fd_shredder_count_data_shreds(   ulong sz_bytes, ulong type ) {
  ulong normal_sets = fd_shredder_count_fec_sets( sz_bytes, type ) - 1UL;
  ulong shreds = normal_sets * 32UL;
  if( FD_UNLIKELY( fd_shred_is_resigned( type ) ) ) {
    ulong remaining_bytes = sz_bytes - normal_sets * FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ;
    if(      FD_UNLIKELY( remaining_bytes <=  8271UL ) ) shreds += fd_ulong_max( 1UL, (remaining_bytes +  918UL)/ 919UL );
    else if( FD_LIKELY(   remaining_bytes <= 28768UL ) ) shreds +=                    (remaining_bytes +  898UL)/ 899UL;
    else if( FD_LIKELY(   remaining_bytes <= 56256UL ) ) shreds +=                    (remaining_bytes +  878UL)/ 879UL;
    else                                                 shreds +=                    (remaining_bytes +  858UL)/ 859UL;
  } else if( FD_LIKELY( fd_shred_is_chained( type ) ) ) {
    ulong remaining_bytes = sz_bytes - normal_sets * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
    if(      FD_UNLIKELY( remaining_bytes <=  8847UL ) ) shreds += fd_ulong_max( 1UL, (remaining_bytes +  982UL)/ 983UL );
    else if( FD_LIKELY(   remaining_bytes <= 30816UL ) ) shreds +=                    (remaining_bytes +  962UL)/ 963UL;
    else if( FD_LIKELY(   remaining_bytes <= 60352UL ) ) shreds +=                    (remaining_bytes +  942UL)/ 943UL;
    else                                                 shreds +=                    (remaining_bytes +  922UL)/ 923UL;
  } else {
    ulong remaining_bytes = sz_bytes - normal_sets * FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ;
    if(      FD_UNLIKELY( remaining_bytes <=  9135UL ) ) shreds += fd_ulong_max( 1UL, (remaining_bytes + 1014UL)/1015UL );
    else if( FD_LIKELY(   remaining_bytes <= 31840UL ) ) shreds +=                    (remaining_bytes +  994UL)/ 995UL;
    else if( FD_LIKELY(   remaining_bytes <= 62400UL ) ) shreds +=                    (remaining_bytes +  974UL)/ 975UL;
    else                                                 shreds +=                    (remaining_bytes +  954UL)/ 955UL;
  }
  return shreds;
}
FD_FN_CONST static inline ulong
fd_shredder_count_parity_shreds( ulong sz_bytes, ulong type ) {
  ulong normal_sets = fd_shredder_count_fec_sets( sz_bytes, type ) - 1UL;
  ulong shreds = normal_sets * 32UL;
  if( FD_UNLIKELY( fd_shred_is_resigned( type ) ) ) {
    ulong remaining_bytes = sz_bytes - normal_sets * FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ;
    if(      FD_UNLIKELY( remaining_bytes <=  8271UL ) ) shreds += fd_shredder_data_to_parity_cnt[ fd_ulong_max( 1UL, (remaining_bytes +  918UL)/ 919UL ) ];
    else if( FD_LIKELY(   remaining_bytes <= 28768UL ) ) shreds += fd_shredder_data_to_parity_cnt[                    (remaining_bytes +  898UL)/ 899UL   ];
    else if( FD_LIKELY(   remaining_bytes <= 56256UL ) ) shreds +=                                                    (remaining_bytes +  878UL)/ 879UL;
    else                                                 shreds +=                                                    (remaining_bytes +  858UL)/ 859UL;
  } else if( FD_LIKELY( fd_shred_is_chained( type ) ) ) {
    ulong remaining_bytes = sz_bytes - normal_sets * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
    if(      FD_UNLIKELY( remaining_bytes <=  8847UL ) ) shreds += fd_shredder_data_to_parity_cnt[ fd_ulong_max( 1UL, (remaining_bytes +  982UL)/ 983UL ) ];
    else if( FD_LIKELY(   remaining_bytes <= 30816UL ) ) shreds += fd_shredder_data_to_parity_cnt[                    (remaining_bytes +  962UL)/ 963UL   ];
    else if( FD_LIKELY(   remaining_bytes <= 60352UL ) ) shreds +=                                                    (remaining_bytes +  942UL)/ 943UL;
    else                                                 shreds +=                                                    (remaining_bytes +  922UL)/ 923UL;
  } else {
    ulong remaining_bytes = sz_bytes - normal_sets * FD_SHREDDER_NORMAL_FEC_SET_PAYLOAD_SZ;
    if(      FD_UNLIKELY( remaining_bytes <=  9135UL ) ) shreds += fd_shredder_data_to_parity_cnt[ fd_ulong_max( 1UL, (remaining_bytes + 1014UL)/1015UL ) ];
    else if( FD_LIKELY(   remaining_bytes <= 31840UL ) ) shreds += fd_shredder_data_to_parity_cnt[                    (remaining_bytes +  994UL)/ 995UL   ];
    else if( FD_LIKELY(   remaining_bytes <= 62400UL ) ) shreds +=                                                    (remaining_bytes +  974UL)/ 975UL;
    else                                                 shreds +=                                                    (remaining_bytes +  954UL)/ 955UL;
  }
  return shreds;
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
   a batch of the specified size, followed by fd_shredder_next_fec_set
   exactly fd_shredder_count_fec_sets( entry_batch_sz ) times. */
fd_shredder_t * fd_shredder_skip_batch( fd_shredder_t * shredder,
                                        ulong           entry_batch_sz,
                                        ulong           slot,
                                        ulong           shred_type );

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

   chained_merkle_root is either NULL or a pointer to a 32-byte buffer
   containing the chained merkle root (the merkle root of the previous
   FEC set).  If not NULL, chained_merkle_root is updated with the new
   root.  This determines the variant of shreds created.

   out_merkle_root is an optional parameter: if non-NULL the merkle root
   of the extracted FEC set will be copied into out_merkle_root on
   success.  Assumes out_merkle_root pointers to a buffer of at least 32
   bytes (FD_SHRED_MERKLE_ROOT_SZ).

   Returns result on success and NULL if all of the entry batch's data
   has been consumed already by previous calls to this function.  On
   success, advances the position of the shredder within the batch
   without finishing the batch. */
fd_fec_set_t *
fd_shredder_next_fec_set( fd_shredder_t * shredder,
                          fd_fec_set_t *  result,
                          uchar *         chained_merkle_root,
                          uchar *         out_merkle_root );

/* fd_shredder_fini_batch finishes the in process batch.  shredder must
   be a valid local join that is currently in a batch.  Upon return,
   shredder will no longer be in a batch and will be ready to begin a
   new batch with init_batch.  Returns shredder. */
fd_shredder_t * fd_shredder_fini_batch( fd_shredder_t * shredder );

#endif /* HEADER_fd_src_disco_shred_fd_shredder_h */
