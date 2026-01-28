#include "fd_eqvoc.h"
#include "fd_eqvoc_private.h"
#include "../../ballet/shred/fd_shred.h"

ulong
fd_eqvoc_align( void ) {
  return 128UL;
}

ulong
fd_eqvoc_footprint( ulong shred_max,
                    ulong slot_max,
                    ulong from_max ) {
  int   lg_from_max = fd_ulong_find_msb( fd_ulong_pow2_up( from_max ) ) + 1;
  ulong proof_max   = slot_max * from_max;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_eqvoc_t),       sizeof(fd_eqvoc_t)                                      );
  l = FD_LAYOUT_APPEND( l, fd_sha512_align(),         fd_sha512_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN,    FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) );
  l = FD_LAYOUT_APPEND( l, shred_pool_align(),        shred_pool_footprint( shred_max )                       );
  l = FD_LAYOUT_APPEND( l, shred_map_align(),         shred_map_footprint( shred_max )                        );
  l = FD_LAYOUT_APPEND( l, shred_deque_align(),       shred_deque_footprint( shred_max )                      );
  l = FD_LAYOUT_APPEND( l, slot_pool_align(),         slot_pool_footprint( slot_max )                         );
  l = FD_LAYOUT_APPEND( l, slot_map_align(),          slot_map_footprint( slot_max )                          );
  l = FD_LAYOUT_APPEND( l, slot_deque_align(),        slot_deque_footprint( slot_max )                        );
  l = FD_LAYOUT_APPEND( l, proof_pool_align(),        proof_pool_footprint( proof_max )                       );
  l = FD_LAYOUT_APPEND( l, proof_map_align(),         proof_map_footprint( proof_max )                        );
  l = FD_LAYOUT_APPEND( l, from_map_align(),          from_map_footprint( lg_from_max )                       );
  for( ulong i = 0UL; i < fd_ulong_pow2( lg_from_max ); i++ ) {
    l = FD_LAYOUT_APPEND( l, proof_deque_align(), proof_deque_footprint( slot_max ) );
  }
  return FD_LAYOUT_FINI( l, fd_eqvoc_align() );
}

void *
fd_eqvoc_new( void * shmem,
              ulong  shred_max,
              ulong  slot_max,
              ulong  from_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_eqvoc_footprint( shred_max, slot_max, from_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad shred_max (%lu), slot_max (%lu), or from_max (%lu)", shred_max, slot_max, from_max ));
    return NULL;
  }

  int   lg_from_max = fd_ulong_find_msb( fd_ulong_pow2_up( from_max ) ) + 1;
  ulong proof_max   = slot_max * from_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * eqvoc_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoc_t),       sizeof(fd_eqvoc_t)                                      );
  void * sha512      = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),         fd_sha512_footprint()                                   );
  void * bmtree_mem  = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN,    FD_BMTREE_COMMIT_FOOTPRINT( FD_SHRED_MERKLE_LAYER_CNT ) );
  void * shred_pool  = FD_SCRATCH_ALLOC_APPEND( l, shred_pool_align(),        shred_pool_footprint( shred_max )                       );
  void * shred_map   = FD_SCRATCH_ALLOC_APPEND( l, shred_map_align(),         shred_map_footprint( shred_max )                        );
  void * shred_deque = FD_SCRATCH_ALLOC_APPEND( l, shred_deque_align(),       shred_deque_footprint( shred_max )                      );
  void * slot_pool   = FD_SCRATCH_ALLOC_APPEND( l, slot_pool_align(),         slot_pool_footprint( slot_max )                         );
  void * slot_map    = FD_SCRATCH_ALLOC_APPEND( l, slot_map_align(),          slot_map_footprint( slot_max )                          );
  void * slot_deque  = FD_SCRATCH_ALLOC_APPEND( l, slot_deque_align(),        slot_deque_footprint( slot_max )                        );
  void * proof_pool  = FD_SCRATCH_ALLOC_APPEND( l, proof_pool_align(),        proof_pool_footprint( proof_max )                       );
  void * proof_map   = FD_SCRATCH_ALLOC_APPEND( l, proof_map_align(),         proof_map_footprint( proof_max )                        );
  void * from_map    = FD_SCRATCH_ALLOC_APPEND( l, from_map_align(),          from_map_footprint( lg_from_max )                       );

  fd_eqvoc_t * eqvoc   = (fd_eqvoc_t *)eqvoc_mem;
  eqvoc->shred_max     = shred_max;
  eqvoc->slot_max      = slot_max;
  eqvoc->from_max      = from_max;

  eqvoc->sha512      = fd_sha512_new  ( sha512 );
  eqvoc->bmtree_mem  = bmtree_mem; /* no new */
  eqvoc->shred_pool  = shred_pool_new ( shred_pool,  shred_max         );
  eqvoc->shred_map   = shred_map_new  ( shred_map,   shred_max,   seed );
  eqvoc->shred_deque = shred_deque_new( shred_deque, shred_max         );
  eqvoc->slot_pool   = slot_pool_new  ( slot_pool,   slot_max          );
  eqvoc->slot_map    = slot_map_new   ( slot_map,    slot_max,    seed );
  eqvoc->slot_deque  = slot_deque_new ( slot_deque,  slot_max          );
  eqvoc->proof_pool  = proof_pool_new ( proof_pool,  proof_max         );
  eqvoc->proof_map   = proof_map_new  ( proof_map,   proof_max,   seed );
  eqvoc->from_map    = from_map_new   ( from_map,    lg_from_max, seed );

  from_t * join = from_map_join( eqvoc->from_map );
  FD_TEST( fd_ulong_pow2( lg_from_max )==from_map_slot_cnt( join ) );
  for( ulong i = 0UL; i < from_map_slot_cnt( join ); i++ ) {
    void *  proof_deque = FD_SCRATCH_ALLOC_APPEND( l, proof_deque_align(), proof_deque_footprint( slot_max ) );
    join[i].proofs      = proof_deque_new( proof_deque, slot_max );
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_eqvoc_t *
fd_eqvoc_join( void * sheqvoc ) {

  if( FD_UNLIKELY( !sheqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)sheqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned eqvoc" ));
    return NULL;
  }

  fd_eqvoc_t * eqvoc = (fd_eqvoc_t *)sheqvoc;
  eqvoc->sha512      = fd_sha512_join  ( eqvoc->sha512      );
  (void)eqvoc->bmtree_mem; /* no join */
  eqvoc->shred_pool  = shred_pool_join ( eqvoc->shred_pool  );
  eqvoc->shred_map   = shred_map_join  ( eqvoc->shred_map   );
  eqvoc->shred_deque = shred_deque_join( eqvoc->shred_deque );
  eqvoc->slot_pool   = slot_pool_join  ( eqvoc->slot_pool   );
  eqvoc->slot_map    = slot_map_join   ( eqvoc->slot_map    );
  eqvoc->slot_deque  = slot_deque_join ( eqvoc->slot_deque  );
  eqvoc->proof_pool  = proof_pool_join ( eqvoc->proof_pool  );
  eqvoc->proof_map   = proof_map_join  ( eqvoc->proof_map   );
  eqvoc->from_map    = from_map_join   ( eqvoc->from_map    );
  for( ulong i = 0UL; i < from_map_slot_cnt( eqvoc->from_map ); i++ ) {
    eqvoc->from_map[i].proofs = proof_deque_join( eqvoc->from_map[i].proofs );
  }

  return (fd_eqvoc_t *)sheqvoc;
}

void *
fd_eqvoc_leave( fd_eqvoc_t const * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  return (void *)eqvoc;
}

void *
fd_eqvoc_delete( void * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)eqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned eqvoc" ));
    return NULL;
  }

  return eqvoc;
}

fd_eqvoc_t *
fd_eqvoc_init( fd_eqvoc_t               * eqvoc,
               ushort                     shred_version,
               fd_epoch_leaders_t const * leaders ) {
  eqvoc->shred_version = shred_version;
  eqvoc->leaders       = leaders;
  return eqvoc;
}

fd_eqvoc_t *
fd_eqvoc_fini( fd_eqvoc_t * eqvoc ) {
  eqvoc->shred_version = 0;
  eqvoc->leaders       = NULL;
  return eqvoc;
}

/* construct_proof constructs an array of DuplicateShred gossip msgs
   (`chunks_out`) from shred1 and shred2.

   Shred1 and shred2 are concatenated and then spliced into chunks of
   FD_EQVOC_CHUNK_SZ size. These chunks are embedded in the body of each
   DuplicateShred msg, along with a common header across all msgs.

   Caller supplies `chunks_out`, which is an array that MUST contain
   FD_EQVOC_CHUNK_CNT elements. */

void
construct_proof( fd_shred_t const *          shred1,
                 fd_shred_t const *          shred2,
                 fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] ) {

  long wallclock = fd_log_wallclock() / (long)1e6; /* ms */
  for (uchar i = 0; i < FD_EQVOC_CHUNK_CNT; i++ ) {
    chunks_out[i].index       = i;
    chunks_out[i].slot        = shred1->slot;
    chunks_out[i].num_chunks  = FD_EQVOC_CHUNK_CNT;
    chunks_out[i].chunk_index = i;
    chunks_out[i].wallclock   = wallclock;
  }

  ulong shred1_sz = fd_shred_sz( shred1 );
  ulong shred2_sz = fd_shred_sz( shred2 );

  /* Populate chunk0 */

  FD_STORE( ulong, chunks_out[0].chunk, shred1_sz );
  memcpy( chunks_out[0].chunk + sizeof(ulong), shred1, FD_EQVOC_CHUNK_SZ - sizeof(ulong) );
  chunks_out[0].chunk_len = FD_EQVOC_CHUNK_SZ;

  /* Populate chunk1 */

  ulong shred1_off = FD_EQVOC_CHUNK_SZ - sizeof(ulong);
  ulong shred1_rem = shred1_sz - shred1_off;
  memcpy( chunks_out[1].chunk, (uchar *)shred1 + shred1_off, shred1_rem );
  FD_STORE( ulong, chunks_out[1].chunk + shred1_rem, shred2_sz );
  ulong chunk1_off = shred1_rem + sizeof(ulong);
  ulong chunk1_rem = FD_EQVOC_CHUNK_SZ - chunk1_off;
  memcpy( chunks_out[1].chunk + chunk1_off, shred2, chunk1_rem );
  chunks_out[1].chunk_len = FD_EQVOC_CHUNK_SZ;

  /* Populate chunk2 */

  ulong shred2_off = chunk1_rem;
  ulong shred2_rem = shred2_sz - shred2_off;
  memcpy( chunks_out[2].chunk, (uchar *)shred2 + shred2_off, shred2_rem );
  chunks_out[2].chunk_len = shred2_rem;
}

/* verify_proof verifies that the two shreds contained in `proof` do in
   fact equivocate.

   Returns: FD_EQVOC_SUCCESS if no effect
            FD_EQVOC_PROOF_{...} if they do
            FD_EQVOC_ERR_{...} if the shreds were not valid inputs

   The implementation mirrors the Agave version very closely. See: https://github.com/anza-xyz/agave/blob/v3.1/gossip/src/duplicate_shred.rs#L137-L142

   Two shreds equivocate if they satisfy any of the following:

   1. Both shreds specify the same index and shred type, however their
      payloads differ.
   2. Both shreds specify the same FEC set, however their merkle roots
      differ.
   3. Both shreds specify the same FEC set and are coding shreds,
      however their erasure configs conflict.
   4. The shreds specify different FEC sets, the lower index shred is a
      coding shred, and its erasure meta indicates an FEC set overlap.
   5. The shreds specify different FEC sets, the lower index shred has a
      merkle root that is not equal to the chained merkle root of the
      higher index shred.
   6. The shreds are data shreds with different indices and the shred
      with the lower index has the LAST_SHRED_IN_SLOT flag set.

   Ref: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0204-slashable-event-verification.md#proof-verification

   Note: two shreds are in the same FEC set if they have the same slot
   and FEC set index.

   To prevent false positives, this function also performs the following
   input validation on the shreds:

   1. shred1 and shred2 are for the same slot.
   2. shred1 and shred2 are both the expected shred_version.
   3. shred1 and shred2 are either chained merkle or chained resigned
      merkle variants.
   4. shred1 and shred2 contain valid signatures signed by the same
      producer pubkey.

   If any of the above input validation fails, this function returns
   FD_EQVOC_ERR_{...}.

   The validation does duplicate some of what's in the shred tile, but
   because this proof is sourced from gossip (which doesn't go through
   shred) we have to also do it. */

int
verify_proof( fd_eqvoc_t const * eqvoc,
              fd_shred_t const * shred1,
              fd_shred_t const * shred2 ) {

  /* Dropping non-CMR shreds has been activated on mainnet, so we ignore
     any proofs containing non-CMR shreds. Currently Agave does not have
     an equivalent check. */

  if( FD_UNLIKELY( !fd_shred_is_chained ( fd_shred_type( shred1->variant ) ) &&
                   !fd_shred_is_resigned( fd_shred_type( shred2->variant ) ) ) ) {
    return FD_EQVOC_ERR_TYPE;
  }

  if( FD_UNLIKELY( shred1->slot != shred2->slot ) ) return FD_EQVOC_ERR_SLOT;

  if( FD_UNLIKELY( shred1->version != eqvoc->shred_version ) ) return FD_EQVOC_ERR_VERSION;
  if( FD_UNLIKELY( shred2->version != eqvoc->shred_version ) ) return FD_EQVOC_ERR_VERSION;

  /* Check both shreds contain valid signatures from the assigned leader
     to that slot. This requires deriving the merkle root and
     sig-verifying it, because the leader signs the merkle root for
     merkle shreds. */

  fd_bmtree_node_t root1;
  if( FD_UNLIKELY( !fd_shred_merkle_root( shred1, eqvoc->bmtree_mem, &root1 ) ) ) return FD_EQVOC_ERR_MERKLE;

  fd_bmtree_node_t root2;
  if( FD_UNLIKELY( !fd_shred_merkle_root( shred2, eqvoc->bmtree_mem, &root2 ) ) ) return FD_EQVOC_ERR_MERKLE;

  fd_pubkey_t const * leader = fd_epoch_leaders_get( eqvoc->leaders, shred1->slot );
  if( FD_UNLIKELY( !leader ) ) return FD_EQVOC_ERR_SIGNATURE;

  fd_sha512_t _sha512[1];
  fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( _sha512 ) );
  if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( root1.hash, 32UL, shred1->signature, leader->uc, sha512 ) ||
                   FD_ED25519_SUCCESS != fd_ed25519_verify( root2.hash, 32UL, shred2->signature, leader->uc, sha512 ) ) ) {
    return FD_EQVOC_ERR_SIGNATURE;
  }

  /* TODO remove below with fixed-32 */

  if( FD_UNLIKELY( shred1->fec_set_idx != shred2->fec_set_idx ) ) {

    /* Different FEC set index checks. Lower FEC set index shred must be a
      coding shred. */

    fd_shred_t const * lo = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx, shred1, shred2 );
    fd_shred_t const * hi = fd_ptr_if( shred1->fec_set_idx > shred2->fec_set_idx, shred1, shred2 );

    if( FD_UNLIKELY( fd_shred_is_code( fd_shred_type( lo->variant ) ) ) ) {

      /* Test for overlap. The FEC sets overlap if the lower fec_set_idx +
        data_cnt > higher fec_set_idx. We must have received at least one
        coding shred in the FEC set with the lower fec_set_idx to perform
        this check. */

      if( FD_UNLIKELY( lo->fec_set_idx + lo->code.data_cnt > hi->fec_set_idx ) ) {
        return FD_EQVOC_PROOF_OVERLAP;
      }

      /* Test for conflicting chained merkle roots when shred1 and shred2
        are in adjacent FEC sets. We know the FEC sets are adjacent if the
        last data shred index in the lower FEC set is one less than the
        first data shred index in the higher FEC set. */

      if( FD_UNLIKELY( lo->fec_set_idx + lo->code.data_cnt == hi->fec_set_idx ) ) {
        uchar * merkle_hash  = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx,
                                          (uchar *)shred1 + fd_shred_merkle_off( shred1 ),
                                          (uchar *)shred2 + fd_shred_merkle_off( shred2 ) );
        uchar * chained_hash = fd_ptr_if( shred1->fec_set_idx > shred2->fec_set_idx,
                                          (uchar *)shred1 + fd_shred_chain_off( shred1->variant ),
                                          (uchar *)shred2 + fd_shred_chain_off( shred2->variant ) );
        if( FD_LIKELY( 0!=memcmp( merkle_hash, chained_hash, FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
          return FD_EQVOC_PROOF_CHAINED;
        }
      }
    }
    return FD_EQVOC_SUCCESS; /* these shreds in different FEC sets do not prove equivocation */
  }

  /* At this point, the two shreds are in the same FEC set. */

  /* If two shreds in the same FEC set have different merkle roots, they
     equivocate. */

  if( FD_LIKELY( 0!=memcmp( root1.hash, root2.hash, sizeof(root1.hash)) ) ) {
    return FD_EQVOC_PROOF_MERKLE;
  }

  /* Remaining checks require the two shreds to be the same type. */

  if( FD_UNLIKELY( fd_shred_type( shred1->variant ) !=
                   fd_shred_type( shred2->variant ) ) ) {
    return FD_EQVOC_ERR_TYPE;
  }

  /* Agave does a payload comparison if two shreds have the same index,
     but it's not necessary for us to do the same because we only
     process merkle shreds (see first conditional in this function). You
     can't generate the same merkle root from different payloads for the
     same leaf in the tree. */

  if( FD_UNLIKELY( shred1->idx==shred2->idx ) ) {
    return FD_EQVOC_SUCCESS;
  }

  int is_data = fd_shred_is_data( fd_shred_type( shred1->variant ) ); /* at this point shreds have the same shred type */

  /* If both are data shreds, then check if one is marked the last shred
     in the slot and the other is a higher shred idx than that one. */

  if( FD_LIKELY( is_data ) ) {
    if( FD_LIKELY( ( shred1->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred2->idx > shred1->idx ) ||
                   ( shred2->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred1->idx > shred2->idx ) ) ) {
      return FD_EQVOC_PROOF_LAST;
    }

  /* If both are coding shreds, then check if they have the same meta.
     TODO fixed-32 remove. */

  } else {
    if( FD_LIKELY( ( shred1->code.code_cnt != shred2->code.code_cnt ||
                     shred1->code.data_cnt != shred2->code.data_cnt ||
                     shred1->idx - shred1->code.idx == shred2->idx - shred2->code.idx ) ) ) {
      return FD_EQVOC_PROOF_META;
    }
  }

  /* Shreds do not prove equivocation. */

  return FD_EQVOC_SUCCESS;
}

slot_t *
slot_insert( fd_eqvoc_t * eqvoc,
              ulong        slot ) {

  /* This is technically FIFO but because equivocation is only proved
     once per slot (elements are never updated after insertion) it's
     effectively LRU eviction. */

  if( FD_UNLIKELY( !slot_pool_free( eqvoc->slot_pool ) ) ) {
    ulong idx = slot_deque_pop_head( eqvoc->slot_deque );
    slot_map_idx_remove_fast( eqvoc->slot_map, idx, eqvoc->slot_pool );
    slot_pool_idx_release( eqvoc->slot_pool, idx );
  }

  slot_t * slot_ = slot_pool_ele_acquire( eqvoc->slot_pool );
  slot_->slot    = slot;
  slot_map_ele_insert( eqvoc->slot_map, slot_, eqvoc->slot_pool );
  return slot_;
}

int
fd_eqvoc_shred_insert( fd_eqvoc_t *                eqvoc,
                       fd_shred_t const *          shred,
                       fd_gossip_duplicate_shred_t chunks_out[static FD_EQVOC_CHUNK_CNT] ) {

  /* Short-circuit if we already know this shred equivocates. */

  ulong     slot   = shred->slot;
  slot_t *  slot_  = slot_map_ele_query( eqvoc->slot_map, &slot, NULL, eqvoc->slot_pool );
  if( FD_UNLIKELY( slot_ && slot_->err > FD_EQVOC_SUCCESS ) ) return FD_EQVOC_SUCCESS; /* already proved equivocation in this slot */

  /* Many equivocation checks are based on conflicts between two shreds
     within the same FEC set, so we index shreds by a composite key of
     32 msb slot and 32 lsb fec_set_idx to compare siblings shreds in
     the same FEC set. */

  ulong key = shred->slot << 32 | shred->fec_set_idx;

  /* Check if we already have indexed a sibling shred in the same FEC
     set, which we can use to check for equivocation. */

  shred_t * shred_ = shred_map_ele_query( eqvoc->shred_map, &key, NULL, eqvoc->shred_pool );

  /* If this FEC set hasn't been indexed, use this shred to do so. */

  if( FD_UNLIKELY( !shred_ ) ) {
    shred_      = shred_pool_ele_acquire( eqvoc->shred_pool );
    shred_->key = shred->slot << 32 | shred->fec_set_idx;
    fd_memcpy( &shred_->shred, shred, fd_shred_sz( shred ) );
    shred_map_ele_insert( eqvoc->shred_map, shred_, eqvoc->shred_pool );
    return FD_EQVOC_SUCCESS;
  }

  /* Check if this is the last shred, which we also index, because it
     allows us to check for last index conflicts. */

  if( FD_UNLIKELY( fd_shred_is_data( fd_shred_type( shred->variant ) ) && shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    if( FD_LIKELY( !slot_ ) ) slot_ = slot_insert( eqvoc, slot );
    fd_memcpy( &slot_->shred.shred, shred, FD_SHRED_MIN_SZ /* always a data shred */ );
  }

  /* Verify if the shred equivocates and construct a proof if so. */

  int err = verify_proof( eqvoc, &shred_->shred, shred );
  if( FD_UNLIKELY( err > FD_EQVOC_SUCCESS ) ) {
    construct_proof( &shred_->shred, shred, chunks_out );
    if( FD_UNLIKELY( !slot_ ) ) slot_ = slot_insert( eqvoc, slot );
    slot_->err = err;
  }
  return err;
}

int
fd_eqvoc_chunk_insert( fd_eqvoc_t                        * eqvoc,
                       fd_pubkey_t const                 * from,
                       fd_gossip_duplicate_shred_t const * chunk ) {

  slot_t * slot_ = slot_map_ele_query( eqvoc->slot_map, &chunk->slot, NULL, eqvoc->slot_pool );
  if( FD_UNLIKELY( slot_ && slot_->err > FD_EQVOC_SUCCESS ) ) return FD_EQVOC_SUCCESS; /* already proved equivocation for this slot */

  xid_t              key   = { .slot = chunk->slot, .from = *from };
  ulong              null  = proof_pool_idx_null( eqvoc->proof_pool );
  fd_eqvoc_proof_t * proof = proof_map_ele_query( eqvoc->proof_map, &key, NULL, eqvoc->proof_pool );
  if( FD_UNLIKELY( !proof ) ) {

    /* The from_map tracks unique pubkeys from gossip and all the proofs
       they've submitted (keyed by slot). */

    from_t * from_ = from_map_query( eqvoc->from_map, *from, NULL );
    if( FD_UNLIKELY( !from_ ) ) from_ = from_map_insert( eqvoc->from_map, *from );

    /* Each unique from pubkey in gossip is limited to slot_max proofs.
       If it exceeds slot_max, evict the least recently rx proof. */

    if( FD_UNLIKELY( proof_deque_full( from_->proofs ) ) ) {

      /* Note proofs are popped from the deque lazily. When a proof is
         completed normally after receiving all chunks, it is not
         immediately removed from the deque, so at this point already
         processed proofs can still be sitting in the deque. */

      ulong slot = proof_deque_pop_head( from_->proofs );
      xid_t key  = { .slot = slot, .from = *from };
      ulong idx  = proof_map_idx_query( eqvoc->proof_map, &key, null, eqvoc->proof_pool );

      /* Optimize for most proofs already having been processed and just
         need lazy pop and were already removed from map / pool. */

      if( FD_UNLIKELY( idx!=null ) ) proof_pool_idx_release( eqvoc->proof_pool, idx );
    }
    proof         = proof_pool_ele_acquire( eqvoc->proof_pool );
    proof->key    = key;
    proof->idxs   = 0;
    proof->prev   = null;
    proof->next   = null;
    proof->buf_sz = 0;
    proof_map_ele_insert( eqvoc->proof_map, proof, eqvoc->proof_pool );
    proof_deque_push_tail( from_->proofs, chunk->slot );
  }

  if( FD_UNLIKELY( fd_uchar_extract_bit( proof->idxs, chunk->chunk_index ) ) ) return FD_EQVOC_SUCCESS; /* already processed chunk */

  fd_memcpy( proof->buf + chunk->chunk_index * FD_EQVOC_CHUNK_SZ, chunk->chunk, chunk->chunk_len );
  proof->buf_sz += chunk->chunk_len;
  proof->idxs = fd_uchar_set_bit( proof->idxs, chunk->chunk_index );
  if( FD_UNLIKELY( proof->idxs!=(1 << FD_EQVOC_CHUNK_CNT) - 1 ) ) return FD_EQVOC_SUCCESS; /* not all chunks received yet */

  ulong              shred1_sz = fd_ulong_load_8( proof->buf );
  fd_shred_t const * shred1    = (fd_shred_t const *)fd_type_pun_const( proof->buf + sizeof(ulong) );
  fd_shred_t const * shred2    = (fd_shred_t const *)fd_type_pun_const( proof->buf + sizeof(ulong) + shred1_sz + sizeof(ulong) );
  int err = verify_proof( eqvoc, shred1, shred2 );
  if( FD_UNLIKELY( err > FD_EQVOC_SUCCESS ) ) {
    if( FD_UNLIKELY( !slot_ ) ) slot_ = slot_insert( eqvoc, chunk->slot );
    slot_->err = err;
  }

  /* We're done processing this chunk-complete proof, so map remove /
     pool release. It is lazily removed from the deque (see above). */

  proof_map_ele_remove_fast( eqvoc->proof_map, proof, eqvoc->proof_pool );
  proof_pool_ele_release( eqvoc->proof_pool, proof );

  return err;
}
