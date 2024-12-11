#include "fd_eqvoc.h"
#include "../../ballet/shred/fd_shred.h"

void *
fd_eqvoc_new( void * shmem, ulong fec_max, ulong proof_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_eqvoc_t * eqvoc = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoc_t),          sizeof(fd_eqvoc_t) );
  void * fec_pool    = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_fec_pool_align(),    fd_eqvoc_fec_pool_footprint( fec_max ) );
  void * fec_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_fec_map_align(),     fd_eqvoc_fec_map_footprint( fec_max ) );
  void * proof_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_pool_align(),  fd_eqvoc_proof_pool_footprint( proof_max ) );
  void * proof_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_map_align(),   fd_eqvoc_proof_map_footprint( proof_max ) );
  void * proof_dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_dlist_align(), fd_eqvoc_proof_dlist_footprint() );
  void * sha512      = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),            fd_sha512_footprint() );
  void * bmtree_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_bmtree_commit_align(),     fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() );

  eqvoc->fec_max       = fec_max;
  eqvoc->proof_max     = proof_max;
  fd_eqvoc_fec_pool_new( fec_pool, fec_max );
  fd_eqvoc_fec_map_new( fec_map, fec_max, seed );
  fd_eqvoc_proof_pool_new( proof_pool, proof_max );
  fd_eqvoc_proof_map_new( proof_map, proof_max, seed );
  fd_eqvoc_proof_dlist_new( proof_dlist );
  fd_sha512_new( sha512 );
  (void)bmtree_mem; /* does not require new */

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

  FD_SCRATCH_ALLOC_INIT( l, sheqvoc );
  fd_eqvoc_t * eqvoc = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoc_t),          sizeof(fd_eqvoc_t) );
  void * fec_pool    = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_fec_pool_align(),    fd_eqvoc_fec_pool_footprint( eqvoc->fec_max ) );
  void * fec_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_fec_map_align(),     fd_eqvoc_fec_map_footprint( eqvoc->fec_max ) );
  void * proof_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_pool_align(),  fd_eqvoc_proof_pool_footprint( eqvoc->proof_max ) );
  void * proof_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_map_align(),   fd_eqvoc_proof_map_footprint( eqvoc->proof_max ) );
  void * proof_dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_dlist_align(), fd_eqvoc_proof_dlist_footprint() );
  void * sha512      = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),            fd_sha512_footprint() );
  void * bmtree_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_bmtree_commit_align(),     fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() );

  eqvoc->fec_pool    = fd_eqvoc_fec_pool_join( fec_pool );
  eqvoc->fec_map     = fd_eqvoc_fec_map_join( fec_map );
  eqvoc->proof_pool  = fd_eqvoc_proof_pool_join( proof_pool );
  eqvoc->proof_map   = fd_eqvoc_proof_map_join( proof_map );
  eqvoc->proof_dlist = fd_eqvoc_proof_dlist_join( proof_dlist );
  eqvoc->sha512      = fd_sha512_join( sha512 );
  eqvoc->bmtree_mem  = bmtree_mem; /* does not require join */

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

fd_eqvoc_fec_t *
fd_eqvoc_fec_insert( fd_eqvoc_t * eqvoc, ulong slot, uint fec_set_idx ) {
  fd_slot_fec_t key = { slot, fec_set_idx };

  #if FD_EQVOC_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_eqvoc_fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool ) ) ) FD_LOG_ERR(( "[%s] key (%lu, %u) already in map.", __func__, slot, fec_set_idx ));
  #endif

  /* FIXME eviction */

  if( FD_UNLIKELY( !fd_eqvoc_fec_pool_free( eqvoc->fec_pool ) ) ) {
    fd_eqvoc_fec_t * fec = fd_eqvoc_fec_dlist_ele_pop_head( eqvoc->fec_dlist, eqvoc->fec_pool );
    fd_eqvoc_fec_t * ele = fd_eqvoc_fec_map_ele_remove( eqvoc->fec_map, &fec->key, NULL, eqvoc->fec_pool );
    #if FD_EQVOC_USE_HANDHOLDING
    FD_TEST( fec == ele );
    #endif
    fd_eqvoc_fec_pool_ele_release( eqvoc->fec_pool, fec );
  }

  fd_eqvoc_fec_t * fec = fd_eqvoc_fec_pool_ele_acquire( eqvoc->fec_pool );

  fec->key.slot        = slot;
  fec->key.fec_set_idx = fec_set_idx;
  fec->prev            = fd_eqvoc_proof_pool_idx_null( eqvoc->proof_pool );
  fec->next            = fd_eqvoc_proof_pool_idx_null( eqvoc->proof_pool );
  fec->hash            = fd_eqvoc_proof_pool_idx_null( eqvoc->proof_pool );

  fec->code_cnt = 0;
  fec->data_cnt = 0;
  fec->last_idx = FD_SHRED_IDX_NULL;

  fd_eqvoc_fec_dlist_ele_push_tail( eqvoc->fec_dlist, fec, eqvoc->fec_pool );
  fd_eqvoc_fec_map_ele_insert( eqvoc->fec_map, fec, eqvoc->fec_pool);

  return fec;
}

fd_eqvoc_fec_t const *
fd_eqvoc_fec_search( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_fec_t const * entry = fd_eqvoc_fec_query( eqvoc, shred->slot, shred->fec_set_idx );

  /* If we've already seen a shred in this FEC set */

  if( FD_LIKELY( entry ) ) {

    /* Make sure the signature matches. Every merkle shred in the FEC
       set must have the same signature. */

    if( FD_UNLIKELY( 0 != memcmp( entry->sig, shred->signature, FD_ED25519_SIG_SZ ) ) ) {
      return entry;
    }

    /* Check if this shred's idx is higher than another shred that claimed
       to be the last_idx. This indicates equivocation. */

    if( FD_UNLIKELY( shred->idx > entry->last_idx ) ) {
      return entry;
    }
  }

  /* Look backward FEC_MAX idxs for overlap. */

  for( uint i = 1; shred->fec_set_idx >= i && i < FD_EQVOC_FEC_MAX; i++ ) {
    fd_eqvoc_fec_t const * conflict = fd_eqvoc_fec_query( eqvoc, shred->slot, shred->fec_set_idx - i );
    if( FD_UNLIKELY( conflict &&
                     conflict->data_cnt > 0 &&
                     conflict->key.fec_set_idx + conflict->data_cnt > shred->fec_set_idx ) ) {
      return conflict;
    }
  }

  /* Look forward data_cnt idxs for overlap. */

  for( uint i = 1; entry && i < entry->data_cnt; i++ ) {
    fd_eqvoc_fec_t const * conflict = fd_eqvoc_fec_query( eqvoc, shred->slot, shred->fec_set_idx + i );
    if( FD_UNLIKELY( conflict ) ) return conflict;
  }

  return NULL; /* No conflicts */
}

int
fd_eqvoc_fec_verify( FD_PARAM_UNUSED fd_eqvoc_t const * eqvoc,
                     fd_blockstore_t *                  blockstore,
                     ulong                              slot,
                     uint                               fec_set_idx,
                     fd_hash_t *                        chained_hash ) {

  fd_shred_t * shred = NULL;
  uint         idx   = fec_set_idx;
  do {
    shred = fd_buf_shred_query( blockstore, slot, idx );

#if FD_EQVOC_USE_HANDHOLDING
    if( FD_UNLIKELY( !shred ) ) {
      FD_LOG_WARNING(( "[%s] couldn't find shred %lu %u", __func__, slot, fec_set_idx ));
      return 0;
    }
#endif

#if FD_EQVOC_USE_HANDHOLDING
    FD_TEST( fd_shred_is_chained( fd_shred_type( shred->variant ) ) );
#endif

    if( FD_UNLIKELY( 0 != memcmp( chained_hash, shred + fd_shred_chain_off( shred->variant ), FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
      return 0;
    }

  } while( shred->fec_set_idx == fec_set_idx );

  return 1;
}

fd_eqvoc_proof_t *
fd_eqvoc_proof_insert( fd_eqvoc_t * eqvoc, ulong slot, fd_pubkey_t const * from ) {
  fd_slot_pubkey_t key = { slot, *from };

  #if FD_EQVOC_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_eqvoc_proof_map_ele_query( eqvoc->proof_map, &key, NULL, eqvoc->proof_pool ) ) ) FD_LOG_ERR(( "[%s] key (%lu, %s) already in map.", __func__, slot, FD_BASE58_ENC_32_ALLOCA( from->uc ) ));
  #endif

  if( FD_UNLIKELY( !fd_eqvoc_proof_pool_free( eqvoc->proof_pool ) ) ) {
    fd_eqvoc_proof_t * proof = fd_eqvoc_proof_dlist_ele_pop_head( eqvoc->proof_dlist, eqvoc->proof_pool );
    fd_eqvoc_proof_t * ele   = fd_eqvoc_proof_map_ele_remove( eqvoc->proof_map, &proof->key, NULL, eqvoc->proof_pool );
    #if FD_EQVOC_USE_HANDHOLDING
    FD_TEST( proof == ele );
    #endif
    fd_eqvoc_proof_pool_ele_release( eqvoc->proof_pool, proof );
  }

  fd_eqvoc_proof_t * proof = fd_eqvoc_proof_pool_ele_acquire( eqvoc->proof_pool );

  proof->key.slot = slot;
  proof->key.hash = *from;
  proof->prev     = fd_eqvoc_proof_pool_idx_null( eqvoc->proof_pool );
  proof->next     = fd_eqvoc_proof_pool_idx_null( eqvoc->proof_pool );
  proof->hash     = fd_eqvoc_proof_pool_idx_null( eqvoc->proof_pool );

  proof->producer   = *fd_epoch_leaders_get( eqvoc->leaders, slot );
  proof->bmtree_mem = eqvoc->bmtree_mem;
  proof->wallclock  = 0;
  proof->chunk_cnt  = 0;
  proof->chunk_sz   = 0;
  fd_eqvoc_proof_set_null( proof->set );

  fd_eqvoc_proof_dlist_ele_push_tail( eqvoc->proof_dlist, proof, eqvoc->proof_pool );
  fd_eqvoc_proof_map_ele_insert( eqvoc->proof_map, proof, eqvoc->proof_pool );

  return proof;
}

void
fd_eqvoc_proof_chunk_insert( fd_eqvoc_proof_t * proof, fd_gossip_duplicate_shred_t const * chunk ) {
  if( FD_UNLIKELY( chunk->wallclock > proof->wallclock ) ) {
    if( FD_UNLIKELY( proof->wallclock != 0 ) ) FD_LOG_WARNING(( "[%s] received newer chunk (slot: %lu from: %s). overwriting.", __func__, proof->key.slot, FD_BASE58_ENC_32_ALLOCA( proof->key.hash.uc ) ));
    proof->wallclock = chunk->wallclock;
    proof->chunk_cnt = chunk->num_chunks;
    if( FD_LIKELY( chunk->chunk_index != chunk->num_chunks - 1 ) ) {
      proof->chunk_sz = chunk->chunk_len;
    }
    fd_eqvoc_proof_set_null( proof->set );
  }

  if ( FD_UNLIKELY( chunk->wallclock < proof->wallclock ) ) {
    FD_LOG_WARNING(( "[%s] received older chunk (slot: %lu from: %s). ignoring.", __func__, proof->key.slot, FD_BASE58_ENC_32_ALLOCA( proof->key.hash.uc ) ));
    return;
  }

  if( FD_UNLIKELY( proof->chunk_cnt != chunk->num_chunks ) ) {
    FD_LOG_WARNING(( "[%s] received incompatible chunk (slot: %lu from: %s). ignoring.", __func__, proof->key.slot, FD_BASE58_ENC_32_ALLOCA( proof->key.hash.uc ) ));
    return;
  }

  if( FD_UNLIKELY( fd_eqvoc_proof_set_test( proof->set, chunk->chunk_index ) ) ) {
    FD_LOG_WARNING(( "[%s] already received chunk %u. slot: %lu from: %s. ignoring.", __func__, chunk->chunk_index, proof->key.slot, FD_BASE58_ENC_32_ALLOCA( proof->key.hash.uc ) ));
    return;
  }

  fd_memcpy( &proof->shreds[proof->chunk_sz * chunk->chunk_index], chunk->chunk, chunk->chunk_len );
  fd_eqvoc_proof_set_insert( proof->set, chunk->chunk_index );
}

void
fd_eqvoc_proof_remove( fd_eqvoc_t * eqvoc, fd_slot_pubkey_t const * key ) {
  fd_eqvoc_proof_t * proof = fd_eqvoc_proof_map_ele_remove( eqvoc->proof_map, key, NULL, eqvoc->proof_pool );
  if( FD_UNLIKELY( !proof ) ) {
    FD_LOG_WARNING(( "[%s] key (%lu, %s) not in map.", __func__, key->slot, FD_BASE58_ENC_32_ALLOCA( key->hash.uc ) ));
    return;
  }
  fd_eqvoc_proof_dlist_ele_remove( eqvoc->proof_dlist, proof, eqvoc->proof_pool );
  fd_eqvoc_proof_pool_ele_release( eqvoc->proof_pool, proof );
}

int
fd_eqvoc_proof_verify( fd_eqvoc_proof_t const * proof ) {
  #if FD_EQVOC_USE_HANDHOLDING
  FD_TEST( fd_eqvoc_proof_complete( proof ) );
  #endif
  return fd_eqvoc_shreds_verify( fd_eqvoc_proof_shred1_const( proof ), fd_eqvoc_proof_shred2_const( proof ), &proof->producer, proof->bmtree_mem );
}

int
fd_eqvoc_shreds_verify( fd_shred_t const * shred1, fd_shred_t const * shred2, fd_pubkey_t const * producer, void * bmtree_mem ) {
  if( FD_UNLIKELY( shred1->slot != shred2->slot ) ) {
    return FD_EQVOC_PROOF_VERIFY_ERR_SLOT;
  }

  if( FD_UNLIKELY( shred1->version != shred2->version ) ) {
    return FD_EQVOC_PROOF_VERIFY_ERR_VERSION;
  }

  if( FD_UNLIKELY( !fd_shred_is_chained ( fd_shred_type( shred1->variant) ) &&
                   !fd_shred_is_resigned( fd_shred_type( shred2->variant ) ) ) ) {
    return FD_EQVOC_PROOF_VERIFY_ERR_TYPE;
  }

  /* Check both shreds contain valid signatures from the assigned leader
     to that slot. This requires deriving the merkle root and
     sig-verifying it, because the leader signs the merkle root for
     merkle shreds.

     TODO remove? */

  fd_bmtree_node_t root1 = { 0 };
  if( FD_UNLIKELY( !fd_shred_merkle_root( shred1, bmtree_mem, &root1 ) ) ) {
    return FD_EQVOC_PROOF_VERIFY_ERR_MERKLE;
  }
  fd_bmtree_node_t root2;
  if( FD_UNLIKELY( !fd_shred_merkle_root( shred2, bmtree_mem, &root2 ) ) ) {
    return FD_EQVOC_PROOF_VERIFY_ERR_MERKLE;
  }
  fd_sha512_t _sha512[1];
  fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( _sha512 ) );
  if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( root1.hash,
                                                            32UL,
                                                            shred1->signature,
                                                            producer->uc,
                                                            sha512 ) ||
                   FD_ED25519_SUCCESS != fd_ed25519_verify( root2.hash,
                                                            32UL,
                                                            shred2->signature,
                                                            producer->uc,
                                                            sha512 ) ) ) {
    return FD_EQVOC_PROOF_VERIFY_ERR_SIGNATURE;
  }

  /* Same FEC set index checks */

  if( FD_LIKELY( shred1->fec_set_idx == shred2->fec_set_idx ) ) {

    /* Test if two shreds have different signatures when they are in the
      same FEC set. */

    if( FD_LIKELY( 0 != memcmp( shred1->signature, shred2->signature, FD_ED25519_SIG_SZ ) ) ) {
      return FD_EQVOC_PROOF_VERIFY_SUCCESS_SIGNATURE;
    }

    /* Test if the shreds have different coding metadata when they're
       both coding shreds in the same FEC set. */

    if( FD_UNLIKELY( fd_shred_is_code( fd_shred_type( shred1->variant ) ) &&
                     fd_shred_is_code( fd_shred_type( shred2->variant ) ) &&
                     ( shred1->code.code_cnt != shred2->code.code_cnt ||
                       shred1->code.data_cnt != shred2->code.data_cnt ||
                       shred1->idx - shred1->code.idx == shred2->idx - shred2->code.idx ) ) ) {
      return FD_EQVOC_PROOF_VERIFY_SUCCESS_META;
    }

    /* Test if one shred is marked the last shred in the slot, but the
       other shred has a higher index when both shreds are data
       shreds. */

    if( FD_UNLIKELY( fd_shred_is_data( fd_shred_type( shred1->variant ) ) &&
                     fd_shred_is_data( fd_shred_type( shred2->variant ) ) &&
                     ( ( shred1->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred2->idx > shred1->idx )  ||
                       ( shred2->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred1->idx > shred2->idx ) ) ) ) {
      return FD_EQVOC_PROOF_VERIFY_SUCCESS_LAST;
    }
  }

  /* Different FEC set index checks. Lower FEC set index shred must be a
     coding shred. */

  fd_shred_t const * lo = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx, shred1, shred2 );
  fd_shred_t const * hi = fd_ptr_if( shred1->fec_set_idx > shred2->fec_set_idx, shred1, shred2 );

  if ( FD_UNLIKELY( fd_shred_is_code( fd_shred_type( lo->variant ) ) ) ) {

    /* Test for overlap. The FEC sets overlap if the lower fec_set_idx +
       data_cnt > higher fec_set_idx. We must have received at least one
       coding shred in the FEC set with the lower fec_set_idx to perform
       this check. */

    if( FD_UNLIKELY( lo->fec_set_idx + lo->code.data_cnt > hi->fec_set_idx ) ) {
      return FD_EQVOC_PROOF_VERIFY_SUCCESS_OVERLAP;
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
      if ( FD_LIKELY( 0 != memcmp( merkle_hash, chained_hash, FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
        return FD_EQVOC_PROOF_VERIFY_SUCCESS_CHAINED;
      };
    }
  }

  /* None of the equivocation tests passed, so this equivocation proof
     failed to verify. */

  return FD_EQVOC_PROOF_VERIFY_FAILURE;
}

void
fd_eqvoc_proof_from_chunks( fd_gossip_duplicate_shred_t const * chunks,
                            fd_eqvoc_proof_t * proof_out ) {
  ulong chunk_cnt = chunks[0].num_chunks;
  for ( ulong i = 0; i < chunk_cnt; i++ ) {
    fd_eqvoc_proof_chunk_insert( proof_out, chunks + i );
  }
}

void
fd_eqvoc_proof_to_chunks( fd_eqvoc_proof_t * proof, fd_gossip_duplicate_shred_t * chunks_out ) {
  for (uchar i = 0; i < FD_EQVOC_PROOF_CHUNK_CNT; i++ ) {
    fd_gossip_duplicate_shred_t * chunk = &chunks_out[i];
    chunk->duplicate_shred_index = i;
    chunk->from = proof->key.hash;
    chunk->wallclock = (ulong)fd_log_wallclock();
    chunk->slot = proof->key.slot;
    chunk->num_chunks = FD_EQVOC_PROOF_CHUNK_CNT;
    chunk->chunk_len = FD_EQVOC_PROOF_CHUNK_MAX;
    ulong off = i * FD_EQVOC_PROOF_CHUNK_MAX;
    ulong sz  = fd_ulong_min( FD_EQVOC_PROOF_CHUNK_MAX, FD_EQVOC_PROOF_MAX - off );
    fd_memcpy( chunks_out[i].chunk, proof->shreds + off, sz );
  }
}
