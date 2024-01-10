#include "fd_shredder.h"
#include "../../ballet/shred/fd_shred.h"

void *
fd_shredder_new( void * mem, void const * pubkey, ushort shred_version ) {
  fd_shredder_t * shredder = (fd_shredder_t *)mem;

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL shredder memory" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_shredder_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shredder memory" ));
    return NULL;
  }

  shredder->shred_version = shred_version;
  shredder->entry_batch   = NULL;
  shredder->sz            = 0UL;
  shredder->offset        = 0UL;

  if( FD_UNLIKELY( !fd_sha512_new( shredder->sha512 ) ) ) return NULL;

  memcpy( shredder->leader_pubkey, pubkey, 32UL );

  fd_memset( &(shredder->meta), 0, sizeof(fd_entry_batch_meta_t) );
  shredder->slot              = ULONG_MAX;
  shredder->data_idx_offset   = 0UL;
  shredder->parity_idx_offset = 0UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shredder->magic ) = FD_SHREDDER_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)shredder;
}

fd_shredder_t *
fd_shredder_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL shredder memory" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_shredder_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shredder memory" ));
    return NULL;
  }

  fd_shredder_t * shredder = (fd_shredder_t *)mem;

  if( FD_UNLIKELY( shredder->magic!=FD_SHREDDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_sha512_join( shredder->sha512 ) ) ) return NULL;

  return shredder;
}

void *
fd_shredder_leave(  fd_shredder_t * shredder ) {
  fd_sha512_leave( shredder->sha512 );

  return (void *)shredder;
}

void *
fd_shredder_delete( void *          mem      ) {
  fd_shredder_t * shredder = (fd_shredder_t *)mem;

  if( FD_UNLIKELY( shredder->magic!=FD_SHREDDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shredder->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)shredder;
}


fd_shredder_t *
fd_shredder_init_batch( fd_shredder_t *               shredder,
                        void const    *               entry_batch,
                        ulong                         entry_batch_sz,
                        ulong                         slot,
                        fd_entry_batch_meta_t const * metadata ) {

  if( FD_UNLIKELY( entry_batch_sz==0UL ) ) return NULL; /* FIXME: should this warn? Silently expand it to 1 byte? */

  shredder->entry_batch = entry_batch;
  shredder->sz          = entry_batch_sz;
  shredder->offset      = 0UL;

  if( FD_UNLIKELY( slot != shredder->slot ) ) {
    shredder->data_idx_offset   = 0UL;
    shredder->parity_idx_offset = 0UL;
  }

  shredder->slot = slot;
  shredder->meta = *metadata;

  return shredder;
}


fd_fec_set_t *
fd_shredder_next_fec_set( fd_shredder_t * shredder,
                          void const * signing_private_key,
                          fd_fec_set_t * result ) {
  uchar const * entry_batch = shredder->entry_batch;
  ulong         offset      = shredder->offset;
  ulong         entry_sz    = shredder->sz;

  uchar * * data_shreds   = result->data_shreds;
  uchar * * parity_shreds = result->parity_shreds;

  fd_ed25519_sig_t __attribute__((aligned(32UL))) root_signature;

  if( FD_UNLIKELY( (offset==entry_sz) ) ) return NULL;

  /* Compute how many data and parity shreds to generate */

  ulong entry_bytes_remaining = entry_sz - offset;
  /* how many total payload bytes in this FEC set? */
  ulong chunk_size              = fd_ulong_if( entry_bytes_remaining>=2UL*31200UL, 31200UL, entry_bytes_remaining );
  ulong data_shred_cnt          = fd_shredder_count_data_shreds( chunk_size );
  ulong parity_shred_cnt        = fd_shredder_count_parity_shreds( chunk_size );
  /* Our notion of tree depth counts the root, while the shred version
     doesn't. */
  ulong tree_depth              = fd_bmtree_depth( data_shred_cnt+parity_shred_cnt )-1UL;
  ulong data_shred_payload_sz   = 1115UL - 20UL*tree_depth;
  ulong parity_shred_payload_sz = data_shred_payload_sz + 0x58UL - 0x40UL;
  ulong data_merkle_sz          = parity_shred_payload_sz;
  ulong parity_merkle_sz        = parity_shred_payload_sz + 0x59UL - 0x40UL;

  ulong last_in_batch           = (chunk_size+offset==entry_sz);
  int   block_complete          = shredder->meta.block_complete;

  fd_reedsol_t * reedsol = fd_reedsol_encode_init( shredder->reedsol, parity_shred_payload_sz );


  /* Write headers and copy the data shred payload */
  ulong flags_for_last = ((last_in_batch & (ulong)block_complete)<<7) | (last_in_batch<<6);
  for( ulong i=0UL; i<data_shred_cnt; i++ ) {
    fd_shred_t         * shred = (fd_shred_t *)data_shreds[ i ];
    /* Size in bytes of the payload section of this data shred,
       excluding any zero-padding */
    ulong shred_payload_sz = fd_ulong_min( entry_sz-offset, data_shred_payload_sz );

    shred->variant            = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, (uchar)tree_depth );
    shred->slot               = shredder->slot;
    shred->idx                = (uint  )(shredder->data_idx_offset + i);
    shred->version            = (ushort)(shredder->shred_version);
    shred->fec_set_idx        = (uint  )(shredder->data_idx_offset);
    shred->data.parent_off    = (ushort)(shredder->meta.parent_offset);
    shred->data.flags         = (uchar )(fd_ulong_if( i==data_shred_cnt-1UL, flags_for_last, 0UL ) | (shredder->meta.reference_tick & 0x3FUL));
    shred->data.size          = (ushort)(FD_SHRED_DATA_HEADER_SZ + shred_payload_sz);

    uchar * payload = fd_memcpy( data_shreds[ i ] + FD_SHRED_DATA_HEADER_SZ , entry_batch+offset, shred_payload_sz );
    offset += shred_payload_sz;

    /* Write zero-padding, likely to be a no-op */
    fd_memset( payload+shred_payload_sz, 0, data_shred_payload_sz-shred_payload_sz );

    /* Set the last bytes of the signature field to the Merkle tree
       prefix so we can use the faster batch sha256 API to compute the
       Merkle tree */
    fd_memcpy( shred->signature + 64UL - 26UL, "\x00SOLANA_MERKLE_SHREDS_LEAF", 26UL );

    /* Prepare to generate parity data: data shred starts right after
       signature and goes until start of Merkle proof. */
    fd_reedsol_encode_add_data_shred( reedsol, ((uchar*)shred) + sizeof(fd_ed25519_sig_t) );
  }

  for( ulong j=0UL; j<parity_shred_cnt; j++ ) {
    fd_shred_t         * shred = (fd_shred_t *)parity_shreds[ j ];

    shred->variant            = fd_shred_variant( FD_SHRED_TYPE_MERKLE_CODE, (uchar)tree_depth );
    shred->slot               = shredder->slot;
    shred->idx                = (uint  )(shredder->parity_idx_offset + j);
    shred->version            = (ushort)(shredder->shred_version);
    shred->fec_set_idx        = (uint  )(shredder->data_idx_offset);
    shred->code.data_cnt      = (ushort)(data_shred_cnt);
    shred->code.code_cnt      = (ushort)(parity_shred_cnt);
    shred->code.idx           = (ushort)(j);

    fd_memcpy( shred->signature + 64UL - 26UL, "\x00SOLANA_MERKLE_SHREDS_LEAF", 26UL );

    /* Prepare to generate parity data: parity info starts right after
       signature and goes until start of Merkle proof. */
    fd_reedsol_encode_add_parity_shred( reedsol, parity_shreds[ j ] + FD_SHRED_CODE_HEADER_SZ );
  }

  /* Generate parity data */
  fd_reedsol_encode_fini( reedsol );

  /* Generate Merkle leaves */
  fd_sha256_batch_t * sha256 = fd_sha256_batch_init( shredder->sha256 );
  fd_bmtree_node_t * leaves = shredder->bmtree_leaves;

  for( ulong i=0UL; i<data_shred_cnt; i++ )
    fd_sha256_batch_add( sha256, data_shreds[i]+sizeof(fd_ed25519_sig_t)-26UL,   data_merkle_sz+26UL,   leaves[i].hash );
  for( ulong j=0UL; j<parity_shred_cnt; j++ )
    fd_sha256_batch_add( sha256, parity_shreds[j]+sizeof(fd_ed25519_sig_t)-26UL, parity_merkle_sz+26UL, leaves[j+data_shred_cnt].hash );
  fd_sha256_batch_fini( sha256 );


  /* Generate Merkle Proofs */
  fd_bmtree_commit_t * bmtree = fd_bmtree_commit_init( shredder->_bmtree_footprint, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, tree_depth+1UL );
  fd_bmtree_commit_append( bmtree, leaves, data_shred_cnt+parity_shred_cnt );
  uchar * root = fd_bmtree_commit_fini( bmtree );

  /* Sign Merkle Root */
  fd_ed25519_sign( root_signature, root, 32UL, shredder->leader_pubkey, signing_private_key, shredder->sha512 );

  /* Write signature and Merkle proof */
  for( ulong i=0UL; i<data_shred_cnt; i++ ) {
    fd_shred_t * shred = (fd_shred_t *)data_shreds[ i ];
    fd_memcpy( shred->signature, root_signature, FD_ED25519_SIG_SZ );

    uchar * merkle = data_shreds[ i ] + fd_shred_merkle_off( shred );
    fd_bmtree_get_proof( bmtree, merkle, i );
  }

  for( ulong j=0UL; j<parity_shred_cnt; j++ ) {
    fd_shred_t * shred = (fd_shred_t *)parity_shreds[ j ];

    fd_memcpy( shred->signature, root_signature, FD_ED25519_SIG_SZ );

    uchar * merkle = parity_shreds[ j ] + fd_shred_merkle_off( shred );
    fd_bmtree_get_proof( bmtree, merkle, data_shred_cnt+j );
  }

  shredder->offset             = offset;
  shredder->data_idx_offset   += data_shred_cnt;
  shredder->parity_idx_offset += parity_shred_cnt;

  result->data_shred_cnt   = data_shred_cnt;
  result->parity_shred_cnt = parity_shred_cnt;

  return result;
}

fd_shredder_t * fd_shredder_fini_batch( fd_shredder_t * shredder ) {
  shredder->entry_batch = NULL;
  shredder->sz          = 0UL;
  shredder->offset      = 0UL;

  return shredder;
}
