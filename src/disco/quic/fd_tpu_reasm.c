#include "fd_tpu_reasm_private.h"
#include "../../waltz/quic/fd_quic_enum.h"

FD_FN_CONST ulong
fd_tpu_reasm_align( void ) {
  return alignof(fd_tpu_reasm_t);
}

FD_FN_CONST ulong
fd_tpu_reasm_footprint( ulong depth,
                        ulong burst ) {

  if( FD_UNLIKELY(
      ( fd_ulong_popcnt( depth )!=1 ) |
      ( depth>0x7fffffffUL          ) |
      ( burst<2                     ) |
      ( burst>0x7fffffffUL          ) ) )
    return 0UL;

  ulong chain_cnt = fd_tpu_reasm_map_chain_cnt_est( burst );
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      FD_TPU_REASM_ALIGN,           sizeof(fd_tpu_reasm_t)                        ), /* hdr       */
      alignof(uint),                 (depth)         *sizeof(uint)                ), /* pub_slots */
      alignof(fd_tpu_reasm_slot_t), ((depth)+(burst))*sizeof(fd_tpu_reasm_slot_t) ), /* slots     */
      FD_CHUNK_ALIGN,               ((depth)+(burst))*FD_TPU_REASM_MTU            ), /* chunks    */
      fd_tpu_reasm_map_align(),     fd_tpu_reasm_map_footprint( chain_cnt )       ), /* map       */
      FD_TPU_REASM_ALIGN );

}

void *
fd_tpu_reasm_new( void * shmem,
                  ulong  depth,
                  ulong  burst,
                  ulong  orig ) {

  if( FD_UNLIKELY( !shmem ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, FD_TPU_REASM_ALIGN ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_tpu_reasm_footprint( depth, burst ) ) ) return NULL;
  if( FD_UNLIKELY( orig > FD_FRAG_META_ORIG_MAX ) ) return NULL;

  /* Memory layout */

  ulong slot_cnt = depth+burst;
  if( FD_UNLIKELY( !slot_cnt ) ) return NULL;
  ulong chain_cnt = fd_tpu_reasm_map_chain_cnt_est( burst );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tpu_reasm_t *      reasm     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tpu_reasm_t), sizeof(fd_tpu_reasm_t) );
  ulong *               pub_slots = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                depth*sizeof(uint)                      );
  fd_tpu_reasm_slot_t * slots     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_tpu_reasm_slot_t), slot_cnt*sizeof(fd_tpu_reasm_slot_t)    );
  uchar *               chunks    = FD_SCRATCH_ALLOC_APPEND( l, FD_CHUNK_ALIGN,               slot_cnt*FD_TPU_REASM_MTU               );
  void *                map_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_tpu_reasm_map_align(),     fd_tpu_reasm_map_footprint( chain_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_tpu_reasm_t) );

  fd_memset( reasm, 0, sizeof(fd_tpu_reasm_t) );
  fd_memset( slots, 0, burst*sizeof(fd_tpu_reasm_slot_t) );

  fd_tpu_reasm_map_t * map = fd_tpu_reasm_map_join( fd_tpu_reasm_map_new( map_mem, chain_cnt, 0UL ) );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "fd_tpu_reasm_map_new failed" ));
    return NULL;
  }

  /* Initialize reasm object */

  reasm->slots_off     = (ulong)( (uchar *)slots     - (uchar *)reasm );
  reasm->pub_slots_off = (ulong)( (uchar *)pub_slots - (uchar *)reasm );
  reasm->chunks_off    = (ulong)( (uchar *)chunks    - (uchar *)reasm );
  reasm->map_off       = (ulong)( (uchar *)map       - (uchar *)reasm );

  reasm->depth    = (uint)depth;
  reasm->burst    = (uint)burst;
  reasm->head     = (uint)slot_cnt-1U;
  reasm->tail     = (uint)depth;
  reasm->slot_cnt = (uint)slot_cnt;
  reasm->orig     = (ushort)orig;

  /* Initial slot distribution */

  fd_tpu_reasm_reset( reasm );

  FD_COMPILER_MFENCE();
  reasm->magic = FD_TPU_REASM_MAGIC;
  FD_COMPILER_MFENCE();

  return reasm;
}

void
fd_tpu_reasm_reset( fd_tpu_reasm_t * reasm ) {

  uint depth    = reasm->depth;
  uint burst    = reasm->burst;
  uint node_cnt = depth+burst;

  fd_tpu_reasm_slot_t * slots     = fd_tpu_reasm_slots_laddr( reasm );
  uint *                pub_slots = fd_tpu_reasm_pub_slots_laddr( reasm );
  fd_tpu_reasm_map_t *  map       = fd_tpu_reasm_map_laddr( reasm );

  /* The initial state moves the first 'depth' slots to the mcache (PUB)
     and leaves the rest as FREE. */

  for( uint j=0U; j<depth; j++ ) {
    fd_tpu_reasm_slot_t * slot = slots + j;
    slot->k.state     = FD_TPU_REASM_STATE_PUB;
    slot->k.conn_uid  = ULONG_MAX;
    slot->k.stream_id = 0xffffffffffff;
    slot->k.sz        = 0;
    slot->chain_next = UINT_MAX;
    pub_slots[ j ]   = j;
  }
  for( uint j=depth; j<node_cnt; j++ ) {
    fd_tpu_reasm_slot_t * slot = slots + j;
    slot->k.state     = FD_TPU_REASM_STATE_FREE;
    slot->k.conn_uid  = ULONG_MAX;
    slot->k.stream_id = 0xffffffffffff;
    slot->k.sz        = 0;
    slot->lru_prev    = fd_uint_if( j<node_cnt-1U, j+1U, UINT_MAX );
    slot->lru_next    = fd_uint_if( j>depth,       j-1U, UINT_MAX );
    slot->chain_next  = UINT_MAX;
  }

  /* Clear the entire hash map */

  ulong  chain_cnt = fd_tpu_reasm_map_chain_cnt( map );
  uint * chains    = fd_tpu_reasm_map_private_chain( map );
  for( uint j=0U; j<chain_cnt; j++ ) {
    chains[ j ] = UINT_MAX;
  }
}

fd_tpu_reasm_t *
fd_tpu_reasm_join( void * shreasm ) {
  fd_tpu_reasm_t * reasm = shreasm;
  if( FD_UNLIKELY( reasm->magic != FD_TPU_REASM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return reasm;
}

void *
fd_tpu_reasm_leave( fd_tpu_reasm_t * reasm ) {
  return reasm;
}

void *
fd_tpu_reasm_delete( void * shreasm ) {
  fd_tpu_reasm_t * reasm = shreasm;
  if( FD_UNLIKELY( !reasm ) ) return NULL;
  reasm->magic = 0UL;
  return shreasm;
}

FD_FN_CONST ulong
fd_tpu_reasm_chunk0( fd_tpu_reasm_t const * reasm,
                     void const *           base ) {
  return fd_laddr_to_chunk( base, slot_get_data_const( reasm, 0UL ) );
}


FD_FN_CONST ulong
fd_tpu_reasm_wmark( fd_tpu_reasm_t const * reasm,
                    void const *           base ) {
  /* U.B. if slot_cnt==0, but this is checked in fd_tpu_reasm_new */
  return fd_laddr_to_chunk( base, slot_get_data_const( reasm, reasm->slot_cnt - 1UL ) );
}


fd_tpu_reasm_slot_t *
fd_tpu_reasm_acquire( fd_tpu_reasm_t * reasm,
                      ulong            conn_uid,
                      ulong            stream_id,
                      long             tsorig ) {
  fd_tpu_reasm_slot_t * slot = slotq_pop_tail( reasm );
  uint was_overrun = slot->k.state == FD_TPU_REASM_STATE_BUSY;
  if( was_overrun ) {
    smap_remove( reasm, slot );
  }
  slot_begin( slot );
  slotq_push_head( reasm, slot );
  slot->k.conn_uid  = conn_uid;
  slot->k.stream_id = stream_id & FD_TPU_REASM_SID_MASK;
  smap_insert( reasm, slot );
  slot->tsorig_comp = (uint)fd_frag_meta_ts_comp( tsorig );
  return slot;
}

int
fd_tpu_reasm_frag( fd_tpu_reasm_t *      reasm,
                   fd_tpu_reasm_slot_t * slot,
                   uchar const *         data,
                   ulong                 data_sz,
                   ulong                 data_off ) {

  if( FD_UNLIKELY( slot->k.state != FD_TPU_REASM_STATE_BUSY ) )
    return FD_TPU_REASM_ERR_STATE;

  ulong slot_idx = slot_get_idx( reasm, slot );
  ulong mtu      = FD_TXN_MTU;
  ulong sz0      = slot->k.sz;

  if( FD_UNLIKELY( data_off>sz0 ) ) {
    fd_tpu_reasm_cancel( reasm, slot );
    return FD_TPU_REASM_ERR_SKIP;
  }

  if( FD_UNLIKELY( data_off<sz0 ) ) {
    /* Fragment partially known ... should not happen */
    ulong skip = sz0 - data_off;
    if( skip>data_sz ) return FD_TPU_REASM_SUCCESS;
    data_off  += skip;
    data_sz   -= skip;
    data      += skip;
  }

  ulong sz1 = sz0 + data_sz;
  if( FD_UNLIKELY( (sz1<sz0)|(sz1>mtu) ) ) {
    fd_tpu_reasm_cancel( reasm, slot );
    return FD_TPU_REASM_ERR_SZ;
  }

  uchar * msg = slot_get_data( reasm, slot_idx );
  fd_memcpy( msg+sz0, data, data_sz );

  slot->k.sz = (ushort)( sz1 & 0x3fff );
  return FD_TPU_REASM_SUCCESS;
}

int
fd_tpu_reasm_publish( fd_tpu_reasm_t *      reasm,
                      fd_tpu_reasm_slot_t * slot,
                      fd_frag_meta_t *      mcache,
                      void *                base,  /* Assumed aligned FD_CHUNK_ALIGN */
                      ulong                 seq,
                      long                  tspub ) {

  if( FD_UNLIKELY( slot->k.state != FD_TPU_REASM_STATE_BUSY ) )
    return FD_TPU_REASM_ERR_STATE;

  /* Derive chunk index */
  uint    slot_idx      = slot_get_idx( reasm, slot );
  uchar * data          = slot_get_data( reasm, slot_idx );
  ulong   data_laddr    = (ulong)data;
  ulong   chunk         = fd_laddr_to_chunk( base, (void *)data_laddr );
  if( FD_UNLIKELY( ( data_laddr<(ulong)base ) |
                   ( chunk>UINT_MAX         ) ) ) {
    FD_LOG_CRIT(( "invalid base %p for slot %p in tpu_reasm %p",
                  base, (void *)slot, (void *)reasm ));
  }

  /* Acquire mcache line */
  ulong  depth          = reasm->depth;

  /* Detect which slot this message belongs to */
  uint * pub_slot       = fd_tpu_reasm_pub_slots_laddr( reasm ) + fd_mcache_line_idx( seq, depth );
  uint   freed_slot_idx = *pub_slot;

  if( FD_UNLIKELY( freed_slot_idx >= reasm->slot_cnt ) ) {
    /* mcache corruption */
    FD_LOG_WARNING(( "mcache corruption detected! tpu_reasm slot %u out of bounds (max %u)",
                     freed_slot_idx, reasm->slot_cnt ));
    fd_tpu_reasm_reset( reasm );
    return FD_TPU_REASM_ERR_STATE;
  }

  /* Mark new slot as published */
  slotq_remove( reasm, slot );
  smap_remove( reasm, slot );
  slot->k.state = FD_TPU_REASM_STATE_PUB;
  *pub_slot = slot_idx;

  /* Free oldest published slot */
  fd_tpu_reasm_slot_t * free_slot = fd_tpu_reasm_slots_laddr( reasm ) + freed_slot_idx;
  uint free_slot_state = free_slot->k.state;
  if( FD_UNLIKELY( free_slot_state != FD_TPU_REASM_STATE_PUB ) ) {
    /* mcache/slots out of sync (memory leak) */
    FD_LOG_WARNING(( "mcache corruption detected! tpu_reasm seq %lu owns slot %u, but it's state is %u",
                     seq, freed_slot_idx, free_slot_state ));
    fd_tpu_reasm_reset( reasm );
    return FD_TPU_REASM_ERR_STATE;
  }
  free_slot->k.state = FD_TPU_REASM_STATE_FREE;
  slotq_push_tail( reasm, free_slot );

  /* Publish to mcache */
  ulong sz          = slot->k.sz;
  ulong ctl         = fd_frag_meta_ctl( reasm->orig, 1, 1, 0 );
  ulong tsorig_comp = slot->tsorig_comp;
  ulong tspub_comp  = fd_frag_meta_ts_comp( tspub );

# if FD_HAS_AVX
  fd_mcache_publish_avx( mcache, depth, seq, 0UL, chunk, sz, ctl, tsorig_comp, tspub_comp );
# elif FD_HAS_SSE
  fd_mcache_publish_sse( mcache, depth, seq, 0UL, chunk, sz, ctl, tsorig_comp, tspub_comp );
# else
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  FD_COMPILER_MFENCE();
  meta->seq    = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  meta->chunk  = (uint  )chunk;
  meta->sz     = (ushort)sz;
  meta->ctl    = (ushort)ctl;
  meta->tsorig = (uint  )tsorig_comp;
  meta->tspub  = (uint  )tspub_comp;
  FD_COMPILER_MFENCE();
  meta->seq    = seq;
  FD_COMPILER_MFENCE();
# endif

  return FD_TPU_REASM_SUCCESS;
}

void
fd_tpu_reasm_cancel( fd_tpu_reasm_t *      reasm,
                     fd_tpu_reasm_slot_t * slot ) {
  if( FD_UNLIKELY( slot->k.state == FD_TPU_REASM_STATE_FREE ) ) return;
  slotq_remove( reasm, slot );
  smap_remove( reasm, slot );
  slot->k.state     = FD_TPU_REASM_STATE_FREE;
  slot->k.conn_uid  = FD_QUIC_STREAM_ID_UNUSED;
  slot->k.stream_id = 0UL;
  slotq_push_tail( reasm, slot );
}

void
fd_tpu_reasm_publish_fast( fd_tpu_reasm_t * reasm,
                           uchar const *    data,
                           ulong            sz,
                           fd_frag_meta_t * mcache,
                           void *           base,  /* Assumed aligned FD_CHUNK_ALIGN */
                           ulong            seq,
                           long             tspub ) {

  fd_tpu_reasm_slot_t * slot = slotq_pop_tail( reasm );
  if( slot->k.state == FD_TPU_REASM_STATE_BUSY ) {
    smap_remove( reasm, slot );
  }

  /* Derive chunk index */
  uint    slot_idx  = slot_get_idx( reasm, slot );
  uchar * buf       = slot_get_data( reasm, slot_idx );
  ulong   chunk     = fd_laddr_to_chunk( base, buf );
  if( FD_UNLIKELY( ( (ulong)buf<(ulong)base ) |
                   ( chunk>UINT_MAX         ) ) ) {
    FD_LOG_ERR(( "Computed invalid chunk index (base=%p buf=%p chunk=%lx)",
                 base, (void *)buf, chunk ));
  }

  /* Acquire mcache line */
  ulong  depth          = reasm->depth;

  /* Detect which slot this message belongs to */
  uint * pub_slot       = fd_tpu_reasm_pub_slots_laddr( reasm ) + fd_mcache_line_idx( seq, depth );
  uint   freed_slot_idx = *pub_slot;

  if( FD_UNLIKELY( freed_slot_idx >= reasm->slot_cnt ) ) {
    /* mcache corruption */
    FD_LOG_WARNING(( "mcache corruption detected! tpu_reasm slot %u out of bounds (max %u)",
                     freed_slot_idx, reasm->slot_cnt ));
    fd_tpu_reasm_reset( reasm );
    return;
  }

  slot->k.state = FD_TPU_REASM_STATE_PUB;
  *pub_slot = slot_idx;

  /* Free oldest published slot */
  fd_tpu_reasm_slot_t * free_slot = fd_tpu_reasm_slots_laddr( reasm ) + freed_slot_idx;
  uint free_slot_state = free_slot->k.state;
  if( FD_UNLIKELY( free_slot_state != FD_TPU_REASM_STATE_PUB ) ) {
    /* mcache/slots out of sync (memory leak) */
    FD_LOG_WARNING(( "mcache corruption detected! tpu_reasm seq %lu owns slot %u, but it's state is %u",
                     seq, freed_slot_idx, free_slot_state ));
    fd_tpu_reasm_reset( reasm );
    return;
  }
  free_slot->k.state = FD_TPU_REASM_STATE_FREE;
  slotq_push_tail( reasm, free_slot );

  /* Copy frag */
  fd_memcpy( buf, data, sz );

  /* Publish to mcache */
  ulong ctl         = fd_frag_meta_ctl( reasm->orig, 1, 1, 0 );
  uint  tsorig_comp = slot->tsorig_comp;
  uint  tspub_comp  = (uint)fd_frag_meta_ts_comp( tspub );

# if FD_HAS_AVX
  fd_mcache_publish_avx( mcache, depth, seq, 0UL, chunk, sz, ctl, tsorig_comp, tspub_comp );
# elif FD_HAS_SSE
  fd_mcache_publish_sse( mcache, depth, seq, 0UL, chunk, sz, ctl, tsorig_comp, tspub_comp );
# else
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  FD_COMPILER_MFENCE();
  meta->seq    = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  meta->chunk  = (uint  )chunk;
  meta->sz     = (ushort)sz;
  meta->ctl    = (ushort)ctl;
  meta->tsorig = tsorig_comp;
  meta->tspub  = tspub_comp;
  FD_COMPILER_MFENCE();
  meta->seq    = seq;
  FD_COMPILER_MFENCE();
# endif
}
