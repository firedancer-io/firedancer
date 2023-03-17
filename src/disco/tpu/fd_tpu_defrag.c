#include "fd_tpu_defrag_private.h"

#include "../../util/fd_util.h"

ulong
fd_tpu_defrag_align( void ) {
  return FD_TPU_DEFRAG_ALIGN;
}

ulong
fd_tpu_defrag_footprint( ulong entry_cnt ) {

  if( FD_UNLIKELY( entry_cnt==0UL ) ) {
    FD_LOG_WARNING(( "zero entry_cnt" ));
    return 0UL;
  }

  ulong  sz  = sizeof(struct fd_tpu_defrag_private);
         sz  = fd_ulong_align_up( sz, fd_tpu_defrag_freelist_align() );
         sz += fd_tpu_defrag_freelist_footprint( entry_cnt );
         sz  = fd_ulong_align_up( sz, FD_TPU_DEFRAG_ENTRY_ALIGN );
         sz += entry_cnt*sizeof(fd_tpu_defrag_entry_t);
  return sz;
}

/* fd_tpu_defrag_entry_alloc pops an unused entry off the defragger free
   stack. */
static fd_tpu_defrag_entry_t *
fd_tpu_defrag_entry_alloc( fd_tpu_defrag_t * defragger ) {

  uint * freelist = fd_tpu_defrag_get_freelist( defragger );

  if( FD_UNLIKELY( !fd_tpu_defrag_freelist_cnt( freelist ) ) )
    return NULL; /* no free chunks */

  uint idx = fd_tpu_defrag_freelist_pop( freelist );

  fd_tpu_defrag_entry_t * chunks = fd_tpu_defrag_get_chunks( defragger );
  return &chunks[ idx ];
}

/* fd_tpu_defrag_entry_free marks the given entry as unused and adds it
   to the defragger free stack.  U.B. if entry is already on the free
   stack. */
static void
fd_tpu_defrag_entry_free( fd_tpu_defrag_t *       defragger,
                          fd_tpu_defrag_entry_t * entry ) {

  if( FD_UNLIKELY( entry->stream_id==ULONG_MAX ) )
    return;

  entry->sz        = 0;
  entry->conn_id   = 0UL;
  entry->stream_id = ULONG_MAX;

  fd_tpu_defrag_entry_t * chunks = fd_tpu_defrag_get_chunks( defragger );
  ulong idx = ( (ulong)entry - (ulong)chunks ) / sizeof(fd_tpu_defrag_entry_t);

  uint * freelist = fd_tpu_defrag_get_freelist( defragger );
  fd_tpu_defrag_freelist_push( freelist, (uint)idx );
}

void *
fd_tpu_defrag_new( void * mem,
                   ulong  entry_cnt ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tpu_defrag_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( entry_cnt==0UL ) ) {
    FD_LOG_WARNING(( "zero entry_cnt" ));
    return NULL;
  }

  fd_tpu_defrag_t * defrag = (fd_tpu_defrag_t *)mem;

  ulong off  = sizeof(struct fd_tpu_defrag_private);
        off  = fd_ulong_align_up( off, fd_tpu_defrag_freelist_align() );
  ulong freelist_hdr_off = off;

        off += fd_tpu_defrag_freelist_footprint( entry_cnt );
        off  = fd_ulong_align_up( off, FD_TPU_DEFRAG_ENTRY_ALIGN );
  ulong chunks_off = off;

  ulong freelist_hdr_laddr = (ulong)mem + freelist_hdr_off;
  uint * freelist = fd_tpu_defrag_freelist_join( fd_tpu_defrag_freelist_new( (void *)freelist_hdr_laddr, entry_cnt ) );
  for( ulong i=0UL; i<entry_cnt; i++ )
    fd_tpu_defrag_freelist_push( freelist, (uint)i );

  ulong freelist_off = (ulong)freelist - (ulong)mem;

  defrag->entry_cnt    = entry_cnt;
  defrag->chunks_off   = chunks_off;
  defrag->freelist_off = freelist_off;

  return mem;
}

void *
fd_tpu_defrag_delete( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tpu_defrag_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_tpu_defrag_t * defragger = (fd_tpu_defrag_t *)mem;

  uint * freelist = fd_tpu_defrag_get_freelist( defragger );
  fd_tpu_defrag_freelist_delete( fd_tpu_defrag_freelist_leave( freelist ) );

  memset( defragger, 0, sizeof(fd_tpu_defrag_t) );

  return mem;
}

fd_tpu_defrag_entry_t *
fd_tpu_defrag_entry_start( fd_tpu_defrag_t * defragger,
                           ulong             conn_id,
                           ulong             stream_id ) {

  fd_tpu_defrag_entry_t * entry = fd_tpu_defrag_entry_alloc( defragger );
  if( FD_UNLIKELY( !entry ) )
    return NULL;

  entry->sz        = 0U;
  entry->conn_id   = conn_id;
  entry->stream_id = stream_id;

  return entry;
}

fd_tpu_defrag_entry_t *
fd_tpu_defrag_entry_append( fd_tpu_defrag_t *       defragger,
                            fd_tpu_defrag_entry_t * entry,
                            ulong                   conn_id,
                            ulong                   stream_id,
                            uchar *                 frag,
                            ulong                   frag_sz ) {

  if( FD_UNLIKELY( !fd_tpu_defrag_entry_exists( entry, conn_id, stream_id ) ) )
    return NULL;

  ulong old_sz = (ulong)entry->sz;
  ulong new_sz = old_sz + frag_sz;
  if( FD_UNLIKELY( new_sz>FD_TPU_MTU || new_sz<frag_sz ) ) {
    fd_tpu_defrag_entry_free( defragger, entry );
    return NULL;
  }

  entry->sz = (ushort)new_sz;
  fd_memcpy( entry->chunk+old_sz, frag, frag_sz );

  return entry;
}

void
fd_tpu_defrag_entry_fini( fd_tpu_defrag_t *       defragger,
                          fd_tpu_defrag_entry_t * entry,
                          ulong                   conn_id,
                          ulong                   stream_id ) {

  if( FD_UNLIKELY( !fd_tpu_defrag_entry_exists( entry, conn_id, stream_id ) ) )
    return;

  fd_tpu_defrag_entry_free( defragger, entry );
}

/* TODO: housekeep aggressively invalidates and frees entries on TTL
   exceed.  Could be optimized to only mark entries as free, and only
   free at next alloc (by leaving the stream ID intact instead of
   unsetting it). */

void
fd_tpu_defrag_housekeep( fd_tpu_defrag_t * defrag ) {
  (void)defrag;
  /* TODO housekeep impl */
}
