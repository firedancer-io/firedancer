#include "fd_gui_chunk.h"

void
fd_gui_chunk_init( fd_gui_chunk_t * c,
                   void *           data ) {
  c->data         = data;
  c->wr           = 0UL;
  c->hi           = 0UL;
  c->now          = 0L;
  c->mode         = 0;
  c->limit        = 0;
  c->hit_cnt      = 0UL;
  c->miss_cnt     = 0UL;
  c->late_cnt     = 0UL;
  c->fallback_cnt = 0UL;
  c->sep_sz       = 0UL;
  c->close_sz     = 0UL;
  for( ulong i=0UL; i<FD_GUI_CHUNK_KIND_CNT; i++ ) {
    for( ulong j=0UL; j<FD_GUI_CHUNK_IDX_CNT; j++ ) c->idx[ i ][ j ] = (fd_gui_chunk_entry_t){ .chunk=ULONG_MAX };
  }
}

uchar *
fd_gui_chunk_prepare( fd_gui_chunk_t * c ) {
  /* Chunks are contiguous: skip the tail of the ring if one might not
     fit. */
  ulong off = c->wr%FD_GUI_CHUNK_CACHE_SZ;
  if( off+FD_GUI_CHUNK_SZ_MAX>FD_GUI_CHUNK_CACHE_SZ ) c->wr += FD_GUI_CHUNK_CACHE_SZ-off;
  c->hi = fd_ulong_max( c->hi, c->wr+FD_GUI_CHUNK_SZ_MAX );
  return c->data + c->wr%FD_GUI_CHUNK_CACHE_SZ;
}

void
fd_gui_chunk_publish( fd_gui_chunk_t * c,
                      int              kind,
                      ulong            k,
                      ulong            len ) {
  c->idx[ kind ][ k%FD_GUI_CHUNK_IDX_CNT ] = (fd_gui_chunk_entry_t){ .chunk=k, .pos=c->wr, .len=len };
  c->wr += len;
}

void
fd_gui_chunk_note( fd_gui_chunk_t * c,
                   ulong            kind_mask,
                   long             lo,
                   long             hi ) {
  if( FD_LIKELY( !c->data ) ) return;
  if( FD_UNLIKELY( lo<0L || hi<lo || hi==LONG_MAX ) ) return;
  ulong k0 = (ulong)(lo/FD_GUI_CHUNK_NS);
  ulong k1 = (ulong)(hi/FD_GUI_CHUNK_NS);
  for( int kind=0; kind<FD_GUI_CHUNK_KIND_CNT; kind++ ) {
    if( !(kind_mask & FD_GUI_CHUNK_MASK( kind )) ) continue;
    ulong edge = fd_gui_chunk_edge( c, kind );
    if( FD_LIKELY( k0>=edge ) ) continue;
    ulong end = fd_ulong_min( fd_ulong_min( k1+1UL, edge ), k0+FD_GUI_CHUNK_IDX_CNT );
    for( ulong k=k0; k<end; k++ ) {
      fd_gui_chunk_entry_t * e = &c->idx[ kind ][ k%FD_GUI_CHUNK_IDX_CNT ];
      c->late_cnt += (ulong)( e->chunk==k );
    }
  }
}
