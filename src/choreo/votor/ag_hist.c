#include "ag_hist.h"

/* rec_sz is the wire size of a record with these flags */

FD_FN_CONST static inline ulong
rec_sz( uchar flags ) {
  return AG_HIST_REC_MIN_SZ + fd_ulong_if( flags & AG_HIST_FLAG_VOTED_NOTAR, sizeof(ag_block_hash_t), 0UL );
}

/* hist_ok is the one place the rules live, so ag_hist_ser refuses to
   emit anything ag_hist_de would refuse to read */

static int
hist_ok( ag_hist_t const * hist ) {
  if( FD_UNLIKELY( hist->rec_cnt>AG_HIST_MAX ) ) return 0;
  if( FD_UNLIKELY( hist->anchor==ULONG_MAX   ) ) return 0;
  ulong first = ag_hist_first_slot( hist->anchor );
  ulong prev  = ULONG_MAX;
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    ag_hist_rec_t const * rec = &hist->rec[ i ];
    if( FD_UNLIKELY( rec->slot<first                      ) ) return 0;
    if( FD_UNLIKELY( i && rec->slot<=prev                 ) ) return 0;
    if( FD_UNLIKELY( rec->flags & ~AG_HIST_FLAG_MASK      ) ) return 0;
    if( FD_UNLIKELY( !( rec->flags & AG_HIST_FLAG_VOTED ) ) ) return 0;
    prev = rec->slot;
  }
  return 1;
}

int
ag_hist_ser( ag_hist_t const * hist,
             uchar *           buf,
             ulong             buf_max,
             ulong *           out_sz ) {
  if( FD_UNLIKELY( !hist_ok( hist ) ) ) return -1;

  ulong sz = AG_HIST_HDR_SZ;
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) sz += rec_sz( hist->rec[ i ].flags );
  if( FD_UNLIKELY( sz>buf_max ) ) return -1;

  ulong off = 0UL;
  FD_STORE( ulong,  buf+off, hist->anchor           ); off += sizeof(ulong);
  FD_STORE( ulong,  buf+off, hist->last_leader_slot ); off += sizeof(ulong);
  FD_STORE( ushort, buf+off, (ushort)hist->rec_cnt  ); off += sizeof(ushort);
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    ag_hist_rec_t const * rec = &hist->rec[ i ];
    FD_STORE( ulong, buf+off, rec->slot ); off += sizeof(ulong);
    buf[ off ] = rec->flags;               off += sizeof(uchar);
    if( rec->flags & AG_HIST_FLAG_VOTED_NOTAR ) { fd_memcpy( buf+off, rec->notar_hash, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t); }
  }

  *out_sz = off;
  return 0;
}

int
ag_hist_de( uchar const * buf,
            ulong         buf_sz,
            ag_hist_t *   out ) {
  if( FD_UNLIKELY( buf_sz<AG_HIST_HDR_SZ ) ) return -1;

  ag_hist_t hist[1];
  fd_memset( hist, 0, sizeof(ag_hist_t) );

  ulong off = 0UL;
  hist->anchor           = FD_LOAD( ulong,  buf+off ); off += sizeof(ulong);
  hist->last_leader_slot = FD_LOAD( ulong,  buf+off ); off += sizeof(ulong);
  hist->rec_cnt          = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);
  if( FD_UNLIKELY( hist->rec_cnt>AG_HIST_MAX ) ) return -1;

  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    ag_hist_rec_t * rec = &hist->rec[ i ];
    if( FD_UNLIKELY( buf_sz-off<AG_HIST_REC_MIN_SZ ) ) return -1;
    rec->slot  = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
    rec->flags = buf[ off ];                off += sizeof(uchar);
    if( rec->flags & AG_HIST_FLAG_VOTED_NOTAR ) {
      if( FD_UNLIKELY( buf_sz-off<sizeof(ag_block_hash_t) ) ) return -1;
      fd_memcpy( rec->notar_hash, buf+off, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t);
    }
  }
  if( FD_UNLIKELY( off!=buf_sz      ) ) return -1; /* trailing bytes */
  if( FD_UNLIKELY( !hist_ok( hist ) ) ) return -1;

  *out = *hist;
  return 0;
}
