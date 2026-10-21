#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_hpack.h"
#include "../../util/fd_util.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */
  return 0;
}

/* fuzz_hpack_dtable_check verifies the dynamic table invariants and
   that every live entry is readable via its HPACK index. */

static void
fuzz_hpack_dtable_check( fd_hpack_dtable_t const * dtable ) {
  assert( dtable->limit_sz  <= FD_HPACK_DTABLE_SZ_MAX    );
  assert( dtable->max_sz    <= dtable->limit_sz          );
  assert( dtable->used_sz   <= dtable->max_sz            );
  assert( dtable->entry_cnt <= FD_HPACK_DTABLE_ENTRY_MAX );

  ulong used_sz = 0UL;
  for( ulong i=1UL; i<=dtable->entry_cnt; i++ ) {
    uchar   buf[ FD_HPACK_DTABLE_SZ_MAX ];
    uchar * bufp = buf;
    fd_h2_hdr_t hdr[1];
    assert( fd_hpack_dtable_query( dtable, 61UL+i, hdr, &bufp, buf+sizeof(buf) )==FD_H2_SUCCESS );
    assert( bufp==buf+hdr->name_len+hdr->value_len );
    used_sz += (ulong)hdr->name_len + hdr->value_len + 32UL;
  }
  assert( used_sz==dtable->used_sz );

  /* One past the last entry is out of bounds */
  uchar   buf[ 64 ];
  uchar * bufp = buf;
  fd_h2_hdr_t hdr[1];
  assert( fd_hpack_dtable_query( dtable, 62UL+dtable->entry_cnt, hdr, &bufp, buf+sizeof(buf) )!=FD_H2_SUCCESS );
}

/* fuzz_hpack_rd_block decodes one field block. */

static void
fuzz_hpack_rd_block( fd_hpack_dtable_t * dtable,
                     uchar const *       data,
                     ulong               size ) {
  fd_hpack_rd_t rd[1];
  if( FD_UNLIKELY( !fd_hpack_rd_init_dtable( rd, data, size, dtable ) ) ) return;
  uchar const * prev = data;
  while( !fd_hpack_rd_done( rd ) ) {
    fd_h2_hdr_t hdr[1];
    uchar buf[ 2*FD_HPACK_DTABLE_SZ_MAX ];
    uchar * bufp = buf;
    if( FD_UNLIKELY( fd_hpack_rd_next( rd, hdr, &bufp, buf+sizeof(buf) )!=FD_H2_SUCCESS ) ) break;
    /* FIXME validate content of hdr */
    assert( rd->src > prev ); /* must advance */
    assert( bufp>=buf && bufp<=buf+sizeof(buf) );
    prev = rd->src;
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  static ulong const limits[] = { 0UL, 1UL, 32UL, 57UL, 256UL, FD_HPACK_DTABLE_SZ_MAX };

  if( FD_UNLIKELY( !size ) ) return -1;
  ulong limit_sz = limits[ data[0] % (sizeof(limits)/sizeof(limits[0])) ];
  data++; size--;

  /* The dynamic table is connection state: feed the input as a series
     of field blocks that share one table. */
  fd_hpack_dtable_t dtable[1];
  assert( fd_hpack_dtable_init( dtable, limit_sz )==dtable );

  while( size ) {
    ulong block_sz = fd_ulong_min( data[0], size-1UL );
    data++; size--;
    fuzz_hpack_rd_block( dtable, data, block_sz );
    fuzz_hpack_dtable_check( dtable );
    data += block_sz; size -= block_sz;
  }

  return 0;
}
