#include "../fd_vinyl.h"
#include <stddef.h>

FD_STATIC_ASSERT( FD_VINYL_BSTREAM_BLOCK_SZ==512UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_BLOCK_LG_SZ==9,  unit_test );

FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_TYPE_PAIR==(int)0x9a17, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_TYPE_SYNC==(int)0x512c, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_TYPE_DEAD==(int)0xdead, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_TYPE_MOVE==(int)0x30c3, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_TYPE_PART==(int)0xd121, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_TYPE_ZPAD==0,           unit_test );

FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_STYLE_RAW==(int)0x7a3, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_CTL_STYLE_LZ4==(int)0x124, unit_test );

FD_STATIC_ASSERT( alignof(fd_vinyl_bstream_phdr_t)==8UL,                                                unit_test );
FD_STATIC_ASSERT( sizeof( fd_vinyl_bstream_phdr_t)==8UL+sizeof(fd_vinyl_key_t)+sizeof(fd_vinyl_info_t), unit_test );

FD_STATIC_ASSERT( FD_VINYL_BSTREAM_FTR_SZ==16UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_BSTREAM_LZ4_VAL_THRESH==440UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_BSTREAM_SYNC_INFO_MAX==464UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_DEAD_INFO_MAX==416UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_MOVE_INFO_MAX==384UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_BSTREAM_PART_INFO_MAX==448UL, unit_test );

FD_STATIC_ASSERT( alignof(fd_vinyl_bstream_block_t)==512UL, unit_test );
FD_STATIC_ASSERT( sizeof (fd_vinyl_bstream_block_t)==512UL, unit_test );

FD_STATIC_ASSERT( offsetof( fd_vinyl_bstream_block_t, ftr .hash_trail )==496UL, unit_test );
FD_STATIC_ASSERT( offsetof( fd_vinyl_bstream_block_t, sync.hash_trail )==496UL, unit_test );
FD_STATIC_ASSERT( offsetof( fd_vinyl_bstream_block_t, dead.hash_trail )==496UL, unit_test );
FD_STATIC_ASSERT( offsetof( fd_vinyl_bstream_block_t, move.hash_trail )==496UL, unit_test );
FD_STATIC_ASSERT( offsetof( fd_vinyl_bstream_block_t, part.hash_trail )==496UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  for( ulong rem=1000000UL; rem; rem-- ) {

    ulong r = fd_rng_ulong( rng );
    ulong s = fd_rng_ulong( rng );

    /* Test sequence comparison */

    long  d = (long)(r-s);
    FD_TEST( fd_vinyl_seq_lt( r, s )==(d< 0L) ); FD_TEST( fd_vinyl_seq_lt( r, r )==0 ); FD_TEST( fd_vinyl_seq_lt( s, s )==0 );
    FD_TEST( fd_vinyl_seq_gt( r, s )==(d> 0L) ); FD_TEST( fd_vinyl_seq_gt( r, r )==0 ); FD_TEST( fd_vinyl_seq_gt( s, s )==0 );
    FD_TEST( fd_vinyl_seq_le( r, s )==(d<=0L) ); FD_TEST( fd_vinyl_seq_le( r, r )==1 ); FD_TEST( fd_vinyl_seq_le( s, s )==1 );
    FD_TEST( fd_vinyl_seq_ge( r, s )==(d>=0L) ); FD_TEST( fd_vinyl_seq_ge( r, r )==1 ); FD_TEST( fd_vinyl_seq_ge( s, s )==1 );
    FD_TEST( fd_vinyl_seq_eq( r, s )==(d==0L) ); FD_TEST( fd_vinyl_seq_eq( r, r )==1 ); FD_TEST( fd_vinyl_seq_eq( s, s )==1 );
    FD_TEST( fd_vinyl_seq_ne( r, s )==(d!=0L) ); FD_TEST( fd_vinyl_seq_ne( r, r )==0 ); FD_TEST( fd_vinyl_seq_ne( s, s )==0 );

    /* Test ctl encoding decoding */

    int   type  = fd_vinyl_bstream_ctl_type ( r ); FD_TEST( (0<=type ) & (type <65536) );
    int   style = fd_vinyl_bstream_ctl_style( r ); FD_TEST( (0<=style) & (style< 4096) );
    ulong sz    = fd_vinyl_bstream_ctl_sz   ( r ); FD_TEST( sz<(1UL<<36)               );

    FD_TEST( fd_vinyl_bstream_ctl( type, style, sz )==r );

    /* Test pair_sz */

    ulong pair_sz = fd_vinyl_bstream_pair_sz( (r>>16) );
    FD_TEST( pair_sz==fd_ulong_align_up( sizeof(fd_vinyl_bstream_phdr_t) + (r>>16) + FD_VINYL_BSTREAM_FTR_SZ,
                                         FD_VINYL_BSTREAM_BLOCK_SZ ) );

    r |= 1UL; /* guarantee non-zero r */

    /* Single block hash tests */

    fd_vinyl_bstream_block_t hdr[1];
    ulong * buf = (ulong *)hdr->data;
    ulong   cnt = FD_VINYL_BSTREAM_BLOCK_SZ / sizeof(ulong);
    for( ulong idx=0UL; idx<cnt; idx++ ) buf[idx] = r;

    hdr->ftr.hash_trail  = 0UL;
    hdr->ftr.hash_blocks = 0UL;
    ulong hash_blocks = fd_vinyl_bstream_hash( s, hdr, FD_VINYL_BSTREAM_BLOCK_SZ );

    fd_vinyl_bstream_block_hash( s, hdr );
    FD_TEST( hdr->ftr.hash_trail ==s           );
    FD_TEST( hdr->ftr.hash_blocks==hash_blocks );

    FD_TEST( !fd_vinyl_bstream_block_test( s, hdr ) );

    hdr->ftr.hash_trail  = r ^ 1UL;
    hdr->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_block_test( s, hdr )==FD_VINYL_ERR_CORRUPT );

    hdr->ftr.hash_trail  = r;
    hdr->ftr.hash_blocks = hash_blocks ^ 1UL;
    FD_TEST( fd_vinyl_bstream_block_test( s, hdr )==FD_VINYL_ERR_CORRUPT );

    /* Pair tests */

#   define BUF_SZ  (3UL*FD_VINYL_BSTREAM_BLOCK_SZ)
#   define VAL_MAX (BUF_SZ - sizeof(fd_vinyl_bstream_phdr_t) - FD_VINYL_BSTREAM_FTR_SZ)

    union {
      fd_vinyl_bstream_block_t block[ BUF_SZ / FD_VINYL_BSTREAM_BLOCK_SZ ];
      fd_vinyl_bstream_phdr_t  phdr;
      uchar                    buf[ BUF_SZ ];
    } cache;

    ulong val_sz  = r % (VAL_MAX+1UL);
    /**/  pair_sz = fd_vinyl_bstream_pair_sz( val_sz );

    ulong phdr_ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );

    cache.phdr.ctl = phdr_ctl;
    memset( &cache.phdr.key,                             (int)((r>> 8) & 255UL), FD_VINYL_KEY_FOOTPRINT );
    memset( &cache.phdr.info,                            (int)((r>>16) & 255UL), FD_VINYL_INFO_SZ       );
    memset( cache.buf + sizeof(fd_vinyl_bstream_phdr_t), (int)((r>>24) & 255UL), val_sz                 );
    cache.phdr.info._val_sz = (uint)val_sz;

    fd_vinyl_bstream_pair_hash( s, cache.block );

    fd_vinyl_bstream_block_t * end = (fd_vinyl_bstream_block_t *)(cache.buf + pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ);
    ulong hash_trail  = end->ftr.hash_trail;
    /**/  hash_blocks = end->ftr.hash_blocks;

    /* Slow tests */

    /* NULL buf */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, NULL, pair_sz ) );

    /* Too small buf */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, cache.block, FD_VINYL_BSTREAM_BLOCK_SZ-1UL ) );

    /* Bad type (and bad hash but type will hit first) */
    cache.phdr.ctl       = fd_vinyl_bstream_ctl( 0, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, cache.block, pair_sz ) );
    cache.phdr.ctl       = phdr_ctl;

    /* Bad val_sz (and bad hash but val_sz will hit first) */
    cache.phdr.info._val_sz = (uint)(FD_VINYL_VAL_MAX+1UL);
    end->ftr.hash_trail    = hash_trail;
    end->ftr.hash_blocks   = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, cache.block, pair_sz ) );
    cache.phdr.info._val_sz = (uint)val_sz;

    /* Truncated */
    end->ftr.hash_trail    = hash_trail;
    end->ftr.hash_blocks   = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, cache.block, pair_sz-1UL ) );

    /* Bad trailing hash */
    end->ftr.hash_trail  = hash_trail ^ 1UL;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, cache.block, pair_sz ) );

    /* Bad end-to-end hash */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks ^ 1UL;
    FD_TEST( fd_vinyl_bstream_pair_test( s, 0UL, cache.block, pair_sz ) );

    /* Good */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( !fd_vinyl_bstream_pair_test( s, 0UL, cache.block, pair_sz ) );

    /* Fast tests */

    /* NULL hdr */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test_fast( s, 0UL, NULL, end ) );

    /* NULL ftr */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test_fast( s, 0UL, cache.block, NULL ) );

    /* Bad type (and bad hash but type will hit first) */
    cache.phdr.ctl       = fd_vinyl_bstream_ctl( 0, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test_fast( s, 0UL, cache.block, end ) );
    cache.phdr.ctl       = phdr_ctl;

    /* Bad val_sz (and bad hash but val_sz will hit first) */
    cache.phdr.info._val_sz = (uint)(FD_VINYL_VAL_MAX+1UL);
    end->ftr.hash_trail    = hash_trail;
    end->ftr.hash_blocks   = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test_fast( s, 0UL, cache.block, end ) );
    cache.phdr.info._val_sz = (uint)val_sz;

    /* Bad trailing hash (fast will detect as leading blocks not matched to trailing blocks) */
    end->ftr.hash_trail  = hash_trail ^ 1UL;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( fd_vinyl_bstream_pair_test_fast( s, 0UL, cache.block, end ) );

    /* Bad end-to-end hash */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks ^ 1UL;
    FD_TEST( fd_vinyl_bstream_pair_test_fast( s, 0UL, cache.block, end ) );

    /* Good */
    end->ftr.hash_trail  = hash_trail;
    end->ftr.hash_blocks = hash_blocks;
    FD_TEST( !fd_vinyl_bstream_pair_test_fast( s, 0UL, cache.block, end ) );

    /* FIXME: add coverage for dead / move / part tests */

    /* Zero pad tests */

    FD_TEST( fd_vinyl_bstream_zpad_test( s, 0UL, hdr ) );

    memset( hdr, 0, FD_VINYL_BSTREAM_BLOCK_SZ );

    FD_TEST( !fd_vinyl_bstream_zpad_test( s, 0UL, hdr ) );

  }

  FD_LOG_NOTICE(( "style_cstr( -1  ): %s", fd_vinyl_bstream_ctl_style_cstr( -1                             ) ));
  FD_LOG_NOTICE(( "style_cstr( RAW ): %s", fd_vinyl_bstream_ctl_style_cstr( FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ));
  FD_LOG_NOTICE(( "style_cstr( LZ4 ): %s", fd_vinyl_bstream_ctl_style_cstr( FD_VINYL_BSTREAM_CTL_STYLE_LZ4 ) ));

  FD_TEST( fd_cstr_to_vinyl_bstream_ctl_style( NULL  )==-1                             );
  FD_TEST( fd_cstr_to_vinyl_bstream_ctl_style( "foo" )==-1                             );
  FD_TEST( fd_cstr_to_vinyl_bstream_ctl_style( "raw" )==FD_VINYL_BSTREAM_CTL_STYLE_RAW );
  FD_TEST( fd_cstr_to_vinyl_bstream_ctl_style( "lz4" )==FD_VINYL_BSTREAM_CTL_STYLE_LZ4 );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
