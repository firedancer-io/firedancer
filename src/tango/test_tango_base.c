#include "fd_tango.h"

FD_STATIC_ASSERT( FD_CHUNK_LG_SZ    ==6,                     unit_test );
FD_STATIC_ASSERT( FD_CHUNK_ALIGN    ==(1UL<<FD_CHUNK_LG_SZ), unit_test );
FD_STATIC_ASSERT( FD_CHUNK_FOOTPRINT==FD_CHUNK_ALIGN,        unit_test );
FD_STATIC_ASSERT( FD_CHUNK_SZ       ==FD_CHUNK_FOOTPRINT,    unit_test );

FD_STATIC_ASSERT( FD_FRAG_META_LG_SZ     ==5,                         unit_test );
FD_STATIC_ASSERT( FD_FRAG_META_ALIGN     ==(1UL<<FD_FRAG_META_LG_SZ), unit_test );
FD_STATIC_ASSERT( FD_FRAG_META_FOOTPRINT ==FD_FRAG_META_ALIGN,        unit_test );
FD_STATIC_ASSERT( FD_FRAG_META_SZ        ==FD_FRAG_META_FOOTPRINT,    unit_test );
FD_STATIC_ASSERT( alignof(fd_frag_meta_t)==FD_FRAG_META_ALIGN,        unit_test );
FD_STATIC_ASSERT( sizeof (fd_frag_meta_t)==FD_FRAG_META_SZ,           unit_test );

FD_STATIC_ASSERT( FD_FRAG_META_ORIG_MAX==8192UL, unit_test );

#define CHUNK_CNT (256UL)

static uchar __attribute__((aligned(FD_CHUNK_ALIGN))) chunk_mem[ CHUNK_CNT ][ FD_CHUNK_SZ ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->seq   ))== 0UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->sig   ))== 8UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->chunk ))==16UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->sz    ))==20UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->ctl   ))==22UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->tsorig))==24UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->tspub ))==28UL );
# if FD_HAS_AVX
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->sse0  ))== 0UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->sse1  ))==16UL );
  TEST( ((ulong)&(((fd_frag_meta_t *)NULL)->avx   ))== 0UL );
# endif

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {
    ulong d     = fd_rng_ulong( rng );
    ulong delta = fd_ulong_min( fd_ulong_max( fd_rng_ulong( rng ) >> (fd_rng_uint( rng ) & 63U), 1UL ), (1UL<<63)-1UL );

    ulong a = fd_seq_dec( d,  1UL<<63      );
    ulong b = fd_seq_dec( d, delta         );
    ulong c = fd_seq_dec( d, 0UL           );
    ulong e = fd_seq_inc( d, 0UL           );
    ulong f = fd_seq_inc( d, delta         );
    ulong g = fd_seq_inc( d, (1UL<<63)-1UL );

    TEST(  fd_seq_lt( a, d ) ); TEST(  fd_seq_le( a, d ) ); TEST( !fd_seq_eq( a, d ) );
    TEST(  fd_seq_lt( b, d ) ); TEST(  fd_seq_le( b, d ) ); TEST( !fd_seq_eq( b, d ) );
    TEST( !fd_seq_lt( c, d ) ); TEST(  fd_seq_le( c, d ) ); TEST(  fd_seq_eq( c, d ) );
    TEST( !fd_seq_lt( d, d ) ); TEST(  fd_seq_le( d, d ) ); TEST(  fd_seq_eq( d, d ) );
    TEST( !fd_seq_lt( e, d ) ); TEST(  fd_seq_le( e, d ) ); TEST(  fd_seq_eq( e, d ) );
    TEST( !fd_seq_lt( f, d ) ); TEST( !fd_seq_le( f, d ) ); TEST( !fd_seq_eq( f, d ) );
    TEST( !fd_seq_lt( g, d ) ); TEST( !fd_seq_le( g, d ) ); TEST( !fd_seq_eq( g, d ) );

    TEST(  fd_seq_ne( a, d ) ); TEST( !fd_seq_ge( a, d ) ); TEST( !fd_seq_gt( a, d ) );
    TEST(  fd_seq_ne( b, d ) ); TEST( !fd_seq_ge( b, d ) ); TEST( !fd_seq_gt( b, d ) );
    TEST( !fd_seq_ne( c, d ) ); TEST(  fd_seq_ge( c, d ) ); TEST( !fd_seq_gt( c, d ) );
    TEST( !fd_seq_ne( d, d ) ); TEST(  fd_seq_ge( d, d ) ); TEST( !fd_seq_gt( d, d ) );
    TEST( !fd_seq_ne( e, d ) ); TEST(  fd_seq_ge( e, d ) ); TEST( !fd_seq_gt( e, d ) );
    TEST(  fd_seq_ne( f, d ) ); TEST(  fd_seq_ge( f, d ) ); TEST(  fd_seq_gt( f, d ) );
    TEST(  fd_seq_ne( g, d ) ); TEST(  fd_seq_ge( g, d ) ); TEST(  fd_seq_gt( g, d ) );

    TEST( fd_seq_diff( a, d )==LONG_MIN     );
    TEST( fd_seq_diff( b, d )==-(long)delta );
    TEST( fd_seq_diff( c, d )==0L           );
    TEST( fd_seq_diff( d, d )==0L           );
    TEST( fd_seq_diff( e, d )==0L           );
    TEST( fd_seq_diff( f, d )== (long)delta );
    TEST( fd_seq_diff( g, d )==LONG_MAX     );

    ulong chunk_idx = d & (CHUNK_CNT-1UL);
    uchar * chunk = fd_chunk_to_laddr( chunk_mem[0], chunk_idx );
    TEST( chunk==chunk_mem[ chunk_idx ] );
    TEST( fd_laddr_to_chunk( chunk_mem[0], chunk )==chunk_idx );

    ulong ctl = d & (65535UL);
    int   mul = (int)fd_rng_uint( rng ); if( !mul ) mul = 1;

    ulong orig = fd_frag_meta_ctl_orig( ctl );
    int   som  = fd_frag_meta_ctl_som ( ctl )*mul;
    int   eom  = fd_frag_meta_ctl_eom ( ctl )*mul;
    int   err  = fd_frag_meta_ctl_err ( ctl )*mul;

    TEST( fd_frag_meta_ctl( orig, som, eom, err )==ctl );
  }

# if FD_HAS_AVX
  for( ulong iter=0UL; iter<100000000UL; iter++ ) {
    ulong seq = fd_rng_ulong( rng );
    ulong sig = fd_rng_ulong( rng );
    __m128i sse0 = fd_frag_meta_sse0( seq, sig );
    TEST( fd_frag_meta_sse0_seq( sse0 )==seq );
    TEST( fd_frag_meta_sse0_sig( sse0 )==sig );

    ulong chunk  = (ulong)fd_rng_uint  ( rng );
    ulong sz     = (ulong)fd_rng_ushort( rng );
    ulong ctl    = (ulong)fd_rng_ushort( rng );
    ulong tsorig = (ulong)fd_rng_uint  ( rng );
    ulong tspub  = (ulong)fd_rng_uint  ( rng );
    __m128i sse1 = fd_frag_meta_sse1( chunk, sz, ctl, tsorig, tspub );
    TEST( fd_frag_meta_sse1_chunk ( sse1 )==chunk  );
    TEST( fd_frag_meta_sse1_sz    ( sse1 )==sz     );
    TEST( fd_frag_meta_sse1_ctl   ( sse1 )==ctl    );
    TEST( fd_frag_meta_sse1_tsorig( sse1 )==tsorig );
    TEST( fd_frag_meta_sse1_tspub ( sse1 )==tspub  );

    __m256i avx = fd_frag_meta_avx( seq, sig, chunk, sz, ctl, tsorig, tspub );
    TEST( fd_frag_meta_avx_seq   ( avx )==seq    );
    TEST( fd_frag_meta_avx_sig   ( avx )==sig    );
    TEST( fd_frag_meta_avx_chunk ( avx )==chunk  );
    TEST( fd_frag_meta_avx_sz    ( avx )==sz     );
    TEST( fd_frag_meta_avx_ctl   ( avx )==ctl    );
    TEST( fd_frag_meta_avx_tsorig( avx )==tsorig );
    TEST( fd_frag_meta_avx_tspub ( avx )==tspub  );

    fd_frag_meta_t meta[1];

    memset( meta, 0, sizeof(fd_frag_meta_t) );
    _mm_store_si128( &meta->sse0, sse0 );
    _mm_store_si128( &meta->sse1, sse1 );
    TEST(        meta->seq   ==seq    );
    TEST(        meta->sig   ==sig    );
    TEST( (ulong)meta->chunk ==chunk  );
    TEST( (ulong)meta->sz    ==sz     );
    TEST( (ulong)meta->ctl   ==ctl    );
    TEST( (ulong)meta->tsorig==tsorig );
    TEST( (ulong)meta->tspub ==tspub  );

    memset( meta, 0, sizeof(fd_frag_meta_t) );
    _mm256_store_si256( &meta->avx, avx );
    TEST(        meta->seq   ==seq    );
    TEST(        meta->sig   ==sig    );
    TEST( (ulong)meta->chunk ==chunk  );
    TEST( (ulong)meta->sz    ==sz     );
    TEST( (ulong)meta->ctl   ==ctl    );
    TEST( (ulong)meta->tsorig==tsorig );
    TEST( (ulong)meta->tspub ==tspub  );
  }
# endif

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {
    uint r     = fd_rng_uint( rng );
    int  sign  = (int)(r &  1U); r>>=1;
    int  extr  = (int)(r &  1U); r>>=1;
    int  shift = (int)(r & 31U); r>>=5;

    long tsref = (long)fd_rng_ulong( rng );
    long delta = (long)( (extr ? UINT_MAX : fd_rng_uint( rng )) >> shift);
    delta >>= 1;
    if( sign ) delta = -delta;
    long ts    = tsref + delta;

    ulong tscomp = fd_frag_meta_ts_comp( ts );
    TEST( tscomp <= (ulong)UINT_MAX );
    TEST( fd_frag_meta_ts_decomp( tscomp, tsref )==ts );

    ulong async_min = 1UL << shift;
    ulong async_rem = fd_async_reload( rng, async_min );
    TEST( async_min<=async_rem     );
    TEST( async_rem< 2UL*async_min );
  }

# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

