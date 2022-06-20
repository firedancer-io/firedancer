#include "../fd_util.h"

#define SMAX  (16384UL)
#define DEPTH (16UL)

#if !FD_HAS_ALLOCA
static FD_TLS uchar smem[ SMAX  ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
static FD_TLS ulong fmem[ DEPTH ];
#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# if FD_HAS_ALLOCA
  uchar * smem = fd_alloca( fd_scratch_smem_align(), fd_scratch_smem_footprint( SMAX  ) );
  ulong * fmem = fd_alloca( fd_scratch_fmem_align(), fd_scratch_fmem_footprint( DEPTH ) );
  TEST( smem ); TEST( fd_ulong_is_aligned( (ulong)smem, FD_SCRATCH_SMEM_ALIGN ) );
  TEST( fmem ); TEST( fd_ulong_is_aligned( (ulong)fmem, FD_SCRATCH_FMEM_ALIGN ) );
# endif

  TEST( fd_ulong_is_pow2( FD_SCRATCH_ALIGN_MIN     )     );
  TEST( fd_ulong_is_pow2( FD_SCRATCH_ALIGN_DEFAULT )     );
  TEST( FD_SCRATCH_ALIGN_DEFAULT >= FD_SCRATCH_ALIGN_MIN );

  TEST( fd_scratch_smem_align()==(ulong)FD_SCRATCH_SMEM_ALIGN );
  TEST( fd_ulong_is_pow2( fd_scratch_smem_align() ) );

  for( ulong smax=1UL; smax<=SMAX; smax++ )
    TEST( fd_scratch_smem_footprint( smax )==fd_ulong_align_up( smax, fd_scratch_smem_align() ) );

  TEST( fd_scratch_fmem_align()==(ulong)FD_SCRATCH_FMEM_ALIGN );
  TEST( fd_scratch_fmem_align()==sizeof(ulong)                );
  TEST( fd_ulong_is_pow2( fd_scratch_fmem_align() )           );

  for( ulong depth=1UL; depth<=DEPTH; depth++ ) TEST( fd_scratch_fmem_footprint( depth )==sizeof(ulong)*depth );

  TEST( !fd_scratch_used()       );
  TEST( !fd_scratch_free()       );
  TEST( !fd_scratch_frame_used() );
  TEST( !fd_scratch_frame_free() );

  fd_scratch_attach( smem, fmem, SMAX, DEPTH );

  TEST( !fd_scratch_used()      );
  TEST( fd_scratch_free()==SMAX );

  TEST( !fd_scratch_frame_used()       );
  TEST( fd_scratch_frame_free()==DEPTH );

  for( ulong i=0UL; i<DEPTH; i++ ) {
    TEST( fd_scratch_frame_used()==i         );
    TEST( fd_scratch_frame_free()==(DEPTH-i) );
    fd_scratch_push();
  }

  for( ulong i=0UL; i<DEPTH; i++ ) {
    TEST( fd_scratch_frame_used()==(DEPTH-i) );
    TEST( fd_scratch_frame_free()==i         );
    fd_scratch_pop();
  }

  TEST( !fd_scratch_frame_used()       );
  TEST( fd_scratch_frame_free()==DEPTH );

  void * mem;

  fd_scratch_push();

  /* sz==0 behavior */
  for( ulong align=4096UL; align; align>>=1 ) {
    mem = fd_scratch_alloc( align, 0UL );
    TEST( mem && fd_ulong_is_aligned( (ulong)mem, fd_ulong_max( FD_SCRATCH_ALIGN_MIN, align ) ) );
  }
  mem = fd_scratch_alloc( 0UL, 0UL );
  TEST( mem && fd_ulong_is_aligned( (ulong)mem, FD_SCRATCH_ALIGN_DEFAULT ) );

  /* non-multiple size behavior */
  for( ulong align=4096UL; align; align>>=1 ) {
    mem = fd_scratch_alloc( align, 1UL );
    TEST( mem && fd_ulong_is_aligned( (ulong)mem, fd_ulong_max( FD_SCRATCH_ALIGN_MIN, align ) ) );
  }
  mem = fd_scratch_alloc( 0UL, 1UL );
  TEST( mem && fd_ulong_is_aligned( (ulong)mem, FD_SCRATCH_ALIGN_DEFAULT ) );

  fd_scratch_pop();

  ulong m0   [ 1024UL ];
  ulong m1   [ 1024UL ]; ulong alloc_cnt = 0UL;
  ulong frame[ DEPTH  ]; ulong frame_cnt = 0UL;

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong bits = (ulong)fd_rng_uint(rng);

    int do_reset = (!(bits & 4095UL)); bits >>= 12;
    if( do_reset ) {
      fd_scratch_reset();
      alloc_cnt = 0UL;
      frame_cnt = 0UL;
      continue;
    }

    TEST( fd_scratch_push_is_safe()==(!!fd_scratch_frame_free()) );
    int do_push = (!(bits & 63UL)) & fd_scratch_push_is_safe(); bits >>= 6;
    if( do_push ) {
      frame[ frame_cnt++ ] = alloc_cnt;
      fd_scratch_push();
      continue;
    }

    TEST( fd_scratch_pop_is_safe()==(!!fd_scratch_frame_used()) );
    int do_pop = (!(bits & 63UL)) & fd_scratch_pop_is_safe(); bits >>= 6;
    if( do_pop ) {
      alloc_cnt = frame[ --frame_cnt ];
      fd_scratch_pop();
      continue;
    }

    /* default is to do an alloc */

    int lg_align = fd_rng_int_roll( rng, 10 )-1; /* lg_align is in [-1,8], 0 means use default */

    ulong align  = fd_ulong_if( lg_align<0, 0UL, 1UL<<lg_align );
    ulong sz     = (ulong)fd_rng_uint( rng ) & 255U;
    if( !( (alloc_cnt<1024UL) & fd_scratch_alloc_is_safe( align, sz ) ) ) continue;
    
    mem = fd_scratch_alloc( align, sz );
    ulong a = fd_ulong_max( fd_ulong_if( !align, FD_SCRATCH_ALIGN_DEFAULT, align ), FD_SCRATCH_ALIGN_MIN );
    TEST( mem && fd_ulong_is_aligned( (ulong)mem, a ) );

    ulong new_m0 = (ulong)mem;
    ulong new_m1 = new_m0 + sz;
    for( ulong idx=0UL; idx<alloc_cnt; idx++ ) {
      TEST( (fd_scratch_private_start<=new_m0) & (new_m0<=new_m1) & (new_m1<=fd_scratch_private_stop) );
      TEST( (m1[idx]<=new_m0) | (new_m1<=m0[idx]) );
    }

    m0[ alloc_cnt ] = new_m0;
    m1[ alloc_cnt ] = new_m1;
    alloc_cnt++;
  }

  void * _fmem;
  TEST( fd_scratch_detach( &_fmem )==smem );
  TEST( _fmem==(void *)fmem );

  TEST( !fd_scratch_used()       );
  TEST( !fd_scratch_free()       );
  TEST( !fd_scratch_frame_used() );
  TEST( !fd_scratch_frame_free() );

  fd_rng_delete( fd_rng_leave( rng ) );

# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

