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

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# if FD_HAS_ALLOCA
  uchar * smem = fd_alloca      ( FD_SCRATCH_SMEM_ALIGN, fd_scratch_smem_footprint( SMAX  ) );
  ulong * fmem = fd_alloca_check( FD_SCRATCH_FMEM_ALIGN, fd_scratch_fmem_footprint( DEPTH ) );
  FD_TEST( smem ); FD_TEST( fd_ulong_is_aligned( (ulong)smem, FD_SCRATCH_SMEM_ALIGN ) );
  FD_TEST( fmem ); FD_TEST( fd_ulong_is_aligned( (ulong)fmem, FD_SCRATCH_FMEM_ALIGN ) );
# endif

  FD_TEST( fd_ulong_is_pow2( FD_SCRATCH_ALIGN_DEFAULT ) );
  FD_TEST( FD_SCRATCH_ALIGN_DEFAULT >= 16UL             );

  FD_TEST( fd_scratch_smem_align()==(ulong)FD_SCRATCH_SMEM_ALIGN );
  FD_TEST( fd_ulong_is_pow2( fd_scratch_smem_align() ) );

  for( ulong smax=1UL; smax<=SMAX; smax++ )
    FD_TEST( fd_scratch_smem_footprint( smax )==fd_ulong_align_up( smax, fd_scratch_smem_align() ) );

  FD_TEST( fd_scratch_fmem_align()==(ulong)FD_SCRATCH_FMEM_ALIGN );
  FD_TEST( fd_scratch_fmem_align()==sizeof(ulong)                );
  FD_TEST( fd_ulong_is_pow2( fd_scratch_fmem_align() )           );

  for( ulong depth=1UL; depth<=DEPTH; depth++ ) FD_TEST( fd_scratch_fmem_footprint( depth )==sizeof(ulong)*depth );

  FD_TEST( !fd_scratch_used()       );
  FD_TEST( !fd_scratch_free()       );
  FD_TEST( !fd_scratch_frame_used() );
  FD_TEST( !fd_scratch_frame_free() );

  fd_scratch_attach( smem, fmem, SMAX, DEPTH );

  FD_TEST( !fd_scratch_used()      );
  FD_TEST( fd_scratch_free()==SMAX );

  FD_TEST( !fd_scratch_frame_used()       );
  FD_TEST( fd_scratch_frame_free()==DEPTH );

  for( ulong i=0UL; i<DEPTH; i++ ) {
    FD_TEST( fd_scratch_frame_used()==i         );
    FD_TEST( fd_scratch_frame_free()==(DEPTH-i) );
    fd_scratch_push();
  }

  for( ulong i=0UL; i<DEPTH; i++ ) {
    FD_TEST( fd_scratch_frame_used()==(DEPTH-i) );
    FD_TEST( fd_scratch_frame_free()==i         );
    fd_scratch_pop();
  }

  FD_TEST( !fd_scratch_frame_used()       );
  FD_TEST( fd_scratch_frame_free()==DEPTH );

  uchar * mem;

  fd_scratch_push();

  /* sz==0 behavior */
  for( ulong align=4096UL; align; align>>=1 ) {
    mem = (uchar *)fd_scratch_alloc( align, 0UL );
    FD_TEST( mem && fd_ulong_is_aligned( (ulong)mem, align ) );
  }
  mem = (uchar *)fd_scratch_alloc( 0UL, 0UL );
  FD_TEST( mem && fd_ulong_is_aligned( (ulong)mem, FD_SCRATCH_ALIGN_DEFAULT ) );

  /* non-multiple size behavior */
  for( ulong align=4096UL; align; align>>=1 ) {
    mem = (uchar *)fd_scratch_alloc( align, 1UL );
    FD_TEST( mem && fd_ulong_is_aligned( (ulong)mem, align ) );
  }
  mem = (uchar *)fd_scratch_alloc( 0UL, 1UL );
  FD_TEST( mem && fd_ulong_is_aligned( (ulong)mem, FD_SCRATCH_ALIGN_DEFAULT ) );

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

    FD_TEST( fd_scratch_push_is_safe()==(!!fd_scratch_frame_free()) );
    int do_push = (!(bits & 63UL)) & fd_scratch_push_is_safe(); bits >>= 6;
    if( do_push ) {
      frame[ frame_cnt++ ] = alloc_cnt;
      fd_scratch_push();
      continue;
    }

    FD_TEST( fd_scratch_pop_is_safe()==(!!fd_scratch_frame_used()) );
    int do_pop = (!(bits & 63UL)) & fd_scratch_pop_is_safe(); bits >>= 6;
    if( do_pop ) {
      alloc_cnt = frame[ --frame_cnt ];
      fd_scratch_pop();
      continue;
    }

    /* default is to do an alloc */

    int lg_align = fd_rng_int_roll( rng, 10 ); /* lg_align is in [0,9], 9 means use align==0 */

    ulong align = ((ulong)(lg_align<9)) << lg_align;
    ulong sz    = (ulong)fd_rng_uint( rng ) & 255U;
    if( !( (alloc_cnt<1024UL) & fd_scratch_alloc_is_safe( align, sz ) ) ) continue;

    if( fd_rng_uint( rng ) & 1U ) {
      mem = (uchar *)fd_scratch_alloc( align, sz );
    } else {
      mem = (uchar *)fd_scratch_prepare( align );
      if( fd_rng_uint( rng ) & 1U ) {
        fd_scratch_cancel();
        mem = (uchar *)fd_scratch_prepare( align );
      }
      fd_scratch_publish( mem + sz );
    }

    ulong a = fd_ulong_if( !align, FD_SCRATCH_ALIGN_DEFAULT, align );
    FD_TEST( mem && fd_ulong_is_aligned( (ulong)mem, a ) );

    ulong new_m0 = (ulong)mem;
    ulong new_m1 = new_m0 + sz;
    for( ulong idx=0UL; idx<alloc_cnt; idx++ ) {
      FD_TEST( (fd_scratch_private_start<=new_m0) & (new_m0<=new_m1) & (new_m1<=fd_scratch_private_stop) );
      FD_TEST( (m1[idx]<=new_m0) | (new_m1<=m0[idx]) );
    }

    sz = fd_rng_ulong_roll( rng, sz+1UL );
    fd_scratch_trim( mem + sz );

    new_m1 = new_m0 + sz;
    for( ulong idx=0UL; idx<alloc_cnt; idx++ ) {
      FD_TEST( (fd_scratch_private_start<=new_m0) & (new_m0<=new_m1) & (new_m1<=fd_scratch_private_stop) );
      FD_TEST( (m1[idx]<=new_m0) | (new_m1<=m0[idx]) );
    }

    m0[ alloc_cnt ] = new_m0;
    m1[ alloc_cnt ] = new_m1;
    alloc_cnt++;
  }

  fd_scratch_reset();
  FD_TEST( fd_scratch_frame_used()==0UL );
  for( ulong i=0; i<3UL; i++ ) {
    FD_SCRATCH_SCOPED_FRAME;
    ulong inner_cnt = fd_rng_ulong_roll( rng, 10UL );
    for( ulong j=0; j < inner_cnt; j++ ) {
      FD_SCRATCH_SCOPED_FRAME;
      FD_TEST( fd_scratch_frame_used()==2UL );
    }
    FD_TEST( fd_scratch_frame_used()==1UL );
  }
  FD_TEST( fd_scratch_frame_used()==0UL );

  void * _fmem;
  FD_TEST( fd_scratch_detach( &_fmem )==smem );
  FD_TEST( _fmem==(void *)fmem );

  FD_TEST( !fd_scratch_used()       );
  FD_TEST( !fd_scratch_free()       );
  FD_TEST( !fd_scratch_frame_used() );
  FD_TEST( !fd_scratch_frame_free() );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

