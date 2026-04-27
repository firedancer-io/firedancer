#include "../fd_util.h"
#include "fd_nt_memcpy.h"

#define BIG_SZ 8388608UL
uchar __attribute__((aligned(64))) big_src[BIG_SZ];
uchar __attribute__((aligned(64))) big_dst[BIG_SZ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  do {
    /* First, test correctness */
    for( ulong fn=0UL; fn<4UL; fn++ ) {
      uchar __attribute__((aligned(64))) _src[1024+64];
      uchar __attribute__((aligned(64))) _dst[1024+64];

      for( ulong misalign=0UL; misalign<64UL; misalign++ ) {
        for( ulong sz=0UL; sz<=1024UL; sz++ ) {
          fd_memset( _dst, '\xcc', 1024UL+64UL );
          uchar * dst = _dst+misalign;
          uchar * src = _src+(64UL-misalign);
          src[sz-1] = (uchar)sz;
          switch( fn ) {
            case 0UL: FD_TEST( dst==fd_memcpy_nn( dst, src, sz ) ); break;
            case 1UL: FD_TEST( dst==fd_memcpy_nt( dst, src, sz ) ); break;
            case 2UL: FD_TEST( dst==fd_memcpy_tn( dst, src, sz ) ); break;
            case 3UL: FD_TEST( dst==fd_memcpy_tt( dst, src, sz ) ); break;
          }
          FD_TEST( fd_memeq( dst, src, sz ) );
          for( ulong j=0UL; j<misalign;             j++ ) FD_TEST( 0xcc==_dst[j] );
          for( ulong j=sz;  j<1024UL+64UL-misalign; j++ ) FD_TEST( 0xcc==dst[j] );
        }
      }
    }


    ulong target[2048];
    /* Target is used for pointer-chasing just to test what level of
       cache it is in. target[x]=x * 847 (mod 2039). */
    for( ulong i=0UL; i<2048UL; i++ ) target[i] = (i * 847UL)%2039UL;
    long post_timing[ 4 ] = { 0L };
    long copy_timing[ 4 ] = { 0L };
    long pre = 0L;

    #pragma GCC unroll 4
    for( ulong fn=0UL; fn<4UL; fn++ ) {
      ulong dummy = 0UL;
      ulong j;
      long nt = 0L, post = 0L;
      for( ulong i=0UL; i<1024UL; i++ ) {
        dummy += fd_hash( i,     target, 2048UL*sizeof(ulong) );
        pre -= fd_tickcount();
        j=1UL; while( target[j]!=1UL ) j=target[j];
        dummy += j;
        pre += fd_tickcount();
        FD_COMPILER_FORGET( dummy );

        nt -= fd_tickcount();
        FD_COMPILER_UNPREDICTABLE( big_src );
        switch( fn ) {
          case 0UL: fd_memcpy_nn( big_dst, big_src, BIG_SZ ); break;
          case 1UL: fd_memcpy_nt( big_dst, big_src, BIG_SZ ); break;
          case 2UL: fd_memcpy_tn( big_dst, big_src, BIG_SZ ); break;
          case 3UL: fd_memcpy_tt( big_dst, big_src, BIG_SZ ); break;
        }
        FD_COMPILER_UNPREDICTABLE( big_dst );
        nt += fd_tickcount();

        post -= fd_tickcount();
        j=1UL; while( target[j]!=1UL ) j=target[j];
        dummy += j;
        post += fd_tickcount();
      }
      post_timing[fn] = post;
      copy_timing[fn] = nt;
    }

    FD_LOG_NOTICE(( "test op cycles when everything is in L1 cache:\t%li", pre/(1024L*4L) ));
    FD_LOG_NOTICE(( "copy type\tB/cyc\t\ttest op cycles" ));
    char const fnames[12] = "nn\0nt\0tn\0tt";
    for( ulong fn=0UL; fn<4UL; fn++ ) {
      /* GiB/s would be nice, but we don't want to depend on tempo */
      FD_LOG_NOTICE(( "%s\t\t%f\t\t%li", fnames+3*fn, (double)(BIG_SZ*1024UL)/(double)copy_timing[fn], post_timing[fn]/1024L ));
    }
  } while(0);

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
