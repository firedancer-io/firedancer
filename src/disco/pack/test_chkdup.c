#define FD_UNALIGNED_ACCESS_STYLE 0
#include "fd_chkdup.h"

#define P 4294967291UL /* A prime that fits in a uint with 2 as a primitive root */

typedef int (*checker)( fd_chkdup_t *, fd_acct_addr_t const *, ulong, fd_acct_addr_t const *, ulong );


/* Populates bytes [0, sz) of mem such that no aligned 4 byte sequence
   occurs twice.  This sounds hard to do, but a trivial algorithm that
   does this would be to write 0, 1, 2, ..., UINT_MAX.  This algorithm
   produces bytes that look a bit more random.  Requires sz to be a
   multiple of 4 and sz<P*4=17,179,869,164.  Requires seed in [1, P).
   Returns a new value of seed that can be used to continue the
   sequence. */
static inline ulong
populate_unique( ulong  seed,
                 void * mem,
                 ulong  sz ) {
  FD_TEST( sz%sizeof(uint)==0UL );
  for( ulong o=0UL; o<sz; o += sizeof(uint) ) {
    FD_STORE( uint, ((uchar *)mem)+o, (uint)fd_ulong_hash( seed ) );
    seed = (seed*2208550410UL)%P;
  }
  return seed;
}


static int
test_false_positive_rate( float      expected,
                          checker    f,
                          fd_rng_t * rng,
                          ulong      l0_cnt,
                          ulong      l1_cnt ) {
  ulong const iters = 1000000UL;
  ulong false_positives = 0UL;
  fd_acct_addr_t l0[128];
  fd_acct_addr_t l1[128];

  fd_chkdup_t _mem[1];
  fd_chkdup_t * chkdup = fd_chkdup_join( fd_chkdup_new( _mem, rng ) );

  for( ulong i=0UL; i<iters; i++ ) {
    ulong base = fd_rng_uint_roll( rng, P-1UL )+1UL; /* ensure it's not 0 mod P */
    populate_unique( populate_unique( base, l0, l0_cnt*sizeof(fd_acct_addr_t) ), l1, l1_cnt*sizeof(fd_acct_addr_t) );
    ulong fp = (ulong)f( chkdup, l0, l0_cnt, l1, l1_cnt );
    if( fp && 0 ) {
      FD_LOG_NOTICE(( "%lu %lu %lu", l0_cnt, l1_cnt, i ));
      fp = (ulong)f( chkdup, l0, l0_cnt, l1, l1_cnt );
    }
    false_positives += fp;
  }
  fd_chkdup_delete( fd_chkdup_leave( chkdup ) );

  /* Is observing `false_positive` successes consistant with a binomial
     distribution with n=iters and p=expected?  The math is not too
     hard, but calculating it in C seems like a nightmare.  Instead
     we'll use the normal approximation to the binomial, since iters is
     pretty large.  We call this function about 3000 times, and we want
     a roughly p=0.001 failure rate, so that suggests we should accept
     anything within 5 standard deviations of the theoretical. */
  ulong acceptable_false_positives = (ulong)(0.49f + (float)iters*expected + 5.0f * sqrtf( (float)iters*expected*(1.0f-expected) ));

  FD_LOG_NOTICE(( "l0=%lu, l1=%lu. fp=%lu acceptable=%lu", l0_cnt, l1_cnt, false_positives, acceptable_false_positives ));
  return false_positives<=acceptable_false_positives;
}

static int
test_null( checker    f,
           fd_rng_t * rng ) {
  fd_acct_addr_t l0[128];

  fd_chkdup_t _mem[1];
  fd_chkdup_t * chkdup = fd_chkdup_join( fd_chkdup_new( _mem, rng ) );
  populate_unique( 0x12345678, l0, 128UL*sizeof(fd_acct_addr_t) );

  ulong false_positive_count = 0UL;
  for( ulong i=0UL; i<128UL; i++ ) {
    fd_acct_addr_t temp;
    fd_acct_addr_t zero = {0};
    temp = l0[i];
    l0[i] = zero;

    /* Take the 8-aligned 8 elements around i */
    false_positive_count += (ulong)f( chkdup, l0 + (i&0x78), 4UL, l0 + (i&0x78)+4UL, 4UL );
    l0[i] = temp;
  }

  /* Insert a 0 wherever i has a 1 bit */
  for( ulong i=1UL; i<256UL; i++ ) {
    populate_unique( 0x12345678, l0, 8UL*sizeof(fd_acct_addr_t) );
    fd_acct_addr_t zero = {0};
    for( ulong k=0UL; k<8UL; k++ ) {
      if( i&(1UL<<k) ) l0[ k ] = zero;
    }
    int result = f( chkdup, l0, 4UL, l0+4UL, 4UL );
    /* has at least two 0 addresses */
    if( (!fd_ulong_is_pow2( i )) & (result==0) ) return 0;
    if(   fd_ulong_is_pow2( i )  & result )      false_positive_count++;
  }
  FD_LOG_NOTICE(( "Had %lu false positives out of 136", false_positive_count ));


  fd_chkdup_delete( fd_chkdup_leave( chkdup ) );

  return 1;
}

static int
test_duplicates( checker    f,
                 fd_rng_t * rng ) {
  fd_acct_addr_t l0[128];

  fd_chkdup_t _mem[1];
  fd_chkdup_t * chkdup = fd_chkdup_join( fd_chkdup_new( _mem, rng ) );
  ulong base = fd_rng_uint_roll( rng, P-1UL )+1UL;
  populate_unique( base, l0, 128UL*sizeof(fd_acct_addr_t) );

  for( ulong i=0UL; i<128UL; i++ ) {
    for( ulong j=0UL; j<128UL; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      /* Make j the same as i */
      fd_acct_addr_t temp = l0[j];
      l0[j] = l0[i];

      /* We need i, j in [0, l0_cnt+l1_cnt), so
         l0_cnt+l1_cnt > max(i, j). */
      ulong l0_cnt = fd_rng_ulong_roll( rng, fd_ulong_max( i, j )+2UL );
      /* Given l0_cnt, then l1_cnt > max(i,j)-l0_cnt.  We also know that
         l0_cnt+l1_cnt<=128.  This implies l1_cnt in
         [max(i,j)-l0_cnt+1, 129-l0_cnt ).  In other words, we generate
         a random value in
         [0, 129-l0_cnt - (max(i,j)-l0_cnt+1) ) and add max(i,j)-l0_cnt+1.
         [0, 128-max(i,j) ) */
      ulong l1_cnt = fd_rng_ulong_roll( rng, 128UL-fd_ulong_max( i, j ) ) + fd_ulong_max( i, j )+1UL - l0_cnt;
      if( FD_UNLIKELY( 0==f( chkdup, l0, l0_cnt, l0+l0_cnt, l1_cnt ) ) ) return 0;
      l0[j] = temp;
    }
  }
  fd_chkdup_delete( fd_chkdup_leave( chkdup ) );

  return 1;
}

static ulong
performance_test( fd_rng_t * rng,
                  int        which ) {
  fd_acct_addr_t l0[32];

  fd_chkdup_t _mem[1];
  fd_chkdup_t * chkdup = fd_chkdup_join( fd_chkdup_new( _mem, rng ) );

  ulong base = fd_rng_uint_roll( rng, P-1UL )+1UL;
  populate_unique( base, l0, 32UL*sizeof(fd_acct_addr_t) );

  ulong false_positives = 0UL;

  ulong const iters = 100000UL;
  long time = -fd_log_wallclock();
  for( ulong i=0UL; i<iters; i++ ) {
    for( ulong k=0UL; k<10UL; k++ ) {
      ulong l0_cnt;
      switch( k ) {
        default:   l0_cnt =  3UL; break;
        case 7UL:  l0_cnt =  8UL; break;
        case 8UL:  l0_cnt = 13UL; break;
        case 9UL:  l0_cnt = 24UL; break;
      }
      /* I'm more optimistic about the compiler's ability to inline this
         vs. calling via a function pointer. */
      switch( which ) {
        case 0: false_positives += (ulong)fd_chkdup_check     ( chkdup, l0, l0_cnt, NULL, 0UL ); break;
        case 1: false_positives += (ulong)fd_chkdup_check_slow( chkdup, l0, l0_cnt, NULL, 0UL ); break;
        case 2: false_positives += (ulong)fd_chkdup_check_fast( chkdup, l0, l0_cnt, NULL, 0UL ); break;
        default: FD_TEST( 0 );
      }
      FD_COMPILER_FORGET( false_positives );
    }
  }
  time += fd_log_wallclock();
  fd_chkdup_delete( fd_chkdup_leave( chkdup ) );
  return (ulong)time/(iters*10UL);
}


const float FALSE_POSITIVE_RATE[3][129] = { {
  0.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f },
 { 0.0f, 0.0f, 9.094947017729282e-13f, 2.0617918483623043e-10f, 4.847388934692276e-09f, 4.577431977903501e-08f, 2.612751602848462e-07f, 1.0803999487274396e-06f, 3.56734803019787e-06f, 9.974062864515076e-06f, 2.4534641517415245e-05f, 5.451591868133043e-05f, 0.00011151780022267133f, 0.00021299704133204145f, 0.0003839707355778321f, 0.0006588414873082149f, 0.0010832750499168986f, 0.0017160525888012534f, 0.002630812858262055f, 0.003917593609369052f, 0.005684075777375397f, 0.008056428074509236f, 0.011179643642517334f, 0.01521725504850957f, 0.02035031035975976f, 0.02677549307982452f, 0.034702274609748285f, 0.04434900217817683f, 8e-05f, 0.00011f, 0.0001f, 0.0004f, 0.0003f, 0.0003f, 0.0003f, 0.0001f, 0.0003f, 0.0005f, 0.0009f, 0.0011f, 0.001f, 0.001f, 0.0018f, 0.0015f, 0.0022f, 0.0019f, 0.003f, 0.0046f, 0.0039f, 0.0047f, 0.0061f, 0.0066f, 0.0089f, 0.0084f, 0.0102f, 0.0102f, 0.0133f, 0.0146f, 0.0177f, 0.0167f, 0.0223f, 0.0205f, 0.0252f, 0.03f, 0.0336f },
 { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.6653345369377348e-15f, 4.8183679268731794e-14f, 7.190914530497139e-13f, 6.9040329009339985e-12f, 4.795008834435066e-11f, 2.599626069965666e-10f, 1.1588630055570093e-09f, 4.408280629419892e-09f, 1.4707721818219e-08f, 4.3947762873308704e-08f, 1.1954088041665756e-07f, 2.9985142335764436e-07f, 7.008890100523857e-07f, 1.5398246405728955e-06f, 3.202324702855641e-06f, 6.342030254291586e-06f, 1.202157745061605e-05f, 2.190520274913954e-05f, 3.851306727542525e-05f, 6.554686731563564e-05f, 0.00010829501498299532f, 0.00017412366349667252f, 0.00027305714590297736f, 0.0034f, 0.0057f, 0.0069f, 0.0089f, 0.0116f, 0.0138f, 0.0183f, 0.0222f, 0.0003f, 0.0005f, 0.0009f, 0.0011f, 0.001f, 0.001f, 0.0018f, 0.0015f, 0.0022f, 0.0019f, 0.003f, 0.0046f, 0.0039f, 0.0047f, 0.0061f, 0.0066f, 0.0089f, 0.0084f, 0.0102f, 0.0102f, 0.0133f, 0.0146f, 0.0177f, 0.0167f, 0.0223f, 0.0205f, 0.0252f, 0.03f, 0.0336f } };


int
main( int argc,
    char ** argv ) {
  fd_boot( &argc, &argv );
  ulong skip = fd_env_strip_cmdline_ulong( &argc, &argv, "--test-interval", NULL, 4UL );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 123U, 4567UL ) );

  float const * fp = FALSE_POSITIVE_RATE[ FD_CHKDUP_IMPL ];

  for( ulong l0=0UL; l0<40UL; l0+=skip ) {
    FD_TEST( test_false_positive_rate( 0.f,    fd_chkdup_check,      rng, l0, 0UL ) );
    FD_TEST( test_false_positive_rate( 0.f,    fd_chkdup_check_slow, rng, l0, 0UL ) );
    FD_TEST( test_false_positive_rate( fp[l0], fd_chkdup_check_fast, rng, l0, 0UL ) );
  }
  for( ulong l=1UL; l<=64UL; l+=7+skip ) {
    for( ulong k=0UL; k<5UL; k+=skip ) {
      ulong l0 = fd_rng_ulong_roll( rng, l+1 );
      ulong l1 = l-l0;
      FD_TEST( test_false_positive_rate( 0.f,   fd_chkdup_check,      rng, l0, l1 ) );
      FD_TEST( test_false_positive_rate( 0.f,   fd_chkdup_check_slow, rng, l0, l1 ) );
      FD_TEST( test_false_positive_rate( fp[l], fd_chkdup_check_fast, rng, l0, l1 ) );
    }
  }
  FD_TEST( test_false_positive_rate( fp[8], fd_chkdup_check_fast, rng, 4, 4 ) );


  FD_LOG_NOTICE(( "check:      %lu ns per transaction", performance_test( rng, 0 ) ));
  FD_LOG_NOTICE(( "check_slow: %lu ns per transaction", performance_test( rng, 1 ) ));
  FD_LOG_NOTICE(( "check_fast: %lu ns per transaction", performance_test( rng, 2 ) ));


  FD_TEST( test_null( fd_chkdup_check,      rng ) );
  FD_TEST( test_null( fd_chkdup_check_slow, rng ) );
  FD_TEST( test_null( fd_chkdup_check_fast, rng ) );

  FD_TEST( test_duplicates( fd_chkdup_check,      rng ) );
  FD_TEST( test_duplicates( fd_chkdup_check_slow, rng ) );
  FD_TEST( test_duplicates( fd_chkdup_check_fast, rng ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
