#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_reedsol.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

#define SHRED_SZ_MIN ( 32UL )
#define SHRED_SZ_MAX ( 63UL )

struct reedsol_test {
  ulong shred_sz;
  ulong data_shred_cnt;
  ulong parity_shred_cnt;
  ulong erased_shred_cnt;
  ulong corrupt_shred_idx;
  uchar data[ ];
};
typedef struct reedsol_test reedsol_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<sizeof( reedsol_test_t ) ) ) return -1;
  reedsol_test_t const * test = ( reedsol_test_t const * ) data;

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  uchar mem[ FD_REEDSOL_FOOTPRINT ] __attribute__((aligned(FD_REEDSOL_ALIGN)));

  uchar const * data_shreds = test->data;
  uchar parity_shreds[ SHRED_SZ_MAX * FD_REEDSOL_PARITY_SHREDS_MAX ];
  uchar recovered_shreds[ SHRED_SZ_MAX * ( FD_REEDSOL_PARITY_SHREDS_MAX+1UL ) ];
  
  uchar const * d[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar *       p[ FD_REEDSOL_PARITY_SHREDS_MAX ];
  uchar *       r[ FD_REEDSOL_PARITY_SHREDS_MAX+1UL ];
  uchar const * erased_truth[ FD_REEDSOL_PARITY_SHREDS_MAX+1UL ];

  ulong shred_sz = SHRED_SZ_MIN + test->shred_sz % ( SHRED_SZ_MAX-SHRED_SZ_MIN+1UL );
  ulong d_cnt = test->data_shred_cnt % FD_REEDSOL_DATA_SHREDS_MAX + 1UL;
  ulong p_cnt = test->parity_shred_cnt % FD_REEDSOL_PARITY_SHREDS_MAX + 1UL;
  ulong e_cnt = test->erased_shred_cnt % ( p_cnt+2UL );
  ulong corrupt_idx = test->corrupt_shred_idx % ( d_cnt+p_cnt );

  if( FD_UNLIKELY( size < sizeof( reedsol_test_t ) + shred_sz*d_cnt ) ) return -1;

  for( ulong i=0UL; i<d_cnt; i++ )  d[ i ] = data_shreds + shred_sz*i;
  for( ulong i=0UL; i<p_cnt; i++ )  p[ i ] = parity_shreds + shred_sz*i;
  for( ulong i=0UL; i<e_cnt; i++ )  r[ i ] = recovered_shreds + shred_sz*i;

  fd_reedsol_t * rs = fd_reedsol_encode_init( mem, shred_sz );
  for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_encode_add_data_shred(   rs, d[ i ] );
  for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_encode_add_parity_shred( rs, p[ i ] );
  fd_reedsol_encode_fini( rs );

  /* Use reservoir sampling to select exactly e_cnt of the shreds
     to erased */
  ulong erased_cnt = 0UL;
  rs = fd_reedsol_recover_init( mem, shred_sz );
  for( ulong i=0UL; i<d_cnt; i++ ) {
    /* Erase with probability:
       (e_cnt - erased_cnt)/(d_cnt + p_cnt - i) */
    if( fd_rng_ulong_roll( rng, d_cnt+p_cnt-i ) < (e_cnt-erased_cnt) ) {
      erased_truth[ erased_cnt ] = d[ i ];
      fd_reedsol_recover_add_erased_shred(    rs, 1, r[ erased_cnt++ ] );
    } else fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
  }
  for( ulong i=0UL; i<p_cnt; i++ ) {
    if( fd_rng_ulong_roll( rng, p_cnt-i ) < (e_cnt-erased_cnt) ) {
      erased_truth[ erased_cnt ] = p[ i ];
      fd_reedsol_recover_add_erased_shred(    rs, 0, r[ erased_cnt++ ] );
    } else fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );
  }

  if( FD_UNLIKELY( erased_cnt!=e_cnt ) ) {
     /* If this fails, the test is wrong. */
     __builtin_trap();
  }
  int retval = fd_reedsol_recover_fini( rs );

  if( FD_UNLIKELY( e_cnt>p_cnt ) ) {
    if( FD_UNLIKELY( retval!=FD_REEDSOL_ERR_PARTIAL ) ) {
      __builtin_trap();
    }
  } else {
    if( FD_UNLIKELY( FD_REEDSOL_SUCCESS!=retval ) ) {
      __builtin_trap();
    }

    for( ulong i=0UL; i<e_cnt; i++ ) {
      if( FD_UNLIKELY( memcmp( erased_truth[ i ], r[ i ], shred_sz ) ) ) {
        __builtin_trap();
      }
    }
  }

  /* Corrupt one shred and make sure it gets caught */
  uchar corrupt_shred[ SHRED_SZ_MAX ];
  ulong byte_idx = fd_rng_ulong_roll( rng, shred_sz );
  if( corrupt_idx<d_cnt ) {
    fd_memcpy( corrupt_shred, d[ corrupt_idx ], shred_sz );
    corrupt_shred[ byte_idx ] ^= (uchar)1;
    d[ corrupt_idx ] = &corrupt_shred[0];
  } else p[ corrupt_idx-d_cnt ][ byte_idx ] ^= (uchar)1;

  rs = fd_reedsol_recover_init( mem, shred_sz );
  for( ulong i=0UL; i<d_cnt; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 1, d[ i ] );
  for( ulong i=0UL; i<p_cnt; i++ ) fd_reedsol_recover_add_rcvd_shred( rs, 0, p[ i ] );

  if( FD_UNLIKELY( FD_REEDSOL_ERR_CORRUPT!=fd_reedsol_recover_fini( rs ) ) ) {
    __builtin_trap();
  }

  if( corrupt_idx<d_cnt )  d[ corrupt_idx       ]              = data_shreds + shred_sz*corrupt_idx;
  else                     p[ corrupt_idx-d_cnt ][ byte_idx ] ^= (uchar)1;

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
