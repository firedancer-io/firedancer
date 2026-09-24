#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "ag_hist_file.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <stdlib.h>

#define SIG_SZ (64UL)

static uchar       valid[ AG_HIST_FILE_MAX ];
static ulong       valid_sz;
static uchar       private_key[ 32 ];
static fd_pubkey_t public_key[ 1 ];

static void
sign_hist( void *        ctx FD_PARAM_UNUSED,
           uchar         sig[ 64 ],
           uchar const * msg,
           ulong         msg_sz ) {
  fd_sha512_t sha[ 1 ];
  uchar       m[ FD_KEYGUARD_VOTOR_HIST_MSG_SZ ];
  ag_hist_file_sign_msg( msg, msg_sz, m );
  fd_ed25519_sign( sig, m, sizeof(m), public_key->uc, private_key, sha );
}

int
LLVMFuzzerInitialize( int *    argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );

  fd_memset( private_key, 0x42, sizeof(private_key) );
  fd_sha512_t sha[ 1 ];
  fd_ed25519_public_from_private( public_key->uc, private_key, sha );

  static ag_hist_t hist;
  ulong first = ag_hist_first_slot( 1000UL );
  hist.anchor           = 1000UL;
  hist.last_leader_slot = first+4UL;
  hist.rec_cnt          = 3UL;
  hist.rec[ 0 ] = (ag_hist_rec_t){ .slot = first,     .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_VOTED_NOTAR };
  hist.rec[ 1 ] = (ag_hist_rec_t){ .slot = first+1UL, .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_BAD_WINDOW  };
  hist.rec[ 2 ] = (ag_hist_rec_t){ .slot = first+5UL, .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_RETIRED     };
  fd_memset( hist.rec[ 0 ].notar_hash, 0xAB, sizeof(ag_block_hash_t) );

  long sz = ag_hist_file_ser( &hist, public_key, 1234567L, sign_hist, NULL, valid, sizeof(valid) );
  FD_TEST( sz>0L );
  valid_sz = (ulong)sz;
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  uchar buf[ AG_HIST_FILE_MAX ];
  fd_memcpy( buf, valid, valid_sz );

  ulong sz = valid_sz;
  if( data_sz>=3UL ) {
    ulong requested = ( (ulong)data[ 1 ] | ( (ulong)data[ 2 ]<<8 ) ) % ( AG_HIST_FILE_MAX+1UL );
    if( ( data[ 0 ]&3U )==1U ) sz = fd_ulong_min( requested, valid_sz );
    if( ( data[ 0 ]&3U )==2U ) {
      sz = fd_ulong_max( requested, valid_sz );
      for( ulong i=valid_sz; i<sz; i++ ) buf[ i ] = data[ i%data_sz ];
    }
  }

  for( ulong i=3UL; i+2UL<data_sz; i+=3UL ) {
    ulong idx = ( (ulong)data[ i ] | ( (ulong)data[ i+1UL ]<<8 ) ) % fd_ulong_max( sz, 1UL );
    if( idx<sz ) buf[ idx ] ^= data[ i+2UL ];
  }

  /* resign most inputs so the body parser sees them, one bit keeps
     the mangled signature so the verify path gets exercised too */
  int keep_sig = data_sz>=1UL && ( data[ 0 ]&4U );
  if( sz>=AG_HIST_FILE_HDR_SZ+SIG_SZ && !keep_sig ) sign_hist( NULL, buf+sz-SIG_SZ, buf, sz-SIG_SZ );

  ag_hist_t out;
  long      timestamp;
  int err = ag_hist_file_de( buf, sz, public_key, &out, &timestamp );
  if( !err ) {
    FD_FUZZ_MUST_BE_COVERED;
    FD_TEST( out.rec_cnt<=AG_HIST_MAX );
    FD_TEST( out.anchor!=ULONG_MAX );
    ulong first = ag_hist_first_slot( out.anchor );
    for( ulong i=0UL; i<out.rec_cnt; i++ ) {
      FD_TEST( out.rec[ i ].slot>=first );
      FD_TEST( !( out.rec[ i ].flags & ~AG_HIST_FLAG_MASK ) );
      FD_TEST( out.rec[ i ].flags & AG_HIST_FLAG_VOTED );
      if( i ) FD_TEST( out.rec[ i-1UL ].slot<out.rec[ i ].slot );
    }
  }
  return 0;
}

#undef SIG_SZ
