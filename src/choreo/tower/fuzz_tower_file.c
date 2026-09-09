#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_tower_file.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <stdlib.h>

#define DATA_OFF (4UL+64UL+8UL)

static uchar       deque_mem[ FD_TOWER_VOTE_FOOTPRINT ] __attribute__((aligned(FD_TOWER_VOTE_ALIGN)));
static uchar       valid[ FD_TOWER_FILE_MAX ];
static ulong       valid_sz;
static uchar       private_key[ 32 ];
static fd_pubkey_t public_key[ 1 ];

static void
sign_tower( void *        ctx FD_PARAM_UNUSED,
            uchar         sig[ 64 ],
            uchar const * msg,
            ulong         msg_sz ) {
  fd_sha512_t sha[ 1 ];
  fd_ed25519_sign( sig, msg, msg_sz, public_key->uc, private_key, sha );
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

  fd_tower_vote_t * votes = fd_tower_vote_join( fd_tower_vote_new( deque_mem ) );
  FD_TEST( votes );
  fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=100UL, .conf=3UL } );
  fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=101UL, .conf=2UL } );
  fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=105UL, .conf=1UL } );

  fd_hash_t bank_hash; fd_memset( &bank_hash, 0xAB, sizeof(bank_hash) );
  fd_hash_t block_id;  fd_memset( &block_id,  0xCD, sizeof(block_id)  );
  long sz = fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                               public_key, sign_tower, NULL, valid, sizeof(valid) );
  FD_TEST( sz>0L );
  valid_sz = (ulong)sz;
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  uchar buf[ FD_TOWER_FILE_MAX ];
  fd_memcpy( buf, valid, valid_sz );

  ulong sz = valid_sz;
  if( data_sz>=3UL ) {
    ulong requested = ( (ulong)data[ 1 ] | ( (ulong)data[ 2 ]<<8 ) ) % ( FD_TOWER_FILE_MAX+1UL );
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

  if( sz>=DATA_OFF ) {
    FD_STORE( ulong, buf+4UL+64UL, sz-DATA_OFF );
    sign_tower( NULL, buf+4UL, buf+DATA_OFF, sz-DATA_OFF );
  }

  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong           votes_cnt;
  ulong           root;
  long            timestamp;
  int err = fd_tower_file_de( buf, sz, public_key, votes, &votes_cnt, &root, &timestamp );
  if( !err ) {
    FD_FUZZ_MUST_BE_COVERED;
    FD_TEST( votes_cnt && votes_cnt<=FD_TOWER_VOTE_MAX );
    for( ulong i=1UL; i<votes_cnt; i++ ) {
      FD_TEST( votes[ i-1UL ].slot<votes[ i ].slot );
      FD_TEST( votes[ i-1UL ].conf>votes[ i ].conf );
    }
  }
  return 0;
}

#undef DATA_OFF
