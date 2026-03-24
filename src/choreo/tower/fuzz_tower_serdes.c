#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_tower_serdes.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

static void
fuzz_compact_tower_sync( uchar const * data,
                         ulong         data_sz ) {

  fd_compact_tower_sync_serde_t serde[1];
  memset( serde, 0, sizeof(fd_compact_tower_sync_serde_t) );

  int de_err = fd_compact_tower_sync_de( serde, data, data_sz );
  if( de_err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return;
  }

  FD_FUZZ_MUST_BE_COVERED;

  uchar buf[1024];
  ulong out_sz = 0;

  int ser_err = fd_compact_tower_sync_ser( serde, buf, sizeof(buf), &out_sz );
  assert( !ser_err );

  FD_FUZZ_MUST_BE_COVERED;

  fd_compact_tower_sync_serde_t serde2[1];
  memset( serde2, 0, sizeof(fd_compact_tower_sync_serde_t) );

  int de_err2 = fd_compact_tower_sync_de( serde2, buf, out_sz );
  assert( !de_err2 );

  assert( serde->root         == serde2->root         );
  assert( serde->lockouts_cnt == serde2->lockouts_cnt );
  for( ushort i = 0; i < serde->lockouts_cnt; i++ ) {
    assert( serde->lockouts[i].offset             == serde2->lockouts[i].offset             );
    assert( serde->lockouts[i].confirmation_count == serde2->lockouts[i].confirmation_count );
  }
  assert( !memcmp( &serde->hash, &serde2->hash, sizeof(fd_hash_t) ) );
  assert( serde->timestamp_option == serde2->timestamp_option );
  if( serde->timestamp_option ) {
    assert( serde->timestamp == serde2->timestamp );
  }
  assert( !memcmp( &serde->block_id, &serde2->block_id, sizeof(fd_hash_t) ) );

  FD_FUZZ_MUST_BE_COVERED;
}

static void
fuzz_vote_acc( uchar const * data,
               ulong         data_sz ) {

  fd_vote_acc_t serde[1];
  memset( serde, 0, sizeof(fd_vote_acc_t) );

  int de_err = fd_vote_acc_de( serde, data, data_sz );
  if( de_err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return;
  }

  FD_FUZZ_MUST_BE_COVERED;

  uchar buf[4096];
  ulong out_sz = 0;

  int ser_err = fd_vote_acc_ser( serde, buf, sizeof(buf), &out_sz );
  assert( !ser_err );

  FD_FUZZ_MUST_BE_COVERED;

  fd_vote_acc_t serde2[1];
  memset( serde2, 0, sizeof(fd_vote_acc_t) );

  int de_err2 = fd_vote_acc_de( serde2, buf, out_sz );
  assert( !de_err2 );

  assert( serde->kind == serde2->kind );

  switch( serde->kind ) {
  case FD_VOTE_ACC_V2: {
    assert( !memcmp( &serde->v2.node_pubkey,          &serde2->v2.node_pubkey,          sizeof(fd_pubkey_t) ) );
    assert( !memcmp( &serde->v2.authorized_withdrawer,&serde2->v2.authorized_withdrawer,sizeof(fd_pubkey_t) ) );
    assert( serde->v2.commission == serde2->v2.commission );
    assert( serde->v2.votes_cnt == serde2->v2.votes_cnt );
    for( ulong i=0; i<serde->v2.votes_cnt; i++ ) {
      assert( serde->v2.votes[i].slot == serde2->v2.votes[i].slot );
      assert( serde->v2.votes[i].conf == serde2->v2.votes[i].conf );
    }
    assert( serde->v2.root_option == serde2->v2.root_option );
    if( serde->v2.root_option ) {
      assert( serde->v2.root == serde2->v2.root );
    }
    assert( serde->v2.authorized_voters_cnt == serde2->v2.authorized_voters_cnt );
    for( ulong i=0; i<serde->v2.authorized_voters_cnt; i++ ) {
      assert( serde->v2.authorized_voters[i].epoch == serde2->v2.authorized_voters[i].epoch );
      assert( !memcmp( &serde->v2.authorized_voters[i].pubkey, &serde2->v2.authorized_voters[i].pubkey, sizeof(fd_pubkey_t) ) );
    }
    break;
  }
  case FD_VOTE_ACC_V3: {
    assert( !memcmp( &serde->v3.node_pubkey,          &serde2->v3.node_pubkey,          sizeof(fd_pubkey_t) ) );
    assert( !memcmp( &serde->v3.authorized_withdrawer,&serde2->v3.authorized_withdrawer,sizeof(fd_pubkey_t) ) );
    assert( serde->v3.commission == serde2->v3.commission );
    assert( serde->v3.votes_cnt == serde2->v3.votes_cnt );
    for( ulong i=0; i<serde->v3.votes_cnt; i++ ) {
      assert( serde->v3.votes[i].latency == serde2->v3.votes[i].latency );
      assert( serde->v3.votes[i].slot    == serde2->v3.votes[i].slot    );
      assert( serde->v3.votes[i].conf    == serde2->v3.votes[i].conf    );
    }
    assert( serde->v3.root_option == serde2->v3.root_option );
    if( serde->v3.root_option ) {
      assert( serde->v3.root == serde2->v3.root );
    }
    assert( serde->v3.authorized_voters_cnt == serde2->v3.authorized_voters_cnt );
    for( ulong i=0; i<serde->v3.authorized_voters_cnt; i++ ) {
      assert( serde->v3.authorized_voters[i].epoch == serde2->v3.authorized_voters[i].epoch );
      assert( !memcmp( &serde->v3.authorized_voters[i].pubkey, &serde2->v3.authorized_voters[i].pubkey, sizeof(fd_pubkey_t) ) );
    }
    break;
  }
  case FD_VOTE_ACC_V4: {
    assert( !memcmp( &serde->v4.node_pubkey,               &serde2->v4.node_pubkey,               sizeof(fd_pubkey_t) ) );
    assert( !memcmp( &serde->v4.authorized_withdrawer,     &serde2->v4.authorized_withdrawer,     sizeof(fd_pubkey_t) ) );
    assert( !memcmp( &serde->v4.inflation_rewards_collector,&serde2->v4.inflation_rewards_collector,sizeof(fd_pubkey_t) ) );
    assert( !memcmp( &serde->v4.block_revenue_collector,   &serde2->v4.block_revenue_collector,   sizeof(fd_pubkey_t) ) );
    assert( serde->v4.inflation_rewards_commission_bps == serde2->v4.inflation_rewards_commission_bps );
    assert( serde->v4.block_revenue_commission_bps     == serde2->v4.block_revenue_commission_bps     );
    assert( serde->v4.pending_delegator_rewards        == serde2->v4.pending_delegator_rewards        );
    assert( serde->v4.has_bls_pubkey_compressed        == serde2->v4.has_bls_pubkey_compressed        );
    if( serde->v4.has_bls_pubkey_compressed ) {
      assert( !memcmp( serde->v4.bls_pubkey_compressed, serde2->v4.bls_pubkey_compressed, 48 ) );
    }
    assert( serde->v4.votes_cnt == serde2->v4.votes_cnt );
    for( ulong i=0; i<serde->v4.votes_cnt; i++ ) {
      assert( serde->v4.votes[i].latency == serde2->v4.votes[i].latency );
      assert( serde->v4.votes[i].slot    == serde2->v4.votes[i].slot    );
      assert( serde->v4.votes[i].conf    == serde2->v4.votes[i].conf    );
    }
    assert( serde->v4.root_option == serde2->v4.root_option );
    if( serde->v4.root_option ) {
      assert( serde->v4.root == serde2->v4.root );
    }
    assert( serde->v4.authorized_voters_cnt == serde2->v4.authorized_voters_cnt );
    for( ulong i=0; i<serde->v4.authorized_voters_cnt; i++ ) {
      assert( serde->v4.authorized_voters[i].epoch == serde2->v4.authorized_voters[i].epoch );
      assert( !memcmp( &serde->v4.authorized_voters[i].pubkey, &serde2->v4.authorized_voters[i].pubkey, sizeof(fd_pubkey_t) ) );
    }
    break;
  }
  default: assert( 0 );
  }

  FD_FUZZ_MUST_BE_COVERED;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  if( FD_UNLIKELY( data_sz<1 ) ) return 0;

  uchar selector = data[0];
  data    += 1;
  data_sz -= 1;

  if( selector & 1 ) fuzz_vote_acc( data, data_sz );
  else               fuzz_compact_tower_sync( data, data_sz );

  return 0;
}
