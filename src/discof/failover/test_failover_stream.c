#include "fd_failover_stream.h"

#include "../../choreo/tower/fd_tower_serdes.h"

#include <string.h>

static ulong
make_tower( uchar * state,
            ulong   root,
            ulong   offset0,
            ulong   offset1 ) {
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = root;
  serde.lockouts_cnt                     = 2U;
  serde.lockouts[ 0 ].offset             = offset0;
  serde.lockouts[ 0 ].confirmation_count = 2U;
  serde.lockouts[ 1 ].offset             = offset1;
  serde.lockouts[ 1 ].confirmation_count = 1U;
  serde.timestamp_option                 = 1U;
  serde.timestamp                        = 123L;
  fd_memset( &serde.hash,     0xA5, sizeof(serde.hash) );
  fd_memset( &serde.block_id, 0x5A, sizeof(serde.block_id) );

  ulong state_sz = 0UL;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, state, FD_FAILOVER_TOWER_STATE_MAX, &state_sz ) );
  return state_sz;
}

static ulong
make_consensus( uchar *       payload,
                ulong         term,
                ulong         link_seq,
                ulong         vote_slot,
                uchar const * state,
                ulong         state_sz ) {
  fd_failover_consensus_state_t msg = {
    .term      = term,
    .link_seq  = link_seq,
    .vote_slot = vote_slot,
    .mode      = (uchar)FD_FAILOVER_MODE_TOWER,
    .state_len = (ushort)state_sz,
  };
  fd_memcpy( payload, &msg, sizeof(msg) );
  fd_memcpy( payload+sizeof(msg), state, state_sz );
  return sizeof(msg)+state_sz;
}

static void
test_status_decode( void ) {
  fd_failover_hello_t peer = { .term=7UL, .role=FD_FAILOVER_ROLE_ACTIVE };
  fd_failover_status_t status = {
    .term             = 7UL,
    .role             = FD_FAILOVER_ROLE_ACTIVE,
    .replay_slot      = 100UL,
    .turbine_slot     = 101UL,
    .last_vote_slot   = 99UL,
    .root_slot        = 68UL,
    .next_leader_slot = FD_FAILOVER_SLOT_NULL,
    .flags            = FD_FAILOVER_FLAG_VOTE_ROOTED|FD_FAILOVER_FLAG_CAUGHT_UP,
    .status           = FD_FAILOVER_STATUS_REPLAG,
    .ack_seq          = 8UL,
  };

  fd_failover_status_t out;
  FD_TEST( fd_failover_status_decode( &out, &peer, 9UL, (uchar const *)&status, sizeof(status) ) );
  FD_TEST( !memcmp( &out, &status, sizeof(status) ) );

  fd_failover_status_t before = out;
  status.ack_seq = 9UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 9UL, (uchar const *)&status, sizeof(status) ) );
  FD_TEST( !memcmp( &out, &before, sizeof(out) ) );

  status.ack_seq = ULONG_MAX-1UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 0UL, (uchar const *)&status, sizeof(status) ) );
  FD_TEST( fd_failover_status_decode( &out, &peer, ULONG_MAX, (uchar const *)&status, sizeof(status) ) );
  status.ack_seq = ULONG_MAX;
  FD_TEST( fd_failover_status_decode( &out, &peer, 0UL, (uchar const *)&status, sizeof(status) ) );

  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status)-1UL ) );
  status.role = FD_FAILOVER_ROLE_STANDBY;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.role = FD_FAILOVER_ROLE_ACTIVE;
  status.term = 8UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.term  = 7UL;
  status.flags = 8U;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.flags  = 0U;
  status.status = 16U;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );

  status.status = FD_FAILOVER_STATUS_CATCHUP;
  status.flags  = FD_FAILOVER_FLAG_CAUGHT_UP;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );

  status.status      = 0U;
  status.replay_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );

  status.flags          = 0U;
  status.replay_slot    = 100UL;
  status.last_vote_slot = 101UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );

  status.last_vote_slot = 99UL;
  status.root_slot      = 100UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );

  status.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  status.replay_slot    = 67UL;
  status.root_slot      = 68UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
}

static void
test_consensus_decode( void ) {
  fd_failover_hello_t peer = {
    .term    = 7UL,
    .role    = FD_FAILOVER_ROLE_ACTIVE,
    .boot_id = 11UL,
  };

  uchar state_a[ FD_FAILOVER_TOWER_STATE_MAX ];
  uchar state_b[ FD_FAILOVER_TOWER_STATE_MAX ];
  uchar state_c[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong state_a_sz = make_tower( state_a, 100UL, 5UL, 2UL );
  ulong state_b_sz = make_tower( state_b, 100UL, 5UL, 4UL );
  ulong state_c_sz = make_tower( state_c, 100UL, 6UL, 1UL );

  uchar payload[ sizeof(fd_failover_consensus_state_t)+FD_FAILOVER_TOWER_STATE_MAX+1UL ];
  ulong payload_sz = make_consensus( payload, 7UL, 10UL, 107UL, state_a, state_a_sz );

  fd_failover_consensus_cache_t cache = {0};
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( cache.valid && cache.msg.link_seq==10UL && cache.msg.vote_slot==107UL );
  FD_TEST( cache.peer_boot_id==11UL && !memcmp( cache.state, state_a, state_a_sz ) );

  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  fd_failover_consensus_cache_t before = cache;
  payload_sz = make_consensus( payload, 7UL, 9UL, 107UL, state_a, state_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( !memcmp( &cache, &before, sizeof(cache) ) );

  payload_sz = make_consensus( payload, 7UL, 11UL, 107UL, state_a, state_a_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  before = cache;
  payload_sz = make_consensus( payload, 7UL, 11UL, 109UL, state_b, state_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( !memcmp( &cache, &before, sizeof(cache) ) );

  payload_sz = make_consensus( payload, 7UL, 12UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.vote_slot==109UL );

  cache.msg.link_seq = ULONG_MAX-1UL;
  payload_sz = make_consensus( payload, 7UL, 0UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  before = cache;
  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_c, state_c_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( !memcmp( &cache, &before, sizeof(cache) ) );

  peer.boot_id = 12UL;
  payload_sz = make_consensus( payload, 7UL, 0UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( cache.peer_boot_id==12UL && cache.msg.link_seq==0UL );

  peer.term = 8UL;
  payload_sz = make_consensus( payload, 8UL, 0UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.term==8UL );

  before = cache;
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_ACTIVE, &peer, payload, payload_sz ) );
  peer.role = FD_FAILOVER_ROLE_STANDBY;
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  peer.role = FD_FAILOVER_ROLE_ACTIVE;
  payload_sz = make_consensus( payload, 7UL, 1UL, 110UL, state_b, state_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  FD_TEST( !memcmp( &cache, &before, sizeof(cache) ) );

  fd_failover_consensus_cache_t empty = {0};
  peer.term = 7UL;
  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  fd_failover_consensus_state_t * hdr = (fd_failover_consensus_state_t *)payload;
  hdr->state_len--;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );
  hdr->state_len++;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz+1UL ) );
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, sizeof(*hdr)-1UL ) );

  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  hdr->vote_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  hdr->mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  uchar invalid[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong invalid_sz = make_tower( invalid, 100UL, 5UL, 0UL );
  payload_sz = make_consensus( payload, 7UL, 1UL, 105UL, invalid, invalid_sz );
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  fd_failover_consensus_state_t oversized = {
    .term      = 7UL,
    .link_seq  = 1UL,
    .vote_slot = 1UL,
    .state_len = (ushort)(FD_FAILOVER_TOWER_STATE_MAX+1UL),
  };
  fd_memcpy( payload, &oversized, sizeof(oversized) );
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer,
                                          payload, sizeof(oversized)+FD_FAILOVER_TOWER_STATE_MAX+1UL ) );

  uchar no_root[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong no_root_sz = make_tower( no_root, ULONG_MAX, 0UL, 2UL );
  payload_sz = make_consensus( payload, 7UL, 1UL, 2UL, no_root, no_root_sz );
  FD_TEST( fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, &peer, payload, payload_sz ) );

  fd_failover_status_t status = { .term=7UL, .last_vote_slot=8UL };
  FD_TEST( fd_failover_replication_lag( 1, &status, 12UL, &empty )==6UL );
  status.term = 8UL;
  FD_TEST( fd_failover_replication_lag( 1, &status, 12UL, &empty )==FD_FAILOVER_SLOT_NULL );
  status.term = 7UL;
  FD_TEST( fd_failover_replication_lag( 1, &status, 11UL, &empty )==FD_FAILOVER_SLOT_NULL );
  status.last_vote_slot = 1UL;
  FD_TEST( fd_failover_replication_lag( 1, &status, 12UL, &empty )==0UL );
  FD_TEST( fd_failover_replication_lag( 0, &status, 12UL, &empty )==FD_FAILOVER_SLOT_NULL );
  status.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( fd_failover_replication_lag( 1, &status, 12UL, &empty )==FD_FAILOVER_SLOT_NULL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_status_decode();
  test_consensus_decode();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
