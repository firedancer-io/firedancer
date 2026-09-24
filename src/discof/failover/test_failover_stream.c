#include "fd_failover_stream.h"

#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../choreo/votor/ag_hist.h"

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

/* An alpenglow vote history with notar votes on the rec_cnt slots
   ending at tip, tip_flags added on the tip record, serialised into
   state.  Returns the byte count. */
static ulong
make_hist( uchar * state,
           ulong   anchor,
           ulong   last_leader_slot,
           ulong   tip,
           ulong   rec_cnt,
           uchar   tip_flags ) {
  FD_TEST( rec_cnt && rec_cnt<=AG_HIST_MAX );
  ag_hist_t hist;
  fd_memset( &hist, 0, sizeof(hist) );
  hist.anchor           = anchor;
  hist.last_leader_slot = last_leader_slot;
  hist.rec_cnt          = rec_cnt;
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    hist.rec[ i ].slot  = tip-rec_cnt+1UL+i;
    hist.rec[ i ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR;
    fd_memset( hist.rec[ i ].notar_hash, (int)(0x10UL+i), sizeof(ag_block_hash_t) );
  }
  hist.rec[ rec_cnt-1UL ].flags |= tip_flags;

  ulong state_sz = 0UL;
  FD_TEST( !ag_hist_ser( &hist, state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &state_sz ) );
  return state_sz;
}

static ulong
make_consensus_mode( uchar *       payload,
                     ulong         mode,
                     ulong         term,
                     ulong         link_seq,
                     ulong         vote_slot,
                     uchar const * state,
                     ulong         state_sz ) {
  fd_failover_consensus_state_t msg = {
    .term      = term,
    .link_seq  = link_seq,
    .vote_slot = vote_slot,
    .mode      = (uchar)mode,
    .state_len = (ushort)state_sz,
  };
  fd_memcpy( payload, &msg, sizeof(msg) );
  fd_memcpy( payload+sizeof(msg), state, state_sz );
  return sizeof(msg)+state_sz;
}

static ulong
make_consensus( uchar *       payload,
                ulong         term,
                ulong         link_seq,
                ulong         vote_slot,
                uchar const * state,
                ulong         state_sz ) {
  return make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, term, link_seq, vote_slot, state, state_sz );
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
  FD_TEST( fd_memeq( &out, &status, sizeof(status) ) );

  fd_failover_status_t before = out;
  status.ack_seq = 9UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 9UL, (uchar const *)&status, sizeof(status) ) );
  FD_TEST( fd_memeq( &out, &before, sizeof(out) ) );

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
  FD_TEST( fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.term = 6UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.term  = 7UL;
  status.flags = 8U;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.flags  = 0U;
  /* A transition sets busy, and bit 5 is still not a status bit. */
  status.status = FD_FAILOVER_STATUS_BUSY;
  FD_TEST(  fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.status = 32U;
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

  /* The readiness fields: caught up needs a known tip, a leader window
     needs a replayed slot, and a leader slot sits above the root. */
  status.replay_slot      = 100UL;
  status.root_slot        = 68UL;
  status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
  status.flags            = FD_FAILOVER_FLAG_CAUGHT_UP;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.turbine_slot     = 101UL;
  FD_TEST(  fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.flags            = FD_FAILOVER_FLAG_IS_LEADER;
  status.replay_slot      = FD_FAILOVER_SLOT_NULL;
  status.last_vote_slot   = FD_FAILOVER_SLOT_NULL;
  status.root_slot        = FD_FAILOVER_SLOT_NULL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.replay_slot      = 100UL;
  FD_TEST(  fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.flags            = 0U;
  status.root_slot        = 68UL;
  status.next_leader_slot = 68UL;
  FD_TEST( !fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
  status.next_leader_slot = 69UL;
  FD_TEST(  fd_failover_status_decode( &out, &peer, 1UL, (uchar const *)&status, sizeof(status) ) );
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
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.valid && cache.msg.link_seq==10UL && cache.msg.vote_slot==107UL );
  FD_TEST( cache.peer_boot_id==11UL && fd_memeq( cache.state, state_a, state_a_sz ) );

  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

  fd_failover_consensus_cache_t before = cache;
  payload_sz = make_consensus( payload, 7UL, 9UL, 107UL, state_a, state_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );

  payload_sz = make_consensus( payload, 7UL, 11UL, 107UL, state_a, state_a_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

  before = cache;
  payload_sz = make_consensus( payload, 7UL, 11UL, 109UL, state_b, state_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );

  payload_sz = make_consensus( payload, 7UL, 12UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.vote_slot==109UL );

  cache.msg.link_seq = ULONG_MAX-1UL;
  payload_sz = make_consensus( payload, 7UL, 0UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

  before = cache;
  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_c, state_c_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );

  /* A term one past the paired HELLO is the active mid demotion, still
     streaming, and is accepted.  A term behind the HELLO is stale. */
  before = cache;
  payload_sz = make_consensus( payload, 8UL, 13UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.term==8UL && cache.msg.link_seq==13UL );
  fd_failover_consensus_cache_t advanced = cache;
  payload_sz = make_consensus( payload, 6UL, 14UL, 109UL, state_b, state_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &advanced, sizeof(cache) ) );
  cache = before; /* the cases below continue from the term 7 stream */

  peer.boot_id = 12UL;
  payload_sz = make_consensus( payload, 7UL, 0UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.peer_boot_id==12UL && cache.msg.link_seq==0UL );

  peer.term = 8UL;
  payload_sz = make_consensus( payload, 8UL, 0UL, 109UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.term==8UL );

  before = cache;
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  peer.role = FD_FAILOVER_ROLE_STANDBY;
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  peer.role = FD_FAILOVER_ROLE_ACTIVE;
  payload_sz = make_consensus( payload, 7UL, 1UL, 110UL, state_b, state_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );

  fd_failover_consensus_cache_t empty = {0};
  peer.term = 7UL;
  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  fd_failover_consensus_state_t * hdr = (fd_failover_consensus_state_t *)payload;
  hdr->state_len--;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  hdr->state_len++;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz+1UL ) );
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, sizeof(*hdr)-1UL ) );

  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  hdr->vote_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

  payload_sz = make_consensus( payload, 7UL, 1UL, 107UL, state_a, state_a_sz );
  hdr->mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

  uchar invalid[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong invalid_sz = make_tower( invalid, 100UL, 5UL, 0UL );
  payload_sz = make_consensus( payload, 7UL, 1UL, 105UL, invalid, invalid_sz );
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

  fd_failover_consensus_state_t oversized = {
    .term      = 7UL,
    .link_seq  = 1UL,
    .vote_slot = 1UL,
    .state_len = (ushort)(FD_FAILOVER_TOWER_STATE_MAX+1UL),
  };
  fd_memcpy( payload, &oversized, sizeof(oversized) );
  FD_TEST( !fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer,
                                          payload, sizeof(oversized)+FD_FAILOVER_TOWER_STATE_MAX+1UL ) );

  uchar no_root[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong no_root_sz = make_tower( no_root, ULONG_MAX, 0UL, 2UL );
  payload_sz = make_consensus( payload, 7UL, 1UL, 2UL, no_root, no_root_sz );
  FD_TEST( fd_failover_consensus_decode( &empty, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );

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

static void
test_consensus_final_check( void ) {
  uchar state_a[ FD_FAILOVER_TOWER_STATE_MAX ];
  uchar state_b[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong state_a_sz = make_tower( state_a, 100UL, 5UL, 2UL );
  ulong state_b_sz = make_tower( state_b, 100UL, 5UL, 4UL );

  fd_failover_consensus_cache_t cache = {0};
  FD_TEST( fd_failover_consensus_final_check( &cache, 11UL, 8UL, 20UL, 109UL,
                                              state_b, state_b_sz ) );

  cache.valid            = 1;
  cache.peer_boot_id     = 11UL;
  cache.msg.term         = 7UL;
  cache.msg.link_seq     = 19UL;
  cache.msg.vote_slot    = 107UL;
  cache.msg.state_len    = (ushort)state_a_sz;
  fd_memcpy( cache.state, state_a, state_a_sz );

  FD_TEST(  fd_failover_consensus_final_check( &cache, 11UL, 8UL, 20UL, 109UL,
                                               state_b, state_b_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 6UL, 20UL, 109UL,
                                               state_b, state_b_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 8UL, 20UL, 106UL,
                                               state_b, state_b_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 8UL, 20UL, 107UL,
                                               state_b, state_b_sz ) );
  FD_TEST(  fd_failover_consensus_final_check( &cache, 11UL, 8UL, 20UL, 107UL,
                                               state_a, state_a_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 8UL, 19UL, 109UL,
                                               state_b, state_b_sz ) );

  cache.msg.link_seq = ULONG_MAX-1UL;
  FD_TEST( fd_failover_consensus_final_check( &cache, 11UL, 8UL, 0UL, 109UL,
                                              state_b, state_b_sz ) );

  FD_TEST( fd_failover_consensus_final_check( &cache, 12UL, 7UL, 0UL, 109UL,
                                              state_b, state_b_sz ) );
  FD_TEST( fd_failover_consensus_final_check( &cache, 12UL, 7UL, 0UL, 107UL,
                                              state_a, state_a_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 12UL, 7UL, 0UL, 107UL,
                                               state_b, state_b_sz ) );
  FD_TEST( fd_failover_consensus_final_check( &cache, 12UL, 8UL, 0UL, 109UL,
                                              state_b, state_b_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 12UL, 8UL, 0UL, 106UL,
                                               state_b, state_b_sz ) );
}

/* test_state_tip_check: a state passes for its own tip only, inside its
   mode's size limit, and an unknown mode never passes. */
static void
test_state_tip_check( void ) {
  uchar tower[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong tower_sz = make_tower( tower, 100UL, 5UL, 2UL ); /* votes end at 107 */
  FD_TEST(  fd_failover_state_tip_check( FD_FAILOVER_MODE_TOWER, tower, tower_sz, 107UL ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_TOWER, tower, tower_sz, 108UL ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_TOWER, tower, tower_sz, 106UL ) );

  uchar hist[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong hist_sz = make_hist( hist, 4UL, 8UL, 10UL, 6UL, 0U );
  FD_TEST(  fd_failover_state_tip_check( FD_FAILOVER_MODE_ALPENGLOW, hist, hist_sz, 10UL ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_ALPENGLOW, hist, hist_sz, 11UL ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_ALPENGLOW, hist, hist_sz, 9UL  ) );
  /* A tower's bytes do not read as a history. */
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_ALPENGLOW, tower, tower_sz, 107UL ) );

  /* Past the mode's limit the bytes are never looked at. */
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_TOWER,     tower, FD_FAILOVER_TOWER_STATE_MAX+1UL,     107UL ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_ALPENGLOW, hist,  FD_FAILOVER_ALPENGLOW_STATE_MAX+1UL, 10UL  ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_CNT, hist,  hist_sz,  10UL  ) );
  FD_TEST( !fd_failover_state_tip_check( FD_FAILOVER_MODE_CNT, tower, tower_sz, 107UL ) );
}

/* test_consensus_decode_alpenglow: a history at the cached tip is taken
   when its link_seq is newer, the first frame pins the mode, and a tower
   still may not change bytes at the same tip. */
static void
test_consensus_decode_alpenglow( void ) {
  fd_failover_hello_t peer = {
    .term    = 7UL,
    .role    = FD_FAILOVER_ROLE_ACTIVE,
    .boot_id = 11UL,
  };

  uchar state_a[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar state_b[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar state_c[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar state_d[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar state_e[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong state_a_sz = make_hist( state_a, 4UL,   8UL,   10UL,  6UL, 0U );
  ulong state_b_sz = make_hist( state_b, 4UL,   8UL,   10UL,  6UL, AG_HIST_FLAG_RETIRED ); /* a final vote on the tip */
  ulong state_c_sz = make_hist( state_c, 4UL,   8UL,   9UL,   5UL, 0U );
  ulong state_d_sz = make_hist( state_d, 4UL,   8UL,   11UL,  7UL, 0U );
  ulong state_e_sz = make_hist( state_e, 100UL, 108UL, 110UL, 4UL, 0U );
  FD_TEST( state_a_sz==state_b_sz && !fd_memeq( state_a, state_b, state_a_sz ) );

  uchar payload[ sizeof(fd_failover_consensus_state_t)+FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 10UL, 10UL, state_a, state_a_sz );

  fd_failover_consensus_cache_t cache = {0};
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( cache.valid && cache.msg.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( cache.msg.link_seq==10UL && cache.msg.vote_slot==10UL && cache.peer_boot_id==11UL );
  FD_TEST( (ulong)cache.msg.state_len==state_a_sz && fd_memeq( cache.state, state_a, state_a_sz ) );

  /* Same tip, new bytes, newer link_seq: the history moved without its
     tip moving. */
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 11UL, 10UL, state_b, state_b_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.link_seq==11UL && fd_memeq( cache.state, state_b, state_b_sz ) );

  /* The same link_seq again, only with the same bytes. */
  fd_failover_consensus_cache_t before = cache;
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 11UL, 10UL, state_a, state_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );

  /* An older link_seq, an older tip and a mode change are all refused. */
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 10UL, 10UL, state_a, state_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 12UL, 9UL, state_c, state_c_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  uchar tower_a[ FD_FAILOVER_TOWER_STATE_MAX ];
  uchar tower_b[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong tower_a_sz = make_tower( tower_a, 100UL, 5UL, 2UL ); /* votes end at 107 */
  ulong tower_b_sz = make_tower( tower_b, 100UL, 6UL, 1UL ); /* other lockouts, same tip */
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, 7UL, 12UL, 107UL, tower_a, tower_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );

  /* The lag reads the cached tip whatever the mode. */
  fd_failover_status_t status = { .term=7UL, .last_vote_slot=14UL };
  FD_TEST( fd_failover_replication_lag( 1, &status, 11UL, &cache )==4UL );
  status.last_vote_slot = 10UL;
  FD_TEST( fd_failover_replication_lag( 1, &status, 11UL, &cache )==0UL );

  /* A newer tip moves the cache on as before. */
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 12UL, 11UL, state_d, state_d_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.vote_slot==11UL && cache.msg.link_seq==12UL );

  /* A tower cache pins its mode too, and at the same tip a tower may not
     change bytes, a new tower vote always raises the tip. */
  fd_failover_consensus_cache_t tower_cache = {0};
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, 7UL, 1UL, 107UL, tower_a, tower_a_sz );
  FD_TEST( fd_failover_consensus_decode( &tower_cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( tower_cache.msg.mode==(uchar)FD_FAILOVER_MODE_TOWER );
  before = tower_cache;
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, 7UL, 2UL, 107UL, tower_b, tower_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &tower_cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 2UL, 110UL, state_e, state_e_sz );
  FD_TEST( !fd_failover_consensus_decode( &tower_cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &tower_cache, &before, sizeof(tower_cache) ) );
}

/* test_consensus_final_check_alpenglow: a final history at the cached
   tip is ordered by link_seq alone, and a final tower at the cached tip
   must still be byte for byte the streamed one. */
static void
test_consensus_final_check_alpenglow( void ) {
  uchar state_a[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar state_b[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar state_c[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong state_a_sz = make_hist( state_a, 4UL, 8UL, 10UL, 6UL, 0U );
  ulong state_b_sz = make_hist( state_b, 4UL, 8UL, 10UL, 6UL, AG_HIST_FLAG_RETIRED );
  ulong state_c_sz = make_hist( state_c, 4UL, 8UL, 9UL,  5UL, 0U );

  fd_failover_consensus_cache_t cache = {0};
  cache.valid         = 1;
  cache.peer_boot_id  = 11UL;
  cache.msg.term      = 7UL;
  cache.msg.link_seq  = 19UL;
  cache.msg.vote_slot = 10UL;
  cache.msg.mode      = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  cache.msg.state_len = (ushort)state_a_sz;
  fd_memcpy( cache.state, state_a, state_a_sz );

  FD_TEST(  fd_failover_consensus_final_check( &cache, 11UL, 7UL, 20UL, 10UL, state_b, state_b_sz ) );
  FD_TEST(  fd_failover_consensus_final_check( &cache, 11UL, 7UL, 20UL, 10UL, state_a, state_a_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 7UL, 19UL, 10UL, state_b, state_b_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 7UL, 18UL, 10UL, state_b, state_b_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 7UL, 20UL, 9UL,  state_c, state_c_sz ) );
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 6UL, 20UL, 10UL, state_b, state_b_sz ) );
  /* Another boot of the peer restarts its link_seq, so only the tip and
     the term order the two. */
  FD_TEST(  fd_failover_consensus_final_check( &cache, 12UL, 7UL, 0UL,  10UL, state_b, state_b_sz ) );

  cache.msg.mode = (uchar)FD_FAILOVER_MODE_TOWER;
  FD_TEST( !fd_failover_consensus_final_check( &cache, 11UL, 7UL, 20UL, 10UL, state_b, state_b_sz ) );
  FD_TEST(  fd_failover_consensus_final_check( &cache, 11UL, 7UL, 20UL, 10UL, state_a, state_a_sz ) );
}

/* test_consensus_decode_mode_mismatch: the decoder runs in one mode and
   a frame whose mode byte says otherwise is refused, a tower under an
   alpenglow decoder and a history under a tower one, before anything is
   cached and after, with the cache left as it was.  The same frames are
   taken under their own mode. */
static void
test_consensus_decode_mode_mismatch( void ) {
  fd_failover_hello_t peer = {
    .term    = 7UL,
    .role    = FD_FAILOVER_ROLE_ACTIVE,
    .boot_id = 11UL,
  };

  uchar tower_a[ FD_FAILOVER_TOWER_STATE_MAX ];
  uchar tower_b[ FD_FAILOVER_TOWER_STATE_MAX ];
  uchar hist_a [ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  uchar hist_b [ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong tower_a_sz = make_tower( tower_a, 100UL, 5UL, 2UL );            /* votes end at 107 */
  ulong tower_b_sz = make_tower( tower_b, 100UL, 5UL, 4UL );            /* votes end at 109 */
  ulong hist_a_sz  = make_hist( hist_a, 100UL, 108UL, 110UL, 4UL, 0U ); /* tip 110 */
  ulong hist_b_sz  = make_hist( hist_b, 100UL, 108UL, 111UL, 5UL, 0U ); /* tip 111 */

  uchar payload[ sizeof(fd_failover_consensus_state_t)+FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong payload_sz;

  /* Nothing cached yet, the wrong mode is refused and the cache stays
     empty. */
  fd_failover_consensus_cache_t empty = {0};
  fd_failover_consensus_cache_t cache = {0};
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, 7UL, 1UL, 107UL, tower_a, tower_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &empty, sizeof(cache) ) );
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 1UL, 110UL, hist_a, hist_a_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &empty, sizeof(cache) ) );

  /* A tower cache, then a newer tower the alpenglow decoder will not
     take and the tower decoder does. */
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, 7UL, 1UL, 107UL, tower_a, tower_a_sz );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.valid && cache.msg.mode==(uchar)FD_FAILOVER_MODE_TOWER && cache.msg.vote_slot==107UL );
  fd_failover_consensus_cache_t before = cache;
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_TOWER, 7UL, 2UL, 109UL, tower_b, tower_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &cache, &before, sizeof(cache) ) );
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( cache.msg.vote_slot==109UL && cache.msg.link_seq==2UL );

  /* The other way round from a history cache. */
  fd_failover_consensus_cache_t ag_cache = {0};
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 1UL, 110UL, hist_a, hist_a_sz );
  FD_TEST( fd_failover_consensus_decode( &ag_cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( ag_cache.valid && ag_cache.msg.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && ag_cache.msg.vote_slot==110UL );
  before = ag_cache;
  payload_sz = make_consensus_mode( payload, FD_FAILOVER_MODE_ALPENGLOW, 7UL, 2UL, 111UL, hist_b, hist_b_sz );
  FD_TEST( !fd_failover_consensus_decode( &ag_cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_TOWER, &peer, payload, payload_sz ) );
  FD_TEST( fd_memeq( &ag_cache, &before, sizeof(ag_cache) ) );
  FD_TEST( fd_failover_consensus_decode( &ag_cache, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_MODE_ALPENGLOW, &peer, payload, payload_sz ) );
  FD_TEST( ag_cache.msg.vote_slot==111UL && ag_cache.msg.link_seq==2UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_status_decode();
  test_consensus_decode();
  test_consensus_final_check();
  test_state_tip_check();
  test_consensus_decode_alpenglow();
  test_consensus_final_check_alpenglow();
  test_consensus_decode_mode_mismatch();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
