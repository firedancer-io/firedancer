#include "fd_failover_proto.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../choreo/votor/ag_hist.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/fd_util.h"

static ulong expected[ 2 ][ FD_FAILOVER_SESSION_CNT ][ FD_FAILOVER_EV_CNT ];

static void
build_expected( void ) {
  int lost[] = { FD_FAILOVER_EV_LINK_LOST, FD_FAILOVER_EV_TIMEOUT, FD_FAILOVER_EV_HELLO_FATAL };
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) expected[ dial_peer ][ s ][ e ] = s;
    }
  }
  /* Listener, candidate sockets do not change the state. */
  expected[ 0 ][ FD_FAILOVER_SESSION_LISTENING ][ FD_FAILOVER_EV_HELLO_OK ] = FD_FAILOVER_SESSION_PAIRED;
  for( ulong i=0UL; i<3UL; i++ ) expected[ 0 ][ FD_FAILOVER_SESSION_PAIRED ][ lost[ i ] ] = FD_FAILOVER_SESSION_LISTENING;
  /* Dialer. */
  expected[ 1 ][ FD_FAILOVER_SESSION_BACKOFF ][ FD_FAILOVER_EV_RETRY     ] = FD_FAILOVER_SESSION_DIALING;
  expected[ 1 ][ FD_FAILOVER_SESSION_DIALING ][ FD_FAILOVER_EV_CONNECTED ] = FD_FAILOVER_SESSION_HELLO;
  expected[ 1 ][ FD_FAILOVER_SESSION_HELLO   ][ FD_FAILOVER_EV_HELLO_OK  ] = FD_FAILOVER_SESSION_PAIRED;
  for( ulong i=0UL; i<3UL; i++ ) {
    expected[ 1 ][ FD_FAILOVER_SESSION_DIALING ][ lost[ i ] ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ 1 ][ FD_FAILOVER_SESSION_HELLO   ][ lost[ i ] ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ 1 ][ FD_FAILOVER_SESSION_PAIRED  ][ lost[ i ] ] = FD_FAILOVER_SESSION_BACKOFF;
  }
}

static void
test_session_exhaustive( void ) {
  build_expected();
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        FD_TEST( fd_failover_session_step( s, dial_peer, e )==expected[ dial_peer ][ s ][ e ] );
      }
    }
  }
  FD_LOG_NOTICE(( "pass: test_session_exhaustive" ));
}

static void
test_session_properties( void ) {
  /* PAIRED is reachable only through HELLO_OK */
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      if( s==FD_FAILOVER_SESSION_PAIRED ) continue;
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        if( e==FD_FAILOVER_EV_HELLO_OK ) continue;
        FD_TEST( fd_failover_session_step( s, dial_peer, e )!=FD_FAILOVER_SESSION_PAIRED );
      }
    }
  }

  /* From its resting state the listener only reaches LISTENING and
     PAIRED, the dialer only BACKOFF, DIALING, HELLO and PAIRED. */
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    int reachable[ FD_FAILOVER_SESSION_CNT ] = {0};
    ulong queue[ FD_FAILOVER_SESSION_CNT ];
    ulong head = 0UL, tail = 0UL;
    ulong init = fd_failover_session_init( dial_peer );
    reachable[ init ] = 1; queue[ tail++ ] = init;
    while( head<tail ) {
      ulong s = queue[ head++ ];
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        ulong n = fd_failover_session_step( s, dial_peer, e );
        if( !reachable[ n ] ) { reachable[ n ] = 1; queue[ tail++ ] = n; }
      }
    }
    FD_TEST( reachable[ FD_FAILOVER_SESSION_PAIRED ] );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_LISTENING ]==!dial_peer );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_BACKOFF   ]==!!dial_peer );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_DIALING   ]==!!dial_peer );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_HELLO     ]==!!dial_peer );
  }
  FD_TEST( fd_failover_session_init( 0 )==FD_FAILOVER_SESSION_LISTENING );
  FD_TEST( fd_failover_session_init( 1 )==FD_FAILOVER_SESSION_BACKOFF );

  /* Out of range inputs change nothing */
  FD_TEST( fd_failover_session_step( 99UL, 1, FD_FAILOVER_EV_RETRY )==99UL );
  FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_BACKOFF, 2, FD_FAILOVER_EV_RETRY )==FD_FAILOVER_SESSION_BACKOFF );
  FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_PAIRED, 1, 99 )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_PAIRED, 1, -1 )==FD_FAILOVER_SESSION_PAIRED );

  FD_LOG_NOTICE(( "pass: test_session_properties" ));
}

static void
fill_hello( fd_failover_hello_t * h,
            uchar                 junk,
            uchar                 staked,
            uchar                 vote,
            uchar                 role ) {
  fd_memset( h, 0, sizeof(fd_failover_hello_t) );
  h->version = (ushort)FD_FAILOVER_VERSION;
  fd_memset( h->junk_pubkey,   junk,   32UL );
  fd_memset( h->staked_pubkey, staked, 32UL );
  fd_memset( h->vote_account,  vote,   32UL );
  h->role    = role;
  h->mode    = (uchar)FD_FAILOVER_MODE_TOWER;
  h->boot_id = 0x1000UL+junk;
}

static void
test_hello_checks( void ) {
  fd_failover_hello_t self;
  fd_failover_hello_t peer;

  /* A well formed pair passes */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );
  FD_TEST( fd_failover_hello_check( &peer, &self )==FD_FAILOVER_HELLO_OK );

  fill_hello( &peer, 0x02, 0xAA, 0xBB, 2U );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_ROLE );

  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );

  /* Version mismatch */
  peer.version = (ushort)( FD_FAILOVER_VERSION+1U );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_VERSION );
  peer.version = (ushort)FD_FAILOVER_VERSION;

  /* Unknown or different consensus mode, on either side */
  peer.mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_MODE );
  FD_TEST( fd_failover_hello_check( &peer, &self )==FD_FAILOVER_HELLO_ERR_MODE );
  self.mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_MODE );
  self.mode = (uchar)FD_FAILOVER_MODE_TOWER;
  peer.mode = (uchar)FD_FAILOVER_MODE_TOWER;

  /* Zero boot_id on either side */
  peer.boot_id = 0UL;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_BOOT_ID );
  FD_TEST( fd_failover_hello_check( &peer, &self )==FD_FAILOVER_HELLO_ERR_BOOT_ID );
  peer.boot_id = 1UL;

  /* Staked identity mismatch */
  fill_hello( &peer, 0x02, 0xAC, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_STAKED );

  /* Vote account mismatch */
  fill_hello( &peer, 0x02, 0xAA, 0xBC, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_VOTE_ACCT );

  /* Junk identity collision */
  fill_hello( &peer, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_JUNK_EQ );

  /* Junk equal to staked on either side */
  fill_hello( &peer, 0xAA, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_JUNK_STAKE );
  fill_hello( &self, 0xAA, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_JUNK_STAKE );

  /* Both sides claiming active */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_BOTH_ACT );
  FD_TEST( fd_failover_hello_check( &peer, &self )==FD_FAILOVER_HELLO_ERR_BOTH_ACT );

  /* Reset the identities for the remaining compatibility checks. */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );

  /* A different commit is fine */
  peer.commit[ 0 ] = 1;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  /* member_cert is not part of the check */
  peer.member_cert[ 0 ] = 1;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  /* Both nodes may remain standby until an operator promotes one */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  FD_LOG_NOTICE(( "pass: test_hello_checks" ));
}

/* test_member_cert: the staked key's signature over the prefix and the
   junk key passes, any other key, junk key or signature does not. */
static void
test_member_cert( void ) {
  fd_sha512_t sha[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  uchar staked[ 64 ] = { 9 };
  uchar junk  [ 64 ] = { 1 };
  fd_ed25519_public_from_private( staked+32, staked, sha );
  fd_ed25519_public_from_private( junk+32,   junk,   sha );

  uchar msg[ 48 ];
  fd_failover_member_cert_msg( msg, junk+32 );
  FD_TEST( fd_memeq( msg, "FD_FAILOVER_MBR1", 16UL ) && fd_memeq( msg+16, junk+32, 32UL ) );

  fd_failover_hello_t hello;
  fd_memset( &hello, 0, sizeof(hello) );
  fd_memcpy( hello.junk_pubkey,   junk+32,   32UL );
  fd_memcpy( hello.staked_pubkey, staked+32, 32UL );
  fd_ed25519_sign( hello.member_cert, msg, sizeof(msg), staked+32, staked, sha );
  FD_TEST( fd_failover_member_cert_check( &hello, sha )==FD_FAILOVER_HELLO_OK );

  fd_failover_hello_t bad = hello;
  bad.member_cert[ 0 ] ^= 1;
  FD_TEST( fd_failover_member_cert_check( &bad, sha )==FD_FAILOVER_HELLO_ERR_CERT );
  bad = hello;
  bad.junk_pubkey[ 0 ] ^= 1;
  FD_TEST( fd_failover_member_cert_check( &bad, sha )==FD_FAILOVER_HELLO_ERR_CERT );
  bad = hello;
  fd_memcpy( bad.staked_pubkey, junk+32, 32UL );
  FD_TEST( fd_failover_member_cert_check( &bad, sha )==FD_FAILOVER_HELLO_ERR_CERT );
  bad = hello;
  fd_ed25519_sign( bad.member_cert, msg, sizeof(msg), junk+32, junk, sha );
  FD_TEST( fd_failover_member_cert_check( &bad, sha )==FD_FAILOVER_HELLO_ERR_CERT );

  FD_LOG_NOTICE(( "pass: test_member_cert" ));
}

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

/* test_demoted_decode: an encoded DEMOTED decodes back, a bad size,
   mode, tip or tower does not and leaves out as it was. */
static void
test_demoted_decode( void ) {
  uchar state[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong state_sz = make_tower( state, 100UL, 5UL, 2UL );

  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX+1UL ];
  ulong payload_sz = fd_failover_demoted_encode( payload, 7UL, 11UL, 107UL, state, state_sz );
  FD_TEST( payload_sz==sizeof(fd_failover_demoted_t)+state_sz );

  fd_failover_demoted_t out;
  FD_TEST( fd_failover_demoted_decode( &out, payload, payload_sz ) );
  FD_TEST( out.handoff_id==7UL && out.target_boot_id==11UL && out.last_vote_slot==107UL );
  FD_TEST( out.mode==FD_FAILOVER_MODE_TOWER );
  FD_TEST( (ulong)out.state_len==state_sz );
  FD_TEST( fd_memeq( payload+sizeof(fd_failover_demoted_t), state, state_sz ) );

  /* The encoder refuses an empty or oversized tower */
  FD_TEST( !fd_failover_demoted_encode( payload, 8UL, 11UL, 107UL, state, 0UL ) );
  FD_TEST( !fd_failover_demoted_encode( payload, 8UL, 11UL, 107UL, state, FD_FAILOVER_TOWER_STATE_MAX+1UL ) );

  fd_failover_demoted_t before = out;
  fd_failover_demoted_t * hdr  = (fd_failover_demoted_t *)payload;

  /* Size has to match state_len exactly */
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz-1UL ) );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz+1UL ) );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, sizeof(fd_failover_demoted_t)-1UL ) );
  hdr->state_len = 0;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, sizeof(fd_failover_demoted_t) ) );
  hdr->state_len = (ushort)( FD_FAILOVER_TOWER_STATE_MAX+1UL );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, FD_FAILOVER_DEMOTED_PAYLOAD_MAX+1UL ) );
  hdr->state_len = (ushort)state_sz;

  /* A wrong state_len with the right payload size */
  ushort bad_len[ 3 ] = { (ushort)( state_sz-1UL ), (ushort)( state_sz+1UL ), USHORT_MAX };
  for( ulong i=0UL; i<3UL; i++ ) {
    hdr->state_len = bad_len[ i ];
    FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  }
  hdr->state_len = (ushort)state_sz;

  /* Trailing bytes after the tower */
  payload[ payload_sz ] = 0;
  hdr->state_len = (ushort)( state_sz+1UL );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz+1UL ) );
  hdr->state_len = (ushort)state_sz;

  hdr->mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->mode = (uchar)FD_FAILOVER_MODE_TOWER;

  /* The tower has to end at last_vote_slot */
  hdr->last_vote_slot = 105UL;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->last_vote_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->last_vote_slot = 107UL;
  FD_TEST( fd_memeq( &out, &before, sizeof(out) ) );
  FD_TEST( fd_failover_demoted_decode( &out, payload, payload_sz ) );

  /* A tower that parses but has no votes */
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root = 100UL;
  ulong empty_sz = 0UL;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, state, FD_FAILOVER_TOWER_STATE_MAX, &empty_sz ) );
  ulong bad_sz = fd_failover_demoted_encode( payload, 9UL, 11UL, 100UL, state, empty_sz );
  FD_TEST( bad_sz );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, bad_sz ) );

  /* A tower with a vote past the lockout of the vote below it */
  serde.lockouts_cnt                     = 2U;
  serde.lockouts[ 0 ].offset             = 5UL;
  serde.lockouts[ 0 ].confirmation_count = 2U;
  serde.lockouts[ 1 ].offset             = 5UL;
  serde.lockouts[ 1 ].confirmation_count = 1U;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, state, FD_FAILOVER_TOWER_STATE_MAX, &bad_sz ) );
  bad_sz = fd_failover_demoted_encode( payload, 9UL, 11UL, 110UL, state, bad_sz );
  FD_TEST( bad_sz );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, bad_sz ) );

  /* Garbage */
  fd_memset( state, 0xFF, FD_FAILOVER_TOWER_STATE_MAX );
  bad_sz = fd_failover_demoted_encode( payload, 9UL, 11UL, 107UL, state, 64UL );
  FD_TEST( bad_sz );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, bad_sz ) );

  FD_TEST( fd_memeq( &out, &before, sizeof(out) ) );

  FD_LOG_NOTICE(( "pass: test_demoted_decode" ));
}

/* Notar votes on the rec_cnt slots ending at tip, serialized. */
static ulong
make_hist( uchar * state,
           ulong   anchor,
           ulong   tip,
           ulong   rec_cnt ) {
  static ag_hist_t hist;
  fd_memset( &hist, 0, sizeof(hist) );
  hist.anchor           = anchor;
  hist.last_leader_slot = tip-4UL;
  hist.vote_bound       = ULONG_MAX;
  hist.rec_cnt          = rec_cnt;
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    hist.rec[ i ].slot  = tip-rec_cnt+1UL+i;
    hist.rec[ i ].flags = (uchar)( AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR );
    fd_memset( hist.rec[ i ].notar_hash, (int)(0x10UL+i), sizeof(ag_block_hash_t) );
  }
  ulong state_sz = 0UL;
  FD_TEST( !ag_hist_ser( &hist, state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &state_sz ) );
  return state_sz;
}

/* test_alpenglow_mode: HELLO tells the two modes apart.  An Alpenglow
   DEMOTED decodes only when its history ends at last_vote_slot and its
   mode byte matches its state. */
static void
test_alpenglow_mode( void ) {
  fd_failover_hello_t self;
  fd_failover_hello_t peer;
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  peer.mode = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_MODE );
  FD_TEST( fd_failover_hello_check( &peer, &self )==FD_FAILOVER_HELLO_ERR_MODE );
  self.mode = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  /* 122 notar records are far past the tower bound. */
  static uchar state  [ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  static uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX+1UL ];
  ulong state_sz = make_hist( state, 80UL, 200UL, 122UL );
  FD_TEST( state_sz==AG_HIST_HDR_SZ+122UL*AG_HIST_REC_MAX_SZ && state_sz>FD_FAILOVER_TOWER_STATE_MAX );
  ulong payload_sz = fd_failover_demoted_encode_alpenglow( payload, 7UL, 11UL, 200UL, state, state_sz );
  FD_TEST( payload_sz==sizeof(fd_failover_demoted_t)+state_sz && payload_sz<=FD_FAILOVER_DEMOTED_PAYLOAD_MAX );

  fd_failover_demoted_t out;
  FD_TEST( fd_failover_demoted_decode( &out, payload, payload_sz ) );
  FD_TEST( out.handoff_id==7UL && out.target_boot_id==11UL && out.last_vote_slot==200UL );
  FD_TEST( out.mode==FD_FAILOVER_MODE_ALPENGLOW );
  FD_TEST( (ulong)out.state_len==state_sz );
  FD_TEST( fd_memeq( payload+sizeof(fd_failover_demoted_t), state, state_sz ) );

  /* The encoder refuses an empty or oversized history, the tower
     encoder refuses a history this long. */
  FD_TEST( !fd_failover_demoted_encode_alpenglow( payload, 8UL, 11UL, 200UL, state, 0UL ) );
  FD_TEST( !fd_failover_demoted_encode_alpenglow( payload, 8UL, 11UL, 200UL, state, FD_FAILOVER_ALPENGLOW_STATE_MAX+1UL ) );
  FD_TEST( !fd_failover_demoted_encode( payload, 8UL, 11UL, 200UL, state, state_sz ) );
  payload_sz = fd_failover_demoted_encode_alpenglow( payload, 7UL, 11UL, 200UL, state, state_sz );

  fd_failover_demoted_t before = out;
  fd_failover_demoted_t * hdr  = (fd_failover_demoted_t *)payload;

  /* The history ends at 200, so 199 and 201 are both wrong. */
  hdr->last_vote_slot = 199UL;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->last_vote_slot = 201UL;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->last_vote_slot = 200UL;

  /* A history that does not decode, its record count runs past the
     limit. */
  uchar * rec_cnt_hi = payload+sizeof(fd_failover_demoted_t)+AG_HIST_HDR_SZ-1UL;
  uchar   saved      = *rec_cnt_hi;
  *rec_cnt_hi = 0xFFU;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  *rec_cnt_hi = saved;

  /* Trailing bytes after the history. */
  payload[ payload_sz ] = 0;
  hdr->state_len = (ushort)( state_sz+1UL );
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz+1UL ) );
  hdr->state_len = (ushort)state_sz;

  /* The same bytes under the tower mode byte. */
  hdr->mode = (uchar)FD_FAILOVER_MODE_TOWER;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->mode = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  FD_TEST( fd_memeq( &out, &before, sizeof(out) ) );
  FD_TEST( fd_failover_demoted_decode( &out, payload, payload_sz ) );

  /* And a tower under the Alpenglow mode byte. */
  uchar tower[ FD_FAILOVER_TOWER_STATE_MAX ];
  ulong tower_sz = make_tower( tower, 100UL, 5UL, 2UL );
  payload_sz = fd_failover_demoted_encode( payload, 9UL, 11UL, 107UL, tower, tower_sz );
  FD_TEST( fd_failover_demoted_decode( &out, payload, payload_sz ) );
  hdr->mode = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  FD_TEST( !fd_failover_demoted_decode( &out, payload, payload_sz ) );

  FD_LOG_NOTICE(( "pass: test_alpenglow_mode" ));
}

/* test_promote_replies: ACK and REJECTED round trip, a bad size or
   reason does not decode. */
static void
test_promote_replies( void ) {
  uchar payload[ 16 ];

  fd_failover_promote_ack_t ack;
  ulong sz = fd_failover_promote_ack_encode( payload, 42UL );
  FD_TEST( sz==sizeof(fd_failover_promote_ack_t) );
  FD_TEST( fd_failover_promote_ack_decode( &ack, payload, sz ) );
  FD_TEST( ack.handoff_id==42UL );
  FD_TEST( !fd_failover_promote_ack_decode( &ack, payload, sz-1UL ) );
  FD_TEST( !fd_failover_promote_ack_decode( &ack, payload, sz+1UL ) );

  fd_failover_promote_rejected_t rej;
  for( uint reason=FD_FAILOVER_REJECT_BUSY; reason<FD_FAILOVER_REJECT_CNT; reason++ ) {
    sz = fd_failover_promote_rejected_encode( payload, 43UL, (uchar)reason );
    FD_TEST( sz==sizeof(fd_failover_promote_rejected_t) );
    FD_TEST( fd_failover_promote_rejected_decode( &rej, payload, sz ) );
    FD_TEST( rej.handoff_id==43UL && rej.reason==reason );
  }
  FD_TEST( !fd_failover_promote_rejected_decode( &rej, payload, sz-1UL ) );
  FD_TEST( !fd_failover_promote_rejected_decode( &rej, payload, sz+1UL ) );

  FD_TEST( !fd_failover_promote_rejected_encode( payload, 43UL, (uchar)FD_FAILOVER_REJECT_NONE ) );
  FD_TEST( !fd_failover_promote_rejected_encode( payload, 43UL, (uchar)FD_FAILOVER_REJECT_CNT  ) );

  fd_failover_promote_rejected_t before = rej;
  fd_failover_promote_rejected_t bad    = { .handoff_id=44UL, .reason=(uchar)FD_FAILOVER_REJECT_NONE };
  FD_TEST( !fd_failover_promote_rejected_decode( &rej, (uchar const *)&bad, sizeof(bad) ) );
  bad.reason = (uchar)FD_FAILOVER_REJECT_CNT;
  FD_TEST( !fd_failover_promote_rejected_decode( &rej, (uchar const *)&bad, sizeof(bad) ) );
  FD_TEST( fd_memeq( &rej, &before, sizeof(rej) ) );

  FD_LOG_NOTICE(( "pass: test_promote_replies" ));
}

/* Exact sizes, unaligned payloads and all-zero id fields.  The output
   stays unchanged on failure, arbitrary refusal codes reach the binding
   and result checks in the controller. */
static void
test_handoff_messages( void ) {
  uchar payload[ 19 ];
  fd_failover_handoff_request_t request = { .handoff_id=1UL, .target_boot_id=ULONG_MAX };
  fd_failover_handoff_request_t out;
  fd_failover_handoff_result_t result = { .handoff_id=ULONG_MAX, .result=ULONG_MAX };
  fd_failover_handoff_result_t answer;
  fd_memset( &out, 0xA5, sizeof(out) );
  fd_memset( &answer, 0xA5, sizeof(answer) );
  fd_failover_handoff_request_t saved_request = out;
  fd_failover_handoff_result_t saved_result = answer;
  fd_memcpy( payload+1, &request, sizeof(request) );
  for( ulong sz=0UL; sz<=18UL; sz++ ) {
    if( sz==16UL ) continue;
    FD_TEST( !fd_failover_handoff_request_decode( &out, payload+1, sz ) );
    FD_TEST( !fd_failover_handoff_result_decode( &answer, payload+1, sz ) );
    FD_TEST( fd_memeq( &out, &saved_request, sizeof(out) ) );
    FD_TEST( fd_memeq( &answer, &saved_result, sizeof(answer) ) );
  }
  FD_TEST( fd_failover_handoff_request_decode( &out, payload+1, 16UL ) );
  FD_TEST( out.handoff_id==1UL && out.target_boot_id==ULONG_MAX );
  saved_request = out;
  for( ulong i=0UL; i<2UL; i++ ) {
    request.handoff_id = i;
    request.target_boot_id = !i;
    fd_memcpy( payload+1, &request, sizeof(request) );
    FD_TEST( !fd_failover_handoff_request_decode( &out, payload+1, 16UL ) );
    FD_TEST( fd_memeq( &out, &saved_request, sizeof(out) ) );
  }
  fd_memcpy( payload+1, &result, sizeof(result) );
  FD_TEST( fd_failover_handoff_result_decode( &answer, payload+1, 16UL ) );
  FD_TEST( answer.handoff_id==ULONG_MAX && answer.result==ULONG_MAX );
  /* A zero result code decodes, a zero handoff id does not. */
  result.result = 0UL;
  fd_memcpy( payload+1, &result, sizeof(result) );
  FD_TEST( fd_failover_handoff_result_decode( &answer, payload+1, 16UL ) );
  FD_TEST( answer.handoff_id==ULONG_MAX && !answer.result );
  saved_result = answer;
  fd_memset( payload+1, 0, 16UL );
  FD_TEST( !fd_failover_handoff_result_decode( &answer, payload+1, 16UL ) );
  FD_TEST( fd_memeq( &answer, &saved_result, sizeof(answer) ) );
  FD_LOG_NOTICE(( "pass: test_handoff_messages" ));
}

/* test_handoff_decode: requests and results need their exact size and
   nonzero ids. */
static void
test_handoff_decode( void ) {
  fd_failover_handoff_request_t request = { .handoff_id=5UL, .target_boot_id=6UL }, request_out;
  FD_TEST( fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request) ) && request_out.handoff_id==5UL );
  FD_TEST( !fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request)-1UL ) );
  request.target_boot_id = 0UL;
  FD_TEST( !fd_failover_handoff_request_decode( &request_out, (uchar const *)&request, sizeof(request) ) );

  fd_failover_handoff_result_t result = { .handoff_id=5UL }, result_out;
  FD_TEST( fd_failover_handoff_result_decode( &result_out, (uchar const *)&result, sizeof(result) ) && result_out.handoff_id==5UL );
  FD_TEST( !fd_failover_handoff_result_decode( &result_out, (uchar const *)&result, sizeof(result)+1UL ) );
  result.handoff_id = 0UL;
  FD_TEST( !fd_failover_handoff_result_decode( &result_out, (uchar const *)&result, sizeof(result) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_session_exhaustive();
  test_session_properties();
  test_hello_checks();
  test_member_cert();
  test_demoted_decode();
  test_alpenglow_mode();
  test_promote_replies();
  test_handoff_messages();
  test_handoff_decode();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
