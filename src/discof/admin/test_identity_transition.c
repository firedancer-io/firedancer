#include "fd_identity_transition.h"
#include <pthread.h>

static fd_identity_transition_t shared;
static ulong done;

static void *
writer( void * arg FD_FN_UNUSED ) {
  for( ulong i=1UL; i<=100000UL; i++ ) {
    fd_identity_record_t record;
    ulong words[FD_IDENTITY_RECORD_WORDS];
    for( ulong j=0UL; j<FD_IDENTITY_RECORD_WORDS; j++ ) words[j] = i;
    memcpy( &record, words, sizeof(record) );
    fd_identity_snapshot_write( &shared.status, &record );
  }
  __atomic_store_n( &done, 1UL, __ATOMIC_RELEASE );
  return NULL;
}

static void
test_snapshots( void ) {
  memset( &shared, 0, sizeof(shared) );
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, writer, NULL ) );
  ulong reads = 0UL;
  do {
    fd_identity_record_t record;
    if( !fd_identity_snapshot_read( &shared.status, &record ) ) continue;
    ulong words[FD_IDENTITY_RECORD_WORDS];
    memcpy( words, &record, sizeof(words) );
    for( ulong i=1UL; i<FD_IDENTITY_RECORD_WORDS; i++ ) FD_TEST( words[i]==words[0] );
    reads++;
  } while( !__atomic_load_n( &done, __ATOMIC_ACQUIRE ) );
  FD_TEST( !pthread_join( thread, NULL ) );
  FD_TEST( reads );
  __atomic_store_n( &shared.status.generation, 1UL, __ATOMIC_SEQ_CST );
  fd_identity_record_t record;
  FD_TEST( !fd_identity_snapshot_read( &shared.status, &record ) );
}

static void
test_transition( int alpenglow ) {
  memset( &shared, 0, sizeof(shared) );
  fd_identity_record_t record = { .instance = { 1UL, 2UL } };
  uchar from[32]; memset( from, 1, 32UL );
  uchar to[32];   memset( to,   2, 32UL );
  uchar vote[32]; memset( vote, 3, 32UL );
  ulong consensus = alpenglow ? FD_IDENTITY_CONSENSUS_ALPENGLOW : FD_IDENTITY_CONSENSUS_TOWER;
  fd_identity_counter_t counter = {0};
  fd_identity_submitted( &counter, 0UL );
  FD_TEST( counter.has_slot && !counter.slot );
  fd_identity_submitted( &counter, 100UL );
  fd_identity_submitted( &counter, 99UL );
  fd_identity_submitted( &counter, 100UL ); /* retry */
  fd_identity_begin( &shared, &record, from, to );
  FD_TEST( record.sequence==1UL && record.state==FD_IDENTITY_STATE_TRANSITIONING );
  fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_REPLAY, from, to, consensus, vote, NULL, ULONG_MAX );
  /* A submission after the request is included at the existing barrier. */
  fd_identity_submitted( &counter, 101UL );
  fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_VOTER, from, to, consensus,
                      vote, alpenglow ? &counter : NULL, alpenglow ? ULONG_MAX : 90UL );
  if( !alpenglow ) fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_TXSEND, from, to, consensus, NULL, &counter, ULONG_MAX );
  FD_TEST( !counter.has_slot );
  FD_TEST( record.state==FD_IDENTITY_STATE_TRANSITIONING );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.state==FD_IDENTITY_STATE_COMPLETE );
  FD_TEST( record.has_last_submitted_slot && record.last_submitted_slot==101UL );
  FD_TEST( record.has_tower_root==!alpenglow );
  FD_TEST( record.has_vote_account && !memcmp( record.vote_account, vote, 32UL ) );
  fd_identity_submitted( &counter, 500UL );
  fd_identity_record_t snapshot;
  FD_TEST( fd_identity_snapshot_read( &shared.status, &snapshot ) );
  FD_TEST( snapshot.last_submitted_slot==101UL );

  /* Stale acknowledgements cannot complete a newer sequence. */
  fd_identity_begin( &shared, &record, to, from );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.state==FD_IDENTITY_STATE_FAILED && !record.has_last_submitted_slot );

  /* A restart changes the instance, even if its sequence is reused. */
  record.instance[0]++;
  record.sequence = 0UL;
  fd_identity_begin( &shared, &record, from, to );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.state==FD_IDENTITY_STATE_FAILED );

  /* Null on a successful transition with no outbound submission. */
  memset( &counter, 0, sizeof(counter) );
  fd_identity_begin( &shared, &record, from, to );
  fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_REPLAY, from, to, consensus, vote, NULL, ULONG_MAX );
  fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_VOTER, from, to, consensus, vote, &counter, ULONG_MAX );
  if( !alpenglow ) fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_TXSEND, from, to, consensus, NULL, &counter, ULONG_MAX );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.state==FD_IDENTITY_STATE_COMPLETE && !record.has_last_submitted_slot );

  /* Migration/unknown evidence fails only the observation. */
  fd_identity_begin( &shared, &record, from, to );
  fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_REPLAY, from, to, FD_IDENTITY_CONSENSUS_UNKNOWN, vote, NULL, ULONG_MAX );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.state==FD_IDENTITY_STATE_FAILED && record.consensus==FD_IDENTITY_CONSENSUS_UNKNOWN );

  /* Same-identity commands preserve the live counter. */
  fd_identity_submitted( &counter, 200UL );
  fd_identity_begin( &shared, &record, from, from );
  fd_identity_freeze( &shared, FD_IDENTITY_FREEZE_VOTER, from, from, consensus, vote, &counter, ULONG_MAX );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.state==FD_IDENTITY_STATE_FAILED && record.error==FD_IDENTITY_ERROR_SAME_IDENTITY );
  FD_TEST( counter.has_slot && counter.slot==200UL );

  record.sequence = ULONG_MAX;
  fd_identity_begin( &shared, &record, from, to );
  fd_identity_finish( &shared, &record, alpenglow );
  FD_TEST( record.sequence==ULONG_MAX && record.state==FD_IDENTITY_STATE_FAILED );
  FD_TEST( record.error==FD_IDENTITY_ERROR_SEQUENCE );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_transition( 0 );
  test_transition( 1 );
  test_snapshots();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
