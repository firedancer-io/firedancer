#include "fd_sched_lthash.h"
#include "fd_rdisp.h" /* FD_RDISP_LTHASH_PSEUDO_TXN, FD_RDISP_MAX_WRITERS_PER_BLOCK */
#include "../../tango/tempo/fd_tempo.h" /* fd_tempo_tick_per_ns */
#include "../../util/tmpl/fd_unit_test.c"

#if FD_HAS_HOSTED
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_CRIT_EXIT (42)

static void
test_crit_handler( int sig ) {
  (void)sig;
  _exit( TEST_CRIT_EXIT );
}

/* TEST_EXPECT_CRIT checks that call CRITs by running it in a child
   process.  The child silences the log and turns the abort into a
   plain exit, so a pass prints nothing and dumps no core. */

#define TEST_EXPECT_CRIT( call ) do {                                          \
    pid_t _pid = fork();                                                       \
    FD_TEST( _pid>=0 );                                                        \
    if( !_pid ) {                                                              \
      fd_log_level_logfile_set( 6 );                                           \
      fd_log_level_stderr_set ( 6 );                                           \
      fd_log_level_core_set   ( 5 );                                           \
      FD_TEST( signal( SIGABRT, test_crit_handler )!=SIG_ERR );                \
      (call);                                                                  \
      _exit( 0 );                                                              \
    }                                                                          \
    int _status = 0;                                                           \
    FD_TEST( waitpid( _pid, &_status, 0 )==_pid );                             \
    FD_TEST( WIFEXITED( _status ) && WEXITSTATUS( _status )==TEST_CRIT_EXIT ); \
  } while(0)
#endif

#define TEST_ENTRY_MAX (1024UL)
#define TEST_HASH_MAX     (8UL)

#define TEST_CANARY ((uchar)0xA5)

static uchar test_mem[ 1UL<<20 ] __attribute__((aligned(128UL)));

static fd_sched_lthash_t *
test_lthash_new( void ) {
  ulong footprint = fd_sched_lthash_footprint( TEST_ENTRY_MAX, TEST_HASH_MAX );
  FD_TEST( footprint && footprint<=sizeof(test_mem) );
  FD_TEST( fd_ulong_is_aligned( (ulong)test_mem, fd_sched_lthash_align() ) );
  memset( test_mem, TEST_CANARY, sizeof(test_mem) );
  fd_sched_lthash_t * l = fd_sched_lthash_join( fd_sched_lthash_new( test_mem, TEST_ENTRY_MAX, TEST_HASH_MAX, 1234UL ) );
  FD_TEST( l );
  return l;
}

/* test_lthash_check_tail checks that nothing wrote past the footprint. */

static void
test_lthash_check_tail( void ) {
  for( ulong i=fd_sched_lthash_footprint( TEST_ENTRY_MAX, TEST_HASH_MAX ); i<sizeof(test_mem); i++ ) FD_TEST( test_mem[ i ]==TEST_CANARY );
}

/* test_check_free_slots acquires every free slot, checks that they and
   the slots in the held bitset are pairwise distinct, which a double
   release would break, and frees them again. */

static void
test_check_free_slots( fd_sched_lthash_t * l,
                       ulong               held ) {
  ulong cnt = fd_sched_lthash_spec_free_cnt( l );
  FD_TEST( cnt<=TEST_HASH_MAX );
  uint idx[ TEST_HASH_MAX ];
  for( ulong i=0UL; i<cnt; i++ ) {
    idx[ i ] = fd_sched_lthash_spec_acquire( l );
    FD_TEST( idx[ i ]<TEST_HASH_MAX && !fd_ulong_extract_bit( held, (int)idx[ i ] ) );
    held = fd_ulong_set_bit( held, (int)idx[ i ] );
  }
  FD_TEST( fd_sched_lthash_spec_acquire( l )==UINT_MAX );
  for( ulong i=0UL; i<cnt; i++ ) fd_sched_lthash_spec_release( l, idx[ i ] );
}

/* test_acct returns a distinct account address for each seed. */

static fd_acct_addr_t
test_acct( ulong seed ) {
  fd_acct_addr_t acct;
  for( ulong i=0UL; i<4UL; i++ ) FD_STORE( ulong, acct.b+8UL*i, fd_ulong_hash( (seed<<2)|i ) );
  return acct;
}

static void
test_value( fd_lthash_value_t * v,
            ulong               seed ) {
  for( ulong i=0UL; i<FD_LTHASH_LEN_ELEMS; i++ ) v->words[ i ] = (ushort)fd_ulong_hash( seed+i );
}

FD_UNIT_TEST( footprint ) {
  FD_TEST( fd_ulong_is_pow2( fd_sched_lthash_align() ) );
  FD_TEST( fd_sched_lthash_align()>=FD_LTHASH_ALIGN );
  FD_TEST( !fd_sched_lthash_footprint( 0UL,                 TEST_HASH_MAX       ) );
  FD_TEST( !fd_sched_lthash_footprint( (ulong)UINT_MAX/2UL+1UL, TEST_HASH_MAX   ) ); /* two entry regions per lane */
  FD_TEST( !fd_sched_lthash_footprint( TEST_ENTRY_MAX,      (ulong)UINT_MAX+1UL ) );
  FD_TEST(  fd_sched_lthash_footprint( TEST_ENTRY_MAX,      0UL                 ) );
  FD_TEST(  fd_sched_lthash_footprint( (ulong)UINT_MAX/2UL, (ulong)UINT_MAX     ) );

  ulong footprint = fd_sched_lthash_footprint( FD_RDISP_MAX_WRITERS_PER_BLOCK, 8192UL );
  FD_TEST( footprint && fd_ulong_is_aligned( footprint, fd_sched_lthash_align() ) );
  FD_LOG_NOTICE(( "footprint( entry_max %lu, hash_max 8192 ) = %lu bytes", FD_RDISP_MAX_WRITERS_PER_BLOCK, footprint ));
}

FD_UNIT_TEST( new_join ) {
  /* new and join log a warning for each bad argument, so silence the
     log meanwhile. */
  int level_logfile = fd_log_level_logfile();
  int level_stderr  = fd_log_level_stderr();
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set ( 4 );
  FD_TEST( !fd_sched_lthash_new( NULL,        TEST_ENTRY_MAX,      TEST_HASH_MAX,       1UL ) );
  FD_TEST( !fd_sched_lthash_new( test_mem+64, TEST_ENTRY_MAX,      TEST_HASH_MAX,       1UL ) ); /* misaligned */
  FD_TEST( !fd_sched_lthash_new( test_mem,    0UL,                 TEST_HASH_MAX,       1UL ) );
  FD_TEST( !fd_sched_lthash_new( test_mem,    (ulong)UINT_MAX+1UL, TEST_HASH_MAX,       1UL ) );
  FD_TEST( !fd_sched_lthash_new( test_mem,    TEST_ENTRY_MAX,      (ulong)UINT_MAX+1UL, 1UL ) );
  FD_TEST( !fd_sched_lthash_join( NULL ) );
  fd_log_level_logfile_set( level_logfile );
  fd_log_level_stderr_set ( level_stderr  );
}

FD_UNIT_TEST( lanes ) {
  fd_sched_lthash_t * l = test_lthash_new();
  for( ulong lane=0UL; lane<FD_SCHED_LTHASH_LANE_CNT; lane++ ) {
    FD_TEST( fd_sched_lthash_lane_bank( l, lane )==ULONG_MAX );
    FD_TEST( fd_sched_lthash_lane_entry_cnt ( l, lane )==0UL );
  }

  ulong bank[ FD_SCHED_LTHASH_LANE_CNT ] = { 7UL, 9UL, 11UL, 13UL };
  for( ulong lane=0UL; lane<FD_SCHED_LTHASH_LANE_CNT; lane++ ) fd_sched_lthash_lane_claim( l, lane, bank[ lane ] );
  fd_sched_lthash_lane_claim( l, 0UL, 7UL ); /* reclaiming for the same bank is a no-op */
  for( ulong lane=0UL; lane<FD_SCHED_LTHASH_LANE_CNT; lane++ ) FD_TEST( fd_sched_lthash_lane_bank( l, lane )==bank[ lane ] );

  /* Two accounts in lane 0, the first of them again in lane 1, the
     second in lane 2, and those two plus a third in lane 3. */
  fd_acct_addr_t acct[ 3 ] = { test_acct( 1UL ), test_acct( 2UL ), test_acct( 3UL ) };
  static int const has[ FD_SCHED_LTHASH_LANE_CNT ][ 3 ] = { { 1, 1, 0 }, { 1, 0, 0 }, { 0, 1, 0 }, { 1, 1, 1 } };

  fd_sched_lthash_entry_t * ent[ FD_SCHED_LTHASH_LANE_CNT ][ 3 ];
  fd_sched_lthash_entry_t * all[ FD_SCHED_LTHASH_LANE_CNT*3UL ];
  ulong                     all_cnt = 0UL;
  memset( ent, 0, sizeof(ent) );
  for( ulong lane=0UL; lane<FD_SCHED_LTHASH_LANE_CNT; lane++ ) {
    for( ulong k=0UL; k<3UL; k++ ) {
      if( !has[ lane ][ k ] ) continue;
      FD_TEST( !fd_sched_lthash_query( l, lane, acct+k ) );
      fd_sched_lthash_entry_t * e = fd_sched_lthash_insert( l, lane, acct+k );
      FD_TEST( e );
      FD_TEST( !memcmp( e->acct.b, acct[ k ].b, 32UL ) );
      FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_QUEUED );
      FD_TEST( e->add_state==FD_SCHED_LTHASH_ADD_NONE   );
      FD_TEST( e->spec_idx==UINT_MAX );
      FD_TEST( e->ptxn_idx==0U       );
      FD_TEST( e->q_next  ==UINT_MAX );
      FD_TEST( e->bank_idx==(uint)bank[ lane ] );
      ulong idx = fd_sched_lthash_entry_idx( l, lane, e );
      FD_TEST( idx<TEST_ENTRY_MAX );
      FD_TEST( fd_sched_lthash_entry( l, lane, idx )==e );
      ent[ lane ][ k ]  = e;
      all[ all_cnt++ ] = e;
    }
  }

  /* Entries are distinct, and queries and counts are lane-scoped. */
  for( ulong i=0UL; i<all_cnt; i++ ) for( ulong j=i+1UL; j<all_cnt; j++ ) FD_TEST( all[ i ]!=all[ j ] );
  for( ulong lane=0UL; lane<FD_SCHED_LTHASH_LANE_CNT; lane++ ) {
    ulong cnt = 0UL;
    for( ulong k=0UL; k<3UL; k++ ) {
      FD_TEST( fd_sched_lthash_query( l, lane, acct+k )==ent[ lane ][ k ] );
      cnt += (ulong)has[ lane ][ k ];
    }
    FD_TEST( fd_sched_lthash_lane_entry_cnt( l, lane )==cnt );
  }
  test_lthash_check_tail();
}

FD_UNIT_TEST( slots ) {
  fd_sched_lthash_t * l = test_lthash_new();
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );

  uint  idx[ TEST_HASH_MAX ];
  ulong seen = 0UL;
  for( ulong i=0UL; i<TEST_HASH_MAX; i++ ) {
    idx[ i ] = fd_sched_lthash_spec_acquire( l );
    FD_TEST( idx[ i ]<TEST_HASH_MAX );
    FD_TEST( !fd_ulong_extract_bit( seen, (int)idx[ i ] ) );
    seen = fd_ulong_set_bit( seen, (int)idx[ i ] );
    FD_TEST( fd_ulong_is_aligned( (ulong)fd_sched_lthash_spec_entry( l, idx[ i ] ), FD_LTHASH_ALIGN ) );
    FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX-1UL-i );
  }
  FD_TEST( fd_sched_lthash_spec_acquire( l )==UINT_MAX );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==0UL );

  /* Slots do not overlap. */
  for( ulong i=0UL; i<TEST_HASH_MAX; i++ ) test_value( fd_sched_lthash_spec_entry( l, idx[ i ] ), i );
  for( ulong i=0UL; i<TEST_HASH_MAX; i++ ) {
    fd_lthash_value_t v[ 1 ]; test_value( v, i );
    FD_TEST( fd_lthash_eq( fd_sched_lthash_spec_entry( l, idx[ i ] ), v ) );
  }

  fd_sched_lthash_spec_release( l, idx[ 3 ] );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==1UL );
  FD_TEST( fd_sched_lthash_spec_acquire( l )==idx[ 3 ] );
  FD_TEST( fd_sched_lthash_spec_acquire( l )==UINT_MAX );

  for( ulong i=0UL; i<TEST_HASH_MAX; i++ ) fd_sched_lthash_spec_release( l, idx[ i ] );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );
  test_lthash_check_tail();
}

/* A map released with entries is cleared a chunk at a time from later
   polls, and a claim in the middle of that has to finish the job.  The
   full clean used to compute its end as cur+max with max ULONG_MAX,
   which wraps once some entries are already clear, left the map
   CLEANING, and tripped the claim's invariant. */
FD_UNIT_TEST( map_clean_resume ) {
  fd_sched_lthash_t * l    = test_lthash_new();
  ulong               lane = 0UL;
  ulong               map  = fd_sched_lthash_lane_primary( l, lane );
  fd_sched_lthash_lane_claim( l, lane, 5UL );
  for( ulong i=0UL; i<10UL; i++ ) { fd_acct_addr_t a = test_acct( 100UL+i ); FD_TEST( fd_sched_lthash_insert( l, lane, &a ) ); }
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, lane )==10UL );

  fd_sched_lthash_map_release( l, lane, map );
  FD_TEST( fd_sched_lthash_map_state( l, lane, map )==FD_SCHED_LTHASH_MAP_CLEANING );
  FD_TEST( fd_sched_lthash_map_clean( l, lane, map, 3UL )==7UL );
  FD_TEST( fd_sched_lthash_map_state( l, lane, map )==FD_SCHED_LTHASH_MAP_CLEANING );
  fd_sched_lthash_map_claim( l, lane, map, 6UL );
  FD_TEST( fd_sched_lthash_map_state( l, lane, map )==FD_SCHED_LTHASH_MAP_LIVE );
  FD_TEST( fd_sched_lthash_map_bank ( l, lane, map )==6UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, lane )==0UL );
  for( ulong i=0UL; i<10UL; i++ ) { fd_acct_addr_t a = test_acct( 100UL+i ); FD_TEST( !fd_sched_lthash_query( l, lane, &a ) ); }
  fd_acct_addr_t b = test_acct( 100UL );
  FD_TEST( fd_sched_lthash_insert( l, lane, &b ) && fd_sched_lthash_query( l, lane, &b ) );

  /* The same resumption through a full clean on its own. */
  for( ulong i=1UL; i<5UL; i++ ) { fd_acct_addr_t a = test_acct( 100UL+i ); FD_TEST( fd_sched_lthash_insert( l, lane, &a ) ); }
  fd_sched_lthash_map_release( l, lane, map );
  FD_TEST( fd_sched_lthash_map_clean( l, lane, map, 2UL )==3UL );
  FD_TEST( fd_sched_lthash_map_clean( l, lane, map, ULONG_MAX )==0UL );
  FD_TEST( fd_sched_lthash_map_state( l, lane, map )==FD_SCHED_LTHASH_MAP_FREE );
  test_lthash_check_tail();
}

FD_UNIT_TEST( rewrite ) {
  fd_sched_lthash_t * l = test_lthash_new();
  fd_sched_lthash_lane_claim( l, 0UL, 3UL );

  fd_lthash_value_t known   [ 1 ]; test_value( known, 42UL ); FD_TEST( !fd_lthash_is_zero( known ) );
  fd_lthash_value_t delta   [ 1 ]; fd_lthash_zero( delta );
  fd_lthash_value_t expected[ 1 ]; fd_lthash_zero( expected ); fd_lthash_sub( expected, known );

  /* ADD_DONE with a slot: the applied addition is undone. */
  fd_acct_addr_t a = test_acct( 1UL );
  fd_sched_lthash_entry_t * e = fd_sched_lthash_insert( l, 0UL, &a );
  e->sub_state = FD_SCHED_LTHASH_SUB_DISPATCHED;
  e->add_state = FD_SCHED_LTHASH_ADD_DONE;
  e->spec_idx  = fd_sched_lthash_spec_acquire( l );
  FD_TEST( e->spec_idx!=UINT_MAX );
  *fd_sched_lthash_spec_entry( l, e->spec_idx ) = *known;
  fd_sched_lthash_entry_rewrite( l, e, delta );
  FD_TEST( fd_lthash_eq( delta, expected ) );
  FD_TEST( e->spec_idx==UINT_MAX );
  FD_TEST( e->ptxn_idx==0U );
  FD_TEST( e->add_state==FD_SCHED_LTHASH_ADD_NONE );
  FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_DISPATCHED );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );
  FD_TEST( fd_sched_lthash_query( l, 0UL, &a )==e );

  /* ADD_DISPATCHED with a slot: the slot is freed and delta is unchanged. */
  fd_acct_addr_t b = test_acct( 2UL );
  e = fd_sched_lthash_insert( l, 0UL, &b );
  e->sub_state = FD_SCHED_LTHASH_SUB_DONE;
  e->add_state = FD_SCHED_LTHASH_ADD_DISPATCHED;
  e->ptxn_idx  = (uint)(FD_RDISP_LTHASH_PSEUDO_TXN|5UL);
  e->spec_idx  = fd_sched_lthash_spec_acquire( l );
  FD_TEST( e->spec_idx!=UINT_MAX );
  *fd_sched_lthash_spec_entry( l, e->spec_idx ) = *known;
  fd_sched_lthash_entry_rewrite( l, e, delta );
  FD_TEST( fd_lthash_eq( delta, expected ) );
  FD_TEST( e->spec_idx==UINT_MAX );
  FD_TEST( e->ptxn_idx==0U );
  FD_TEST( e->add_state==FD_SCHED_LTHASH_ADD_NONE );
  FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_DONE );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );

  /* ADD_PENDING without a slot: only the ticket and the state change. */
  fd_acct_addr_t c = test_acct( 3UL );
  e = fd_sched_lthash_insert( l, 0UL, &c );
  e->add_state = FD_SCHED_LTHASH_ADD_PENDING;
  e->ptxn_idx  = (uint)(FD_RDISP_LTHASH_PSEUDO_TXN|6UL);
  fd_sched_lthash_entry_t want = *e;
  want.ptxn_idx  = 0U;
  want.add_state = FD_SCHED_LTHASH_ADD_NONE;
  fd_sched_lthash_entry_rewrite( l, e, delta );
  FD_TEST( !memcmp( e, &want, sizeof(fd_sched_lthash_entry_t) ) );
  FD_TEST( fd_lthash_eq( delta, expected ) );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );

  /* ADD_DONE without a slot cannot be undone, so rewriting it CRITs. */
# if FD_HAS_HOSTED
  fd_acct_addr_t d = test_acct( 4UL );
  e = fd_sched_lthash_insert( l, 0UL, &d );
  e->add_state = FD_SCHED_LTHASH_ADD_DONE;
  TEST_EXPECT_CRIT( fd_sched_lthash_entry_rewrite( l, e, delta ) );
# endif
  test_lthash_check_tail();
}

FD_UNIT_TEST( iter ) {
  fd_sched_lthash_t * l = test_lthash_new();

  /* An empty lane has nothing to visit. */
  FD_TEST( fd_sched_lthash_iter_done( l, 2UL, fd_sched_lthash_iter_init( l, 2UL, fd_sched_lthash_lane_primary( l, 2UL ) ) ) );

  /* Lane 0 holds accounts 0 to 99 and lane 1 holds 1000 to 1009. */
# define ITER_CNT (100UL)
  fd_sched_lthash_lane_claim( l, 0UL, 1UL );
  fd_sched_lthash_lane_claim( l, 1UL, 2UL );
  for( ulong i=0UL; i<ITER_CNT; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    fd_sched_lthash_insert( l, 0UL, &a );
  }
  for( ulong i=0UL; i<10UL; i++ ) {
    fd_acct_addr_t a = test_acct( 1000UL+i );
    fd_sched_lthash_insert( l, 1UL, &a );
  }
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 0UL )==ITER_CNT );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 1UL )==10UL     );

  /* The walk of lane 0 visits each of its entries once, in insertion
     order, and may modify the entries it visits. */
  ulong visit_cnt = 0UL;
  for( fd_sched_lthash_iter_t it = fd_sched_lthash_iter_init( l, 0UL, fd_sched_lthash_lane_primary( l, 0UL ) );
       !fd_sched_lthash_iter_done( l, 0UL, it );
       it = fd_sched_lthash_iter_next( l, 0UL, it ) ) {
    fd_sched_lthash_entry_t * e = fd_sched_lthash_iter_ele( l, 0UL, it );
    fd_acct_addr_t            a = test_acct( visit_cnt );
    FD_TEST( visit_cnt<ITER_CNT && !memcmp( e->acct.b, a.b, 32UL ) );
    visit_cnt++;
    e->sub_state = FD_SCHED_LTHASH_SUB_DONE;
  }
  FD_TEST( visit_cnt==ITER_CNT );
  for( ulong i=0UL; i<ITER_CNT; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    FD_TEST( fd_sched_lthash_query( l, 0UL, &a )->sub_state==FD_SCHED_LTHASH_SUB_DONE );
  }
# undef ITER_CNT

  /* The walk of lane 1 sees only lane 1's entries, in insertion order
     and untouched. */
  visit_cnt = 0UL;
  for( fd_sched_lthash_iter_t it = fd_sched_lthash_iter_init( l, 1UL, fd_sched_lthash_lane_primary( l, 1UL ) );
       !fd_sched_lthash_iter_done( l, 1UL, it );
       it = fd_sched_lthash_iter_next( l, 1UL, it ) ) {
    fd_sched_lthash_entry_t * e = fd_sched_lthash_iter_ele( l, 1UL, it );
    fd_acct_addr_t            a = test_acct( 1000UL+visit_cnt );
    FD_TEST( visit_cnt<10UL && !memcmp( e->acct.b, a.b, 32UL ) );
    FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_QUEUED );
    visit_cnt++;
  }
  FD_TEST( visit_cnt==10UL );

  /* A reset lane has nothing to visit. */
  fd_sched_lthash_lane_reset( l, 0UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 0UL )==0UL );
  FD_TEST( fd_sched_lthash_iter_done( l, 0UL, fd_sched_lthash_iter_init( l, 0UL, fd_sched_lthash_lane_primary( l, 0UL ) ) ) );
  test_lthash_check_tail();
}

FD_UNIT_TEST( lane_reset ) {
  fd_sched_lthash_t * l = test_lthash_new();
  fd_sched_lthash_lane_claim( l, 0UL, 5UL );
  fd_sched_lthash_lane_claim( l, 1UL, 6UL );

  /* Lane 0 holds 100 accounts, 7 of them with a slot.  Lane 1 holds
     the last slot. */
  for( ulong i=0UL; i<100UL; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    fd_sched_lthash_entry_t * e = fd_sched_lthash_insert( l, 0UL, &a );
    if( i<TEST_HASH_MAX-1UL ) {
      e->add_state = FD_SCHED_LTHASH_ADD_DONE;
      e->spec_idx  = fd_sched_lthash_spec_acquire( l );
      FD_TEST( e->spec_idx!=UINT_MAX );
    }
  }
  fd_acct_addr_t a0 = test_acct( 0UL );
  fd_sched_lthash_entry_t * e1 = fd_sched_lthash_insert( l, 1UL, &a0 );
  e1->add_state = FD_SCHED_LTHASH_ADD_DISPATCHED;
  e1->ptxn_idx  = (uint)(FD_RDISP_LTHASH_PSEUDO_TXN|9UL);
  e1->spec_idx  = fd_sched_lthash_spec_acquire( l );
  FD_TEST( e1->spec_idx!=UINT_MAX );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==0UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 0UL )==100UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 1UL )==1UL   );

  /* Resetting lane 0 frees its slots and entries and leaves lane 1
     alone. */
  fd_sched_lthash_lane_reset( l, 0UL );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX-1UL );
  FD_TEST( fd_sched_lthash_lane_bank( l, 0UL )==ULONG_MAX );
  FD_TEST( fd_sched_lthash_lane_bank( l, 1UL )==6UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt ( l, 0UL )==0UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt ( l, 1UL )==1UL );
  for( ulong i=0UL; i<100UL; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    FD_TEST( !fd_sched_lthash_query( l, 0UL, &a ) );
  }
  FD_TEST( fd_sched_lthash_query( l, 1UL, &a0 )==e1 );
  FD_TEST( e1->spec_idx!=UINT_MAX );
  test_check_free_slots( l, fd_ulong_set_bit( 0UL, (int)e1->spec_idx ) );

  fd_sched_lthash_lane_reset( l, 1UL );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );
  FD_TEST( fd_sched_lthash_lane_bank( l, 1UL )==ULONG_MAX );
  FD_TEST( fd_sched_lthash_lane_entry_cnt ( l, 1UL )==0UL );
  FD_TEST( !fd_sched_lthash_query( l, 1UL, &a0 ) );
  test_check_free_slots( l, 0UL );

  /* Resetting an empty lane makes it idle, so another bank can claim
     it. */
  fd_sched_lthash_lane_claim( l, 2UL, 4UL );
  fd_sched_lthash_lane_reset( l, 2UL );
  FD_TEST( fd_sched_lthash_lane_bank( l, 2UL )==ULONG_MAX );
  fd_sched_lthash_lane_claim( l, 2UL, 5UL );
  FD_TEST( fd_sched_lthash_lane_bank( l, 2UL )==5UL );
  fd_sched_lthash_lane_reset( l, 2UL );

  /* The reset freed every entry, so a reclaimed lane holds entry_max
     accounts again, each in a distinct entry. */
  static uchar seen[ TEST_ENTRY_MAX ];
  memset( seen, 0, sizeof(seen) );
  fd_sched_lthash_lane_claim( l, 0UL, 8UL );
  for( ulong i=0UL; i<TEST_ENTRY_MAX; i++ ) {
    fd_acct_addr_t a = test_acct( 1000UL+i );
    fd_sched_lthash_entry_t * e = fd_sched_lthash_insert( l, 0UL, &a );
    FD_TEST( e->bank_idx==8U );
    ulong idx = fd_sched_lthash_entry_idx( l, 0UL, e );
    FD_TEST( idx<TEST_ENTRY_MAX && !seen[ idx ] );
    seen[ idx ] = 1;
  }
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 0UL )==TEST_ENTRY_MAX );
  for( ulong i=0UL; i<TEST_ENTRY_MAX; i++ ) {
    fd_acct_addr_t a = test_acct( 1000UL+i );
    FD_TEST( fd_sched_lthash_query( l, 0UL, &a ) );
  }
  fd_sched_lthash_lane_reset( l, 0UL );
  FD_TEST( fd_sched_lthash_lane_bank( l, 0UL )==ULONG_MAX );
  FD_TEST( fd_sched_lthash_lane_entry_cnt ( l, 0UL )==0UL );
  test_lthash_check_tail();
}

FD_UNIT_TEST( lane_reset_reuse ) {
  fd_sched_lthash_t * l = test_lthash_new();

  /* Lane 1 is partly filled with 300 accounts over the 1024 chains of
     its map, so some chains hold several entries.  Four of the accounts
     hold a slot. */
# define REUSE_CNT (300UL)
  fd_sched_lthash_lane_claim( l, 1UL, 5UL );
  for( ulong i=0UL; i<REUSE_CNT; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    fd_sched_lthash_entry_t * e = fd_sched_lthash_insert( l, 1UL, &a );
    if( i<4UL ) {
      e->spec_idx = fd_sched_lthash_spec_acquire( l );
      FD_TEST( e->spec_idx!=UINT_MAX );
    }
  }

  /* The reset leaves the map empty.  A chain head left set would still
     lead to the entry it held, whose account a query would find, so
     finding none of the accounts shows that every chain head is clear. */
  fd_sched_lthash_lane_reset( l, 1UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 1UL )==0UL );
  FD_TEST( fd_sched_lthash_iter_done( l, 1UL, fd_sched_lthash_iter_init( l, 1UL, fd_sched_lthash_lane_primary( l, 1UL ) ) ) );
  FD_TEST( fd_sched_lthash_spec_free_cnt( l )==TEST_HASH_MAX );
  for( ulong i=0UL; i<REUSE_CNT; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    FD_TEST( !fd_sched_lthash_query( l, 1UL, &a ) );
  }

  /* Re-insert the first half of the accounts and as many new ones.
     Each gets a fresh entry of its own, the second half stays absent,
     and the walk visits each entry once. */
  fd_sched_lthash_lane_claim( l, 1UL, 6UL );
  for( ulong i=0UL; i<REUSE_CNT/2UL; i++ ) {
    fd_acct_addr_t a = test_acct( i        );
    fd_acct_addr_t b = test_acct( 10000UL+i );
    fd_sched_lthash_insert( l, 1UL, &a );
    fd_sched_lthash_insert( l, 1UL, &b );
  }
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 1UL )==REUSE_CNT );

  static uchar seen[ TEST_ENTRY_MAX ];
  memset( seen, 0, sizeof(seen) );
  ulong visit_cnt = 0UL;
  for( fd_sched_lthash_iter_t it = fd_sched_lthash_iter_init( l, 1UL, fd_sched_lthash_lane_primary( l, 1UL ) );
       !fd_sched_lthash_iter_done( l, 1UL, it );
       it = fd_sched_lthash_iter_next( l, 1UL, it ) ) {
    ulong idx = fd_sched_lthash_entry_idx( l, 1UL, fd_sched_lthash_iter_ele( l, 1UL, it ) );
    FD_TEST( idx<TEST_ENTRY_MAX && !seen[ idx ] );
    seen[ idx ] = 1;
    visit_cnt++;
  }
  FD_TEST( visit_cnt==REUSE_CNT );

  for( ulong i=0UL; i<REUSE_CNT; i++ ) {
    fd_acct_addr_t a = test_acct( i<REUSE_CNT/2UL ? i : 10000UL+i-REUSE_CNT/2UL );
    fd_sched_lthash_entry_t * e = fd_sched_lthash_query( l, 1UL, &a );
    FD_TEST( e && !memcmp( e->acct.b, a.b, 32UL ) );
    FD_TEST( seen[ fd_sched_lthash_entry_idx( l, 1UL, e ) ] );
    FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_QUEUED && e->add_state==FD_SCHED_LTHASH_ADD_NONE );
    FD_TEST( e->spec_idx==UINT_MAX && e->ptxn_idx==0U && e->q_next==UINT_MAX && e->bank_idx==6U );
  }
  for( ulong i=REUSE_CNT/2UL; i<REUSE_CNT; i++ ) {
    fd_acct_addr_t a = test_acct( i );
    FD_TEST( !fd_sched_lthash_query( l, 1UL, &a ) );
  }

  fd_sched_lthash_lane_reset( l, 1UL );
  FD_TEST( fd_sched_lthash_lane_entry_cnt( l, 1UL )==0UL );
  FD_TEST( fd_sched_lthash_iter_done( l, 1UL, fd_sched_lthash_iter_init( l, 1UL, fd_sched_lthash_lane_primary( l, 1UL ) ) ) );
  for( ulong i=0UL; i<REUSE_CNT/2UL; i++ ) {
    fd_acct_addr_t a = test_acct( i        );
    fd_acct_addr_t b = test_acct( 10000UL+i );
    FD_TEST( !fd_sched_lthash_query( l, 1UL, &a ) );
    FD_TEST( !fd_sched_lthash_query( l, 1UL, &b ) );
  }
# undef REUSE_CNT
  test_lthash_check_tail();
}

FD_UNIT_TEST( crit ) {
# if FD_HAS_HOSTED
  fd_sched_lthash_t * l = test_lthash_new();
  fd_acct_addr_t a = test_acct( 1UL );
  fd_acct_addr_t b = test_acct( 2UL );

  TEST_EXPECT_CRIT( fd_sched_lthash_insert( l, 0UL, &a ) );                 /* idle lane */
  TEST_EXPECT_CRIT( fd_sched_lthash_lane_claim( l, 0UL, (ulong)UINT_MAX ) ); /* bank_idx does not fit an entry */
  fd_sched_lthash_lane_claim( l, 0UL, 3UL );
  TEST_EXPECT_CRIT( fd_sched_lthash_lane_claim( l, 0UL, 4UL ) );            /* claimed by another bank */
  fd_sched_lthash_insert( l, 0UL, &a );
  TEST_EXPECT_CRIT( fd_sched_lthash_insert( l, 0UL, &a ) );                 /* already has an entry */

  uint slot = fd_sched_lthash_spec_acquire( l );
  TEST_EXPECT_CRIT( fd_sched_lthash_spec_release( l, (uint)TEST_HASH_MAX ) ); /* out of range */
  fd_sched_lthash_spec_release( l, slot );
  TEST_EXPECT_CRIT( fd_sched_lthash_spec_release( l, slot ) );              /* every slot already free */

  /* A lane with no free entry. */
  l = fd_sched_lthash_join( fd_sched_lthash_new( test_mem, 1UL, 1UL, 1UL ) );
  FD_TEST( l );
  fd_sched_lthash_lane_claim( l, 0UL, 3UL );
  fd_sched_lthash_insert( l, 0UL, &a );
  TEST_EXPECT_CRIT( fd_sched_lthash_insert( l, 0UL, &b ) );
# else
  FD_LOG_WARNING(( "skip: CRIT checks need a hosted target" ));
# endif
}

/* lane_reset_bench times fd_sched_lthash_lane_reset on a lane holding
   no entries, 3000 entries (about one block of the perf ledger) and
   FD_RDISP_MAX_WRITERS_PER_BLOCK entries (a full lane), in an object
   with fd_sched's entry_max so that the lane map has fd_sched's 2^18
   chain heads.  Every reset frees new accounts.  The inserts before a
   reset are not timed and leave what the reset touches in cache, so
   these are best cases for the replay tile. */

FD_UNIT_TEST( lane_reset_bench ) {
# if FD_HAS_HOSTED && FD_HAS_DOUBLE
  ulong  footprint = fd_sched_lthash_footprint( FD_RDISP_MAX_WRITERS_PER_BLOCK, 0UL );
  void * mem       = aligned_alloc( fd_sched_lthash_align(), footprint );
  FD_TEST( mem );
  fd_sched_lthash_t * l = fd_sched_lthash_join( fd_sched_lthash_new( mem, FD_RDISP_MAX_WRITERS_PER_BLOCK, 0UL, 1234UL ) );
  FD_TEST( l );

  /* The timer alone, for scale. */
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  long   timer_best  = LONG_MAX;
  long   timer_sum   = 0L;
  for( ulong rep=0UL; rep<1000UL; rep++ ) {
    long dt = -fd_tickcount();
    dt += fd_tickcount();
    timer_best  = fd_long_min( timer_best, dt );
    timer_sum  += dt;
  }
  FD_LOG_NOTICE(( "timer alone: best %.1f ns, mean %.1f ns over 1000 reads", (double)timer_best/tick_per_ns, (double)timer_sum/1000.0/tick_per_ns ));

  static ulong const entry_cnt[ 3 ] = { 0UL,    3000UL, FD_RDISP_MAX_WRITERS_PER_BLOCK };
  static ulong const rep_cnt  [ 3 ] = { 1000UL, 200UL,  10UL                           };
  for( ulong j=0UL; j<3UL; j++ ) {
    long best = LONG_MAX;
    long sum  = 0L;
    for( ulong rep=0UL; rep<rep_cnt[ j ]; rep++ ) {
      fd_sched_lthash_lane_claim( l, 0UL, 1UL );
      for( ulong i=0UL; i<entry_cnt[ j ]; i++ ) {
        fd_acct_addr_t a = test_acct( (rep<<32)|i );
        fd_sched_lthash_insert( l, 0UL, &a );
      }
      long dt = -fd_tickcount();
      fd_sched_lthash_lane_reset( l, 0UL );
      dt += fd_tickcount();
      best  = fd_long_min( best, dt );
      sum  += dt;
    }
    FD_LOG_NOTICE(( "lane_reset of %lu entries: best %.1f ns, mean %.1f ns over %lu resets",
                    entry_cnt[ j ], (double)best/tick_per_ns, (double)sum/(double)rep_cnt[ j ]/tick_per_ns, rep_cnt[ j ] ));
  }
  free( mem );
# else
  FD_LOG_WARNING(( "skip: the bench needs a hosted target with double" ));
# endif
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
