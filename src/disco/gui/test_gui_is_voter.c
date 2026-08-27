/* test_gui_is_voter exercises the is_voter answer that
   fd_gui_slot_get_canon_safe synthesises for slots which have no
   fd_gui_slot_t of their own -- slots we skipped, slots evicted from the
   slot ring, and the pre-boot range after a snapshot resume.

   The value is derived from fd_gui_epoch_t.epoch_is_voter, a tri-state
   per-epoch seat written at block completion, and falls back to the node
   level gui->summary.is_voter only while that seat is still UNKNOWN.  The
   properties that matter, and that this test pins:

     - Legacy consensus is untouched: the answer is always 0 when
       is_alpenglow is clear, whatever the epoch and summary say.
     - A skipped slot in an epoch where we hold a seat reads 1.  This is
       the originally reported bug: the fabricated record hardcoded 0.
     - The seat wins over the summary flag, so a stale or newly changed
       node level value cannot rewrite history for an epoch whose seat is
       already known.
     - Seats are per epoch, so two epochs with different seats give
       different answers under one global summary flag.

   Only gui->db / gui->hist and a couple of summary fields are involved, so
   the test allocates a bare fd_gui_t and wires up the two store layers by
   hand -- no http server / topology / fd_gui_new -- exactly as
   test_gui_hist_evict does. */

#include "../../util/fd_util.h"
#include "fd_gui.h"
#include "fd_gui_store.h"
#include "fd_gui_hist.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS_PER_EPOCH (100UL)

#define EPOCH_A      (10UL)
#define EPOCH_B      (11UL)
#define A_START_SLOT (EPOCH_A*SLOTS_PER_EPOCH) /* 1000 */
#define B_START_SLOT (EPOCH_B*SLOTS_PER_EPOCH) /* 1100 */

static void
rm_tmpdir( char const * path ) {
  char cmd[ 256 ];
  fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "rm -rf %s %s-lock", path, path );
  FD_TEST( !system( cmd ) );
}

/* ---- lifecycle -------------------------------------------------------- */

struct test_store {
  fd_gui_t * gui;
  void *     db_mem;
  void *     hist_mem;
  char       path[ 128 ];
};
typedef struct test_store test_store_t;

static void
store_open( test_store_t * s, ulong map_bytes, int instance ) {
  fd_cstr_printf_check( s->path, sizeof(s->path), NULL, "/tmp/fd_gui_is_voter_test.%i.%i", (int)getpid(), instance );

  s->gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL ) );
  FD_TEST( s->gui );
  memset( s->gui, 0, fd_gui_footprint( 1UL ) );

  s->db_mem = aligned_alloc( fd_gui_store_align(),
                             fd_ulong_align_up( fd_gui_store_footprint( map_bytes, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( map_bytes ) ), fd_gui_store_align() ) );
  FD_TEST( s->db_mem );
  s->gui->db = fd_gui_store_join( fd_gui_store_new( s->db_mem, s->path, map_bytes, fd_gui_hist_db_cnt(), 0x0123456789abcdefUL, fd_gui_hist_db_descs( map_bytes ) ) );
  FD_TEST( s->gui->db );

  s->hist_mem = aligned_alloc( fd_gui_hist_align(),
                               fd_ulong_align_up( fd_gui_hist_footprint(), fd_gui_hist_align() ) );
  FD_TEST( s->hist_mem );
  s->gui->hist = fd_gui_hist_join( fd_gui_hist_new( s->hist_mem, s->gui->db ) );
  FD_TEST( s->gui->hist );

  /* A freshly booted gui: no tower/root/OC progress yet, so
     fd_gui_slot_get_canon finds nothing and canon_safe always takes the
     fabricate branch that this test is about. */
  s->gui->summary.slot_tower                    = ULONG_MAX;
  s->gui->summary.slot_rooted                   = ULONG_MAX;
  s->gui->summary.slot_optimistically_confirmed = ULONG_MAX;
  s->gui->summary.slot_caught_up                = ULONG_MAX;

  /* No warmup, epoch 0 starts at slot 0, so epoch == slot/SLOTS_PER_EPOCH. */
  s->gui->epoch.epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = SLOTS_PER_EPOCH,
    .leader_schedule_slot_offset = SLOTS_PER_EPOCH,
    .warmup                      = (uchar)0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL,
  };
  s->gui->epoch.has_epoch_schedule = 1;
}

static void
store_close( test_store_t * s ) {
  fd_gui_store_delete( fd_gui_store_leave( s->gui->db ) );
  free( s->hist_mem );
  free( s->db_mem );
  free( s->gui );
  rm_tmpdir( s->path );
}

/* ---- helpers ---------------------------------------------------------- */

static fd_gui_epoch_t *
put_epoch( fd_gui_t * gui, ulong epoch, ulong start_slot, uchar seat ) {
  fd_gui_hist_epoch_key_t key[ 1 ];
  key->epoch = epoch;

  fd_gui_epoch_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec );
  memset( rec, 0, sizeof(fd_gui_epoch_t) );
  rec->epoch          = epoch;
  rec->start_slot     = start_slot;
  rec->slot_cnt       = SLOTS_PER_EPOCH;
  rec->epoch_is_voter = seat;

  gui->epoch.stored_epoch_cnt++;
  return rec;
}

/* is_voter as the websocket layer would see it for a slot with no record. */
static uchar
synth_is_voter( fd_gui_t * gui, ulong slot ) {
  fd_gui_slot_t const * rec = fd_gui_slot_get_canon_safe( gui, slot );
  FD_TEST( rec );
  FD_TEST( rec->slot==slot );
  FD_TEST( rec->bank_seq==ULONG_MAX ); /* must be the fabricated record */
  return (uchar)rec->is_voter;
}

/* ---- tests ------------------------------------------------------------ */

/* Legacy consensus must be bit for bit unchanged: 0 regardless of what the
   epoch seat or the node level flag say. */

static void
test_legacy_always_zero( fd_gui_t * gui ) {
  gui->summary.is_alpenglow = 0;

  put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_YES );

  gui->summary.is_voter = 1;
  FD_TEST( synth_is_voter( gui, A_START_SLOT+5UL )==0 );

  gui->summary.is_voter = 0;
  FD_TEST( synth_is_voter( gui, A_START_SLOT+5UL )==0 );

  /* and for a slot with no epoch record at all */
  FD_TEST( synth_is_voter( gui, B_START_SLOT+5UL )==0 );

  FD_LOG_NOTICE(( "test_legacy_always_zero: ok" ));
}

/* The reported bug: a skipped slot in an epoch where we hold a seat used to
   report is_voter:false because the fabricated record hardcoded 0. */

static void
test_seat_yes_reports_voter( fd_gui_t * gui ) {
  gui->summary.is_alpenglow = 1;
  gui->summary.is_voter     = 0; /* deliberately disagrees with the seat */

  put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_YES );

  for( ulong s=A_START_SLOT; s<A_START_SLOT+SLOTS_PER_EPOCH; s+=17UL ) {
    FD_TEST( synth_is_voter( gui, s )==1 );
  }

  FD_LOG_NOTICE(( "test_seat_yes_reports_voter: ok" ));
}

/* A known seat of NO wins over a summary flag of 1.  Without this the single
   global flag would be applied retroactively to an epoch in which we held no
   seat, manufacturing false missed votes. */

static void
test_seat_no_beats_summary( fd_gui_t * gui ) {
  gui->summary.is_alpenglow = 1;
  gui->summary.is_voter     = 1;

  put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_NO );

  FD_TEST( synth_is_voter( gui, A_START_SLOT+3UL )==0 );

  FD_LOG_NOTICE(( "test_seat_no_beats_summary: ok" ));
}

/* Before any block of an epoch has been replayed there is no epoch scoped
   answer, so the node level flag is the only thing available. */

static void
test_unknown_seat_falls_back( fd_gui_t * gui ) {
  gui->summary.is_alpenglow = 1;

  put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_UNKNOWN );

  gui->summary.is_voter = 1;
  FD_TEST( synth_is_voter( gui, A_START_SLOT+3UL )==1 );

  gui->summary.is_voter = 0;
  FD_TEST( synth_is_voter( gui, A_START_SLOT+3UL )==0 );

  /* No epoch record at all behaves the same way. */
  gui->summary.is_voter = 1;
  FD_TEST( synth_is_voter( gui, B_START_SLOT+3UL )==1 );
  gui->summary.is_voter = 0;
  FD_TEST( synth_is_voter( gui, B_START_SLOT+3UL )==0 );

  FD_LOG_NOTICE(( "test_unknown_seat_falls_back: ok" ));
}

/* Seats are per epoch.  One global summary flag cannot make both epochs
   agree, which is precisely what the node level flag alone would have done. */

static void
test_seats_are_per_epoch( fd_gui_t * gui ) {
  gui->summary.is_alpenglow = 1;
  gui->summary.is_voter     = 1;

  put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_YES );
  put_epoch( gui, EPOCH_B, B_START_SLOT, FD_GUI_IS_VOTER_NO  );

  FD_TEST( synth_is_voter( gui, A_START_SLOT+1UL )==1 );
  FD_TEST( synth_is_voter( gui, B_START_SLOT+1UL )==0 );

  /* and the other way round */
  put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_NO  );
  put_epoch( gui, EPOCH_B, B_START_SLOT, FD_GUI_IS_VOTER_YES );

  FD_TEST( synth_is_voter( gui, A_START_SLOT+1UL )==0 );
  FD_TEST( synth_is_voter( gui, B_START_SLOT+1UL )==1 );

  FD_LOG_NOTICE(( "test_seats_are_per_epoch: ok" ));
}

/* A runtime identity / vote account change moves the node level flag.  Epochs
   whose seat is already known must keep their recorded answer; only epochs
   still UNKNOWN follow the new value. */

static void
test_runtime_identity_change( fd_gui_t * gui ) {
  gui->summary.is_alpenglow = 1;
  gui->summary.is_voter     = 1;

  fd_gui_epoch_t * a = put_epoch( gui, EPOCH_A, A_START_SLOT, FD_GUI_IS_VOTER_YES );
  put_epoch( gui, EPOCH_B, B_START_SLOT, FD_GUI_IS_VOTER_UNKNOWN );

  FD_TEST( synth_is_voter( gui, A_START_SLOT+2UL )==1 );
  FD_TEST( synth_is_voter( gui, B_START_SLOT+2UL )==1 );

  /* operator removes the vote account at runtime */
  gui->summary.is_voter = 0;

  FD_TEST( synth_is_voter( gui, A_START_SLOT+2UL )==1 ); /* history preserved */
  FD_TEST( synth_is_voter( gui, B_START_SLOT+2UL )==0 ); /* unknown seat follows */

  /* once a block of epoch A is replayed under the new configuration the seat
     is restamped, and the new answer takes effect for that epoch too */
  a->epoch_is_voter = FD_GUI_IS_VOTER_NO;
  FD_TEST( synth_is_voter( gui, A_START_SLOT+2UL )==0 );

  FD_LOG_NOTICE(( "test_runtime_identity_change: ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Each test gets a fresh store so epochs written by one do not perturb
     the next. */
  struct { void (*fn)( fd_gui_t * ); int inst; } cases[] = {
    { test_legacy_always_zero,      0 },
    { test_seat_yes_reports_voter,  1 },
    { test_seat_no_beats_summary,   2 },
    { test_unknown_seat_falls_back, 3 },
    { test_seats_are_per_epoch,     4 },
    { test_runtime_identity_change, 5 },
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    test_store_t s[ 1 ];
    store_open( s, 1UL<<30, cases[ i ].inst );
    cases[ i ].fn( s->gui );
    store_close( s );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
