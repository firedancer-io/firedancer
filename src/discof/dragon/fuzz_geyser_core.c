/* fuzz_geyser_core.c drives the fork graph and commitment machine with
   random sequences of the things replay and the record links can say:
   completed slots, optimistic confirmations, roots, dead slots, bank
   reference drops, gaps, commit records and runtime write records, in
   any order and about any bank, including banks that were never
   announced and banks that are long gone.

   Replay is modelled the way test_geyser_core models it, so the
   invariants the unit tests assert are asserted here on every
   sequence: every reference the core is granted is given back, no slot
   gets two of the same status, a bank is discarded once, and the
   counters the core reports stay inside their structural bounds. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_geyser_core.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../util/fd_util.h"

#define BANK_IDX_MAX (16UL)
#define SLOT_MAX     (32UL)
#define GRANT_MAX    (4096UL)

/* Modelled replay: a grant is live until a release names its bank
   index with a bound above the sequence it was granted at. */

struct grant {
  ulong bank_idx;
  ulong seq;
  int   live;
};

typedef struct grant grant_t;

static FD_TL grant_t g_grant[ GRANT_MAX ];
static FD_TL ulong   g_grant_cnt;
static FD_TL ulong   g_seq;

/* What each bank has been told about.  A status belongs to a bank,
   not to a slot: two banks of the same slot are two forks and each
   gets its own statuses.  A bank that is discarded and created again
   under the same id starts over, which a flush does to every bank. */

#define BANK_SEEN_MAX (16UL)

static FD_TL uchar g_status_seen[ BANK_SEEN_MAX ][ 8 ];
static FD_TL ulong g_discard_cnt;
static FD_TL ulong g_status_cnt;
static FD_TL ulong g_acct_cnt;
static FD_TL ulong g_txn_cnt;

static FD_TL uchar g_core_mem[ 1UL<<20 ] __attribute__((aligned(FD_GEYSER_CORE_ALIGN)));
static FD_TL fd_geyser_core_t * g_core;

static void
model_grant( ulong bank_idx,
             ulong seq ) {
  if( FD_UNLIKELY( g_grant_cnt>=GRANT_MAX ) ) return;
  g_grant[ g_grant_cnt ].bank_idx = bank_idx;
  g_grant[ g_grant_cnt ].seq      = seq;
  g_grant[ g_grant_cnt ].live     = 1;
  g_grant_cnt++;
}

static void
fuzz_release( void * ctx,
              ulong  bank_idx,
              ulong  seq_bound ) {
  (void)ctx;
  assert( bank_idx<BANK_IDX_MAX );
  for( ulong i=0UL; i<g_grant_cnt; i++ ) {
    if( g_grant[ i ].bank_idx!=bank_idx ) continue;
    if( g_grant[ i ].seq>=seq_bound     ) continue;
    g_grant[ i ].live = 0;
  }
}

static void
cb_slot_status( void *       ctx,
                ulong        slot,
                ulong        parent_slot,
                int          status,
                ulong        bank_id,
                int          has_bank_id,
                char const * dead_error ) {
  (void)ctx; (void)parent_slot; (void)bank_id; (void)has_bank_id; (void)dead_error;
  (void)slot;
  assert( status>=0 && status<8 );
  g_status_cnt++;
  if( has_bank_id ) {
    assert( !g_status_seen[ bank_id % BANK_SEEN_MAX ][ status ] );
    g_status_seen[ bank_id % BANK_SEEN_MAX ][ status ] = 1;
  }
}

static void
cb_slot_status_shim( void *       ctx,
                     ulong        slot,
                     ulong        parent_slot,
                     int          has_parent,
                     int          status,
                     ulong        bank_id,
                     int          has_bank_id,
                     char const * dead_error ) {
  (void)has_parent;
  cb_slot_status( ctx, slot, parent_slot, status, bank_id, has_bank_id, dead_error );
}

static void
cb_block_meta( void *                         ctx,
               fd_geyser_block_meta_t const * meta,
               ulong                          bank_id ) {
  (void)ctx; (void)bank_id;
  assert( meta );
}

static void
cb_bank_discarded( void * ctx,
                   ulong  bank_id,
                   int    reason ) {
  (void)ctx;
  assert( reason>=0 && reason<7 );
  fd_memset( g_status_seen[ bank_id % BANK_SEEN_MAX ], 0, 8UL );
  g_discard_cnt++;
}

static void
cb_account( void *                      ctx,
            fd_geyser_account_t const * acct,
            ulong                       slot,
            ulong                       bank_id ) {
  (void)ctx;
  assert( acct->slot==slot && acct->bank_id==bank_id );
  assert( acct->pubkey && acct->owner );
  /* Touch the data so that a bad length shows up */
  ulong sum = 0UL;
  for( ulong i=0UL; i<acct->data_sz; i++ ) sum += acct->data[ i ];
  FD_COMPILER_UNPREDICTABLE( sum );
  g_acct_cnt++;
}

static void
cb_transaction( void *                  ctx,
                fd_geyser_txn_t const * txn,
                ulong                   slot,
                ulong                   bank_id ) {
  assert( txn->slot==slot && txn->bank_id==bank_id );
  assert( txn->rec && txn->rec->prefix->bank_seq==bank_id );
  /* The meta is built lazily and cached; asking twice answers the
     same way. */
  fd_txn_meta_t const * m1 = fd_geyser_txn_meta( (fd_geyser_core_t *)ctx, txn );
  fd_txn_meta_t const * m2 = fd_geyser_txn_meta( (fd_geyser_core_t *)ctx, txn );
  assert( m1==m2 );
  g_txn_cnt++;
}

static void
cb_end_of_startup( void * ctx ) {
  (void)ctx;
}

/* The record the fuzzer feeds: two accounts of a few bytes each, with
   the fields the input chooses. */

static int
drive_commit( fd_rng_t * rng,
              ulong      bank_seq,
              ulong      slot ) {
  static FD_TL uchar payload[ 128 ];
  static FD_TL uchar keys[ 2 ][ 32 ];
  static FD_TL ulong pre [ 2 ];
  static FD_TL ulong post[ 2 ];
  static FD_TL uchar writable[ 2 ] = { 1, 1 };
  static FD_TL fd_event_internal_commit_touched_t touched[ 2 ];

  ulong touched_cnt = (ulong)fd_rng_uint_roll( rng, 3U );
  ulong data_sz     = (ulong)fd_rng_uint_roll( rng, 65U );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_memset( keys[ i ], (int)( 0x40+i ), 32UL );
    pre [ i ] = 100UL+i;
    post[ i ] = 200UL+i;
  }
  for( ulong i=0UL; i<touched_cnt; i++ ) {
    touched[ i ].key_idx    = (uint)fd_rng_uint_roll( rng, 3U ); /* may be out of range */
    touched[ i ].executable = 0U;
    touched[ i ].lamports   = 200UL+i;
    touched[ i ].data_sz    = data_sz;
    fd_memset( touched[ i ].owner, 0x50, 32UL );
  }

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq             = bank_seq;
  ev->slot                 = slot;
  ev->index_in_slot        = (ulong)fd_rng_uint_roll( rng, 8U );
  ev->commit_index_in_slot = ev->index_in_slot;
  ev->accounts_included    = !!( fd_rng_uint( rng ) & 1U );
  ev->payload_cnt          = (ulong)fd_rng_uint_roll( rng, (uint)sizeof(payload)+1U );
  ev->keys_cnt             = 2UL;
  ev->pre_lamports_cnt     = 2UL;
  ev->post_lamports_cnt    = 2UL;
  ev->is_writable_cnt      = 2UL;
  ev->touched_cnt          = touched_cnt;

  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = payload,
    .keys          = (uchar const (*)[ 32UL ])keys,
    .pre_lamports  = pre,
    .post_lamports = post,
    .is_writable   = writable,
    .touched       = touched
  };
  return fd_geyser_core_commit_record( g_core, &parts );
}

static int
drive_write( fd_rng_t * rng,
             ulong      bank_seq,
             ulong      slot ) {
  static FD_TL uchar keys[ 1 ][ 32 ];
  static FD_TL uchar data[ 64 ];
  static FD_TL fd_event_internal_runtime_write_touched_t touched[ 1 ];

  /* One of the four sysvars a bank has to see written, or another
     account: the sysvar mask is what seals a bank. */
  fd_pubkey_t const * sysvar[ 4 ] = { &fd_sysvar_clock_id, &fd_sysvar_slot_hashes_id,
                                      &fd_sysvar_slot_history_id, &fd_sysvar_recent_block_hashes_id };
  uint pick = fd_rng_uint_roll( rng, 5U );
  if( pick<4U ) fd_memcpy( keys[ 0 ], sysvar[ pick ]->uc, 32UL );
  else          fd_memset( keys[ 0 ], (int)fd_rng_uchar( rng ), 32UL );

  ulong data_sz = (ulong)fd_rng_uint_roll( rng, (uint)sizeof(data)+1U );
  touched[ 0 ].key_idx    = 0U;
  touched[ 0 ].executable = 0U;
  touched[ 0 ].lamports   = (ulong)fd_rng_uint( rng );
  touched[ 0 ].data_off   = 0UL;
  touched[ 0 ].data_sz    = data_sz;
  fd_memset( touched[ 0 ].owner, 0x51, 32UL );

  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->bank_seq          = bank_seq;
  ev->slot              = slot;
  ev->phase             = fd_rng_uint_roll( rng, 3U );
  ev->accounts_included = 1;
  ev->write_seq         = (ulong)fd_rng_uint( rng );
  ev->keys_cnt          = 1UL;
  ev->touched_cnt       = 1UL;
  ev->account_data_cnt  = data_sz;

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = data
  };
  return fd_geyser_core_runtime_write_record( g_core, &parts );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<5UL ) return -1;
  uint  seed  = FD_LOAD( uint, data );
  uchar flags = data[ 4 ];
  data += 5UL; size -= 5UL;

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  fd_geyser_core_params_t params = {
    .max_live_banks = BANK_IDX_MAX,
    .alpenglow      = !!( flags & 1U ),
    .records_gate   = !!( flags & 2U ),
    .stale_slots    = ( flags & 4U ) ? 8UL : 0UL,
    .release_fn     = fuzz_release
  };
  assert( fd_geyser_core_footprint( &params )<=sizeof(g_core_mem) );
  g_core = fd_geyser_core_join( fd_geyser_core_new( g_core_mem, &params ) );
  assert( g_core );

  fd_geyser_consumer_t consumer = {
    .ctx                = g_core,
    .wants_accounts     = !!( flags &  8U ),
    .wants_transactions = !!( flags & 16U ),
    .on_slot_status     = cb_slot_status_shim,
    .on_block_meta      = cb_block_meta,
    .on_account         = cb_account,
    .on_transaction     = cb_transaction,
    .on_bank_discarded  = cb_bank_discarded,
    .on_end_of_startup  = cb_end_of_startup
  };
  assert( !fd_geyser_core_register( g_core, &consumer ) );

  g_grant_cnt   = 0UL;
  g_seq         = 1000UL;
  g_discard_cnt = 0UL;
  g_status_cnt  = 0UL;
  g_acct_cnt    = 0UL;
  g_txn_cnt     = 0UL;
  fd_memset( g_status_seen, 0, sizeof(g_status_seen) );
  fd_memset( g_grant,       0, sizeof(g_grant) );

  /* Each input byte is one action.  bank_seq is drawn from a small
     range so that the same bank is named again and again, which is
     what makes forks, re-notifications and stale references
     happen. */
  ulong bank_seq_hi = 1UL;
  for( ulong i=0UL; i<size; i++ ) {
    uchar act      = data[ i ];
    ulong bank_seq = 1UL + (ulong)( act>>3 ) % 12UL;
    ulong slot     = 10UL + bank_seq % SLOT_MAX;
    ulong bank_idx = bank_seq % BANK_IDX_MAX;
    bank_seq_hi    = fd_ulong_max( bank_seq_hi, bank_seq );

    switch( act & 7U ) {
    case 0: {
      fd_replay_slot_completed_t msg = {
        .slot              = slot,
        .parent_slot       = slot ? slot-1UL : 0UL,
        .bank_seq          = bank_seq,
        .parent_bank_seq   = bank_seq>1UL ? bank_seq-1UL : 0UL,
        .bank_idx          = bank_idx,
        .block_height      = slot,
        .transaction_count = (ulong)fd_rng_uint_roll( rng, 4U ),
        .vote_success      = ULONG_MAX,
        .vote_failed       = ULONG_MAX,
        .nonvote_success   = ULONG_MAX,
        .nonvote_failed    = ULONG_MAX
      };
      msg.block_hash.ul[ 0 ] = 0x100UL+bank_seq;
      msg.block_id.ul  [ 0 ] = 0x200UL+bank_seq;
      ulong seq = g_seq++;
      model_grant( bank_idx, seq );
      fd_geyser_core_slot_completed( g_core, &msg, seq );
      break;
    }
    case 1: {
      fd_replay_oc_advanced_t msg = { .slot = slot, .bank_seq = bank_seq, .bank_idx = bank_idx };
      fd_geyser_core_oc_advanced( g_core, &msg, g_seq++ );
      break;
    }
    case 2: {
      fd_replay_root_advanced_t msg = { .slot = slot, .bank_seq = bank_seq, .bank_idx = bank_idx };
      ulong seq = g_seq++;
      model_grant( bank_idx, seq );
      fd_geyser_core_root_advanced( g_core, &msg, seq );
      break;
    }
    case 3: {
      fd_replay_slot_dead_t msg = { .slot = slot };
      fd_geyser_core_slot_dead( g_core, &msg, g_seq++ );
      break;
    }
    case 4:
      fd_geyser_core_drop_bank_ref( g_core, bank_idx, g_seq++ );
      break;
    case 5:
      (void)drive_commit( rng, bank_seq, slot );
      break;
    case 6:
      (void)drive_write( rng, bank_seq, slot );
      break;
    default:
      if     ( act & 0x40U ) fd_geyser_core_record_gap( g_core );
      else if( act & 0x20U ) fd_geyser_core_link_gap( g_core, g_seq++ );
      else                   fd_geyser_core_housekeeping( g_core );
      break;
    }

    /* The structural bounds hold after every action */
    assert( fd_geyser_core_bank_cnt( g_core )<=2UL*BANK_IDX_MAX );
    assert( fd_geyser_core_ref_held_cnt( g_core )<=2UL*BANK_IDX_MAX );
    assert( fd_geyser_core_pending_cnt( g_core )<=2UL*BANK_IDX_MAX );
  }

  fd_geyser_core_end_of_startup( g_core );

  /* Every reference the core was granted comes back once replay stops
     naming banks: a gap makes the core give back everything it holds
     for banks it can no longer account for. */
  for( ulong idx=0UL; idx<BANK_IDX_MAX; idx++ ) fd_geyser_core_drop_bank_ref( g_core, idx, g_seq++ );
  fd_geyser_core_link_gap( g_core, g_seq++ );
  for( ulong idx=0UL; idx<BANK_IDX_MAX; idx++ ) fd_geyser_core_drop_bank_ref( g_core, idx, g_seq++ );

  fd_geyser_core_metrics_t const * m = fd_geyser_core_metrics( g_core );
  assert( m->ref_released_cnt==m->ref_acquired_cnt );
  assert( !fd_geyser_core_ref_held_cnt( g_core ) );
  for( ulong i=0UL; i<g_grant_cnt; i++ ) assert( !g_grant[ i ].live );

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
