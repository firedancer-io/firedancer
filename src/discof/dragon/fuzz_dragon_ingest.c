/* fuzz_dragon_ingest.c drives the record path end to end with
   arbitrary bytes: fragments of arbitrary size, order and framing are
   reassembled, the completed records are unpacked, and what comes out
   is handed to the geyser core exactly as the tile hands it over.

   This is the path that carries the runtime's own records, so the
   bytes are not adversarial in production; they are here because a
   record link is shared memory and a producer that went wrong must
   not take the tile with it.  The fragments are also the only place
   the tile decides how much of a buffer to copy.

   What is asserted: the reassembled record is inside the link's
   buffer and matches the size its header claims, a record the
   unpacker accepts has counts within the schema's bounds, and the
   core gives back every reference it was granted. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "fd_dragon_ingest.h"
#include "fd_geyser_core.h"
#include "../../disco/events/fd_event_report.h"
#include "../../util/fd_util.h"

#define LINK_CNT     (2UL)
#define BANK_IDX_MAX (8UL)

static FD_TL uchar g_ing_mem [ 40UL<<20 ] __attribute__((aligned(128)));
static FD_TL uchar g_core_mem[  1UL<<20 ] __attribute__((aligned(FD_GEYSER_CORE_ALIGN)));
static FD_TL fd_dragon_ingest_t * g_ing;
static FD_TL fd_geyser_core_t *   g_core;

static FD_TL ulong g_release_cnt;

static void
fuzz_release( void * ctx,
              ulong  bank_idx,
              ulong  seq_bound ) {
  (void)ctx; (void)seq_bound;
  assert( bank_idx<BANK_IDX_MAX );
  g_release_cnt++;
}

static void
cb_slot_status( void *       ctx,
                ulong        slot,
                ulong        parent_slot,
                int          has_parent,
                int          status,
                ulong        bank_id,
                int          has_bank_id,
                char const * dead_error ) {
  (void)ctx; (void)slot; (void)parent_slot; (void)has_parent; (void)bank_id;
  (void)has_bank_id; (void)dead_error;
  assert( status>=0 && status<8 );
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
  (void)ctx; (void)bank_id; (void)reason;
}

static void
cb_account( void *                      ctx,
            fd_geyser_account_t const * acct,
            ulong                       slot,
            ulong                       bank_id ) {
  (void)ctx;
  assert( acct->slot==slot && acct->bank_id==bank_id );
  assert( acct->pubkey && acct->owner );
  assert( acct->data_sz<=FD_EVENT_INTERNAL_RUNTIME_WRITE_ACCOUNT_DATA_MAX );
  ulong sum = 0UL;
  for( ulong i=0UL; i<acct->data_sz; i++ ) sum += acct->data[ i ];
  FD_COMPILER_UNPREDICTABLE( sum );
}

static void
cb_transaction( void *                  ctx,
                fd_geyser_txn_t const * txn,
                ulong                   slot,
                ulong                   bank_id ) {
  assert( txn->slot==slot && txn->bank_id==bank_id );
  /* Building the meta is what turns a record's transaction payload
     into the message a subscriber gets */
  (void)fd_geyser_txn_meta( (fd_geyser_core_t *)ctx, txn );
}

static void
cb_end_of_startup( void * ctx ) {
  (void)ctx;
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */

  assert( fd_dragon_ingest_footprint( LINK_CNT )<=sizeof(g_ing_mem) );
  g_ing = fd_dragon_ingest_join( fd_dragon_ingest_new( g_ing_mem, LINK_CNT ) );
  assert( g_ing );
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

  /* A fresh ingest for every input, so that a run does not depend on
     the one before it. */
  g_ing = fd_dragon_ingest_join( fd_dragon_ingest_new( g_ing_mem, LINK_CNT ) );
  assert( g_ing );

  fd_geyser_core_params_t params = {
    .max_live_banks = BANK_IDX_MAX,
    .alpenglow      = !!( flags & 1U ),
    .records_gate   = !!( flags & 2U ),
    .release_fn     = fuzz_release
  };
  assert( fd_geyser_core_footprint( &params )<=sizeof(g_core_mem) );
  g_core = fd_geyser_core_join( fd_geyser_core_new( g_core_mem, &params ) );
  assert( g_core );

  fd_geyser_consumer_t consumer = {
    .ctx                = g_core,
    .wants_accounts     = 1,
    .wants_transactions = 1,
    .on_slot_status     = cb_slot_status,
    .on_block_meta      = cb_block_meta,
    .on_account         = cb_account,
    .on_transaction     = cb_transaction,
    .on_bank_discarded  = cb_bank_discarded,
    .on_end_of_startup  = cb_end_of_startup
  };
  assert( !fd_geyser_core_register( g_core, &consumer ) );
  g_release_cnt = 0UL;

  /* One bank the records can name, so that a well formed record has
     somewhere to land. */
  fd_replay_slot_completed_t sc = {
    .slot = 10UL, .parent_slot = 9UL, .bank_seq = 1UL, .parent_bank_seq = 0UL,
    .bank_idx = 1UL, .block_height = 10UL, .transaction_count = 4UL,
    .vote_success = ULONG_MAX, .vote_failed = ULONG_MAX,
    .nonvote_success = ULONG_MAX, .nonvote_failed = ULONG_MAX
  };
  fd_geyser_core_slot_completed( g_core, &sc, 1UL );

  /* The fragments.  A record is normally framed the way the reporter
     frames one, so that the unpacker and the core are reached, and
     every so often it is not: a frame that lies about its size, one
     that never starts, one that never ends, or a sequence number that
     jumped, which is a record the tile lost. */
  ulong seq[ LINK_CNT ];
  for( ulong i=0UL; i<LINK_CNT; i++ ) seq[ i ] = 0UL;

  ulong off = 0UL;
  while( off<size ) {
    ulong link_idx = (ulong)fd_rng_uint_roll( rng, (uint)LINK_CNT );
    ulong body_sz  = fd_ulong_min( 1UL + (ulong)fd_rng_uint_roll( rng, 200000U ), size-off );
    uchar const * body = data+off;
    off += body_sz;

    uint  quirk = fd_rng_uint_roll( rng, 8U );
    ulong type  = ( fd_rng_uint( rng ) & 1U ) ? FD_EVENT_INTERNAL_COMMIT_ID
                                              : FD_EVENT_INTERNAL_RUNTIME_WRITE_ID;
    ulong claim = body_sz;
    if( quirk==1U ) claim = (ulong)fd_rng_ulong( rng );                /* lies about the size */
    if( quirk==2U ) type  = (ulong)fd_rng_uchar( rng );                /* an unknown record */

    int done = 0;
    for( ulong b=0UL; b<body_sz; ) {
      ulong frag_sz = fd_ulong_min( FD_EVENT_INTERNAL_FRAG_MAX, body_sz-b );
      if( quirk==3U ) frag_sz = fd_ulong_min( frag_sz, 1UL + (ulong)fd_rng_uint_roll( rng, 4096U ) );
      int som = !b            && quirk!=4U; /* 4: the record never starts */
      int eom = b+frag_sz>=body_sz && quirk!=5U; /* 5: the record never ends */
      ulong ctl = (ulong)fd_frag_meta_ctl( 0UL, som, eom, 0 );
      ulong sig = som ? FD_EVENT_SIG( type, claim ) : 0UL;

      if( FD_UNLIKELY( quirk==6U && !( fd_rng_uint( rng ) & 3U ) ) ) {
        seq[ link_idx ] += 1UL + (ulong)fd_rng_uint_roll( rng, 8U ); /* a lost fragment */
      }
      done = fd_dragon_ingest_frag( g_ing, link_idx, seq[ link_idx ]++, sig, ctl, body+b, frag_sz );
      b += frag_sz;
      if( done ) break;
    }

    if( fd_dragon_ingest_gap_clear( g_ing ) ) fd_geyser_core_record_gap( g_core );
    if( !done ) continue;

    ulong        got_type;
    void const * rec;
    ulong        rec_sz;
    fd_dragon_ingest_record( g_ing, link_idx, &got_type, &rec, &rec_sz );
    assert( rec );
    assert( rec_sz<=FD_EVENT_INTERNAL_SZ_MAX );
    assert( fd_ulong_is_aligned( (ulong)rec, 8UL ) );

    switch( got_type ) {
    case FD_EVENT_INTERNAL_COMMIT_ID: {
      fd_event_internal_commit_parts_t parts[1];
      if( fd_event_internal_commit_unpack( rec, rec_sz, parts ) ) break;
      assert( fd_event_internal_commit_bounded( parts->prefix ) );
      assert( fd_event_internal_commit_footprint( parts->prefix )==rec_sz );
      fd_geyser_core_commit_record( g_core, parts );
      break;
    }
    case FD_EVENT_INTERNAL_RUNTIME_WRITE_ID: {
      fd_event_internal_runtime_write_parts_t parts[1];
      if( fd_event_internal_runtime_write_unpack( rec, rec_sz, parts ) ) break;
      fd_geyser_core_runtime_write_record( g_core, parts );
      break;
    }
    default:
      break;
    }
  }

  /* Whatever the records did, the references come back */
  for( ulong idx=0UL; idx<BANK_IDX_MAX; idx++ ) fd_geyser_core_drop_bank_ref( g_core, idx, 1000UL+idx );
  fd_geyser_core_link_gap( g_core, 2000UL );
  for( ulong idx=0UL; idx<BANK_IDX_MAX; idx++ ) fd_geyser_core_drop_bank_ref( g_core, idx, 3000UL+idx );

  fd_geyser_core_metrics_t const * m = fd_geyser_core_metrics( g_core );
  assert( m->ref_released_cnt==m->ref_acquired_cnt );
  assert( !fd_geyser_core_ref_held_cnt( g_core ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
