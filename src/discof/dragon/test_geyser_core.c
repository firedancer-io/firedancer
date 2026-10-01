/* test_geyser_core drives the geyser core with synthetic replay
   notifications and records what a consumer sees.

   Replay is modelled too: a granted reference increments the model's
   reference count for a bank index, and a release message zeroes it,
   which is what the replay tile does with a dragon release.  Every
   scenario ends by checking that no reference is left behind. */

#include "fd_geyser_core.h"

#include "../../flamenco/runtime/fd_system_ids.h"

#define BANK_IDX_MAX (64UL)

/* Recorded callbacks *************************************************/

#define EV_STATUS  (0)
#define EV_META    (1)
#define EV_DISCARD (2)
#define EV_STARTUP (3)
#define EV_ACCOUNT (4)
#define EV_TXN     (5)

struct ev {
  int   kind;
  ulong slot;
  ulong parent_slot;
  int   has_parent;
  int   status;
  ulong bank_id;
  int   has_bank_id;
  int   reason;
  ulong block_height;
  ulong write_version;
  ulong data_sz;
};

typedef struct ev ev_t;

#define EV_MAX (4096UL)

static ev_t  g_ev[ EV_MAX ];
static ulong g_ev_cnt;

/* Modelled replay ****************************************************/

/* One grant, as replay records it: the bank index it is for and the
   replay_out sequence number it was published with.  A release gives
   back the grants for its bank index below the bound it carries,
   which is what keeps a release from taking back a grant for a bank
   the core has not read yet. */

#define GRANT_MAX (8192UL)

struct grant {
  ulong bank_idx;
  ulong seq;
  int   live;
};

typedef struct grant grant_t;

static grant_t g_grant[ GRANT_MAX ];
static ulong   g_grant_cnt;
static ulong   g_grant_unseen; /* granted for a notification the core never saw */
static ulong   g_release_msg_cnt;
static ulong   g_seq;          /* the replay_out sequence number to publish at next */

static void
model_grant( ulong bank_idx,
             ulong seq ) {
  FD_TEST( bank_idx<BANK_IDX_MAX );
  FD_TEST( g_grant_cnt<GRANT_MAX );
  g_grant[ g_grant_cnt ].bank_idx = bank_idx;
  g_grant[ g_grant_cnt ].seq      = seq;
  g_grant[ g_grant_cnt ].live     = 1;
  g_grant_cnt++;
}

static void
test_release( void * ctx,
              ulong  bank_idx,
              ulong  seq_bound ) {
  (void)ctx;
  FD_TEST( bank_idx<BANK_IDX_MAX );
  g_release_msg_cnt++;
  for( ulong i=0UL; i<g_grant_cnt; i++ ) {
    if( g_grant[ i ].bank_idx!=bank_idx ) continue;
    if( g_grant[ i ].seq>=seq_bound     ) continue;
    g_grant[ i ].live = 0;
  }
}

/* model_live counts the grants replay still holds for a bank index. */

static ulong
model_live( ulong bank_idx ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<g_grant_cnt; i++ ) cnt += g_grant[ i ].live && g_grant[ i ].bank_idx==bank_idx;
  return cnt;
}

static void
model_expect_drained( void ) {
  for( ulong i=0UL; i<g_grant_cnt; i++ ) {
    if( FD_UNLIKELY( g_grant[ i ].live ) )
      FD_LOG_ERR(( "bank idx %lu still holds the reference granted at seq %lu",
                   g_grant[ i ].bank_idx, g_grant[ i ].seq ));
  }
}

static void
on_slot_status( void *       ctx,
                ulong        slot,
                ulong        parent_slot,
                int          has_parent,
                int          status,
                ulong        bank_id,
                int          has_bank_id,
                char const * dead_error ) {
  (void)ctx; (void)dead_error;
  FD_TEST( g_ev_cnt<EV_MAX );
  g_ev[ g_ev_cnt++ ] = (ev_t){ .kind        = EV_STATUS,
                               .slot        = slot,
                               .parent_slot = parent_slot,
                               .has_parent  = has_parent,
                               .status      = status,
                               .bank_id     = bank_id,
                               .has_bank_id = has_bank_id };
}

static void
on_block_meta( void *                         ctx,
               fd_geyser_block_meta_t const * meta,
               ulong                          bank_id ) {
  (void)ctx;
  FD_TEST( g_ev_cnt<EV_MAX );
  g_ev[ g_ev_cnt++ ] = (ev_t){ .kind         = EV_META,
                               .slot         = meta->slot,
                               .parent_slot  = meta->parent_slot,
                               .has_parent   = meta->has_parent,
                               .bank_id      = bank_id,
                               .has_bank_id  = 1,
                               .block_height = meta->block_height };
}

static void
on_bank_discarded( void * ctx,
                   ulong  bank_id,
                   int    reason ) {
  (void)ctx;
  FD_TEST( g_ev_cnt<EV_MAX );
  g_ev[ g_ev_cnt++ ] = (ev_t){ .kind = EV_DISCARD, .bank_id = bank_id, .has_bank_id = 1, .reason = reason };
}

static void
on_account( void *                      ctx,
            fd_geyser_account_t const * acct,
            ulong                       slot,
            ulong                       bank_id ) {
  (void)ctx;
  FD_TEST( g_ev_cnt<EV_MAX );
  FD_TEST( acct->slot==slot && acct->bank_id==bank_id );
  FD_TEST( acct->pubkey && acct->owner );
  g_ev[ g_ev_cnt++ ] = (ev_t){ .kind          = EV_ACCOUNT,
                               .slot          = slot,
                               .bank_id       = bank_id,
                               .has_bank_id   = 1,
                               .write_version = acct->write_version,
                               .data_sz       = acct->data_sz };
}

static void
on_transaction( void *                  ctx,
                fd_geyser_txn_t const * txn,
                ulong                   slot,
                ulong                   bank_id ) {
  FD_TEST( g_ev_cnt<EV_MAX );
  FD_TEST( txn->slot==slot && txn->bank_id==bank_id );
  FD_TEST( txn->rec && txn->rec->prefix->bank_seq==bank_id );

  /* The meta object is built on the first ask, for the record the
     callback is about.  The records these tests feed carry no
     transaction payload, so the core reports that it cannot build
     one, twice for the one ask it caches. */
  FD_TEST( !fd_geyser_txn_meta( (fd_geyser_core_t *)ctx, txn ) );
  FD_TEST( !fd_geyser_txn_meta( (fd_geyser_core_t *)ctx, txn ) );

  g_ev[ g_ev_cnt++ ] = (ev_t){ .kind        = EV_TXN,
                               .slot        = slot,
                               .bank_id     = bank_id,
                               .has_bank_id = 1 };
}

static void
on_end_of_startup( void * ctx ) {
  (void)ctx;
  FD_TEST( g_ev_cnt<EV_MAX );
  g_ev[ g_ev_cnt++ ] = (ev_t){ .kind = EV_STARTUP };
}

/* Driving ************************************************************/

static uchar            core_mem[ 1UL<<20 ] __attribute__((aligned(FD_GEYSER_CORE_ALIGN)));
static fd_geyser_core_t * g_core;

static fd_geyser_core_t *
core_new( int   alpenglow,
          int   records_gate,
          ulong stale_slots ) {
  fd_geyser_core_params_t params = {
    .max_live_banks = BANK_IDX_MAX,
    .alpenglow      = alpenglow,
    .records_gate   = records_gate,
    .stale_slots    = stale_slots,
    .release_fn     = test_release
  };
  FD_TEST( fd_geyser_core_footprint( &params )<=sizeof(core_mem) );
  g_core = fd_geyser_core_join( fd_geyser_core_new( core_mem, &params ) );
  FD_TEST( g_core );

  fd_geyser_consumer_t consumer = {
    .ctx                = g_core,
    .wants_accounts     = 1,
    .wants_transactions = 1,
    .on_slot_status     = on_slot_status,
    .on_block_meta      = on_block_meta,
    .on_account         = on_account,
    .on_transaction     = on_transaction,
    .on_bank_discarded  = on_bank_discarded,
    .on_end_of_startup  = on_end_of_startup
  };
  FD_TEST( !fd_geyser_core_register( g_core, &consumer ) );

  g_ev_cnt          = 0UL;
  g_grant_cnt       = 0UL;
  g_grant_unseen    = 0UL;
  g_release_msg_cnt = 0UL;
  g_seq             = 1000UL;
  fd_memset( g_grant, 0, sizeof(g_grant) );
  return g_core;
}

/* drive_slot publishes one REPLAY_SIG_SLOT_COMPLETED, granting a
   reference the way the replay tile does. */

static void
drive_slot( ulong slot,
            ulong parent_slot,
            ulong bank_seq,
            ulong parent_bank_seq,
            ulong bank_idx,
            ulong block_height,
            ulong txn_count ) {
  /* Replay's per slot transaction counts are absent, so the core falls
     back on the cumulative count and the parent's. */
  fd_replay_slot_completed_t msg = {
    .slot              = slot,
    .parent_slot       = parent_slot,
    .bank_seq          = bank_seq,
    .parent_bank_seq   = parent_bank_seq,
    .bank_idx          = bank_idx,
    .block_height      = block_height,
    .transaction_count = txn_count,
    .vote_success      = ULONG_MAX,
    .vote_failed       = ULONG_MAX,
    .nonvote_success   = ULONG_MAX,
    .nonvote_failed    = ULONG_MAX
  };
  msg.block_hash.ul[ 0 ] = 0x100UL + bank_seq;
  msg.block_id.ul  [ 0 ] = 0x200UL + bank_seq;

  ulong seq = g_seq++;
  model_grant( bank_idx, seq );
  fd_geyser_core_slot_completed( g_core, &msg, seq );
}

/* drive_slot_counted publishes a completed slot the way replay does
   when it knows the block's own transaction counts, which is whenever
   the bank has a parent in its pool. */

static void
drive_slot_counted( ulong slot,
                    ulong parent_slot,
                    ulong bank_seq,
                    ulong parent_bank_seq,
                    ulong bank_idx,
                    ulong block_height,
                    ulong slot_txn_cnt ) {
  fd_replay_slot_completed_t msg = {
    .slot              = slot,
    .parent_slot       = parent_slot,
    .bank_seq          = bank_seq,
    .parent_bank_seq   = parent_bank_seq,
    .bank_idx          = bank_idx,
    .block_height      = block_height,
    .transaction_count = 0UL,
    .vote_success      = slot_txn_cnt,
    .vote_failed       = 0UL,
    .nonvote_success   = 0UL,
    .nonvote_failed    = 0UL
  };

  ulong seq = g_seq++;
  model_grant( bank_idx, seq );
  fd_geyser_core_slot_completed( g_core, &msg, seq );
}

/* drive_slot_txns publishes a completed slot whose per slot
   transaction counts replay does report, so the core knows how many
   records the bank owes without having seen its parent. */

static void
drive_slot_txns( ulong slot,
                 ulong parent_slot,
                 ulong bank_seq,
                 ulong parent_bank_seq,
                 ulong bank_idx,
                 ulong block_height,
                 ulong txn_count,
                 ulong exec_cnt ) {
  fd_replay_slot_completed_t msg = {
    .slot              = slot,
    .parent_slot       = parent_slot,
    .bank_seq          = bank_seq,
    .parent_bank_seq   = parent_bank_seq,
    .bank_idx          = bank_idx,
    .block_height      = block_height,
    .transaction_count = txn_count,
    .vote_success      = 0UL,
    .vote_failed       = 0UL,
    .nonvote_success   = exec_cnt,
    .nonvote_failed    = 0UL
  };
  msg.block_hash.ul[ 0 ] = 0x100UL + bank_seq;
  msg.block_id.ul  [ 0 ] = 0x200UL + bank_seq;

  ulong seq = g_seq++;
  model_grant( bank_idx, seq );
  fd_geyser_core_slot_completed( g_core, &msg, seq );
}

static void
drive_oc( ulong slot,
          ulong bank_seq,
          ulong bank_idx ) {
  fd_replay_oc_advanced_t msg = { .slot = slot, .bank_seq = bank_seq, .bank_idx = bank_idx };
  fd_geyser_core_oc_advanced( g_core, &msg, g_seq++ );
}

static void
drive_root( ulong slot,
            ulong bank_seq,
            ulong bank_idx ) {
  fd_replay_root_advanced_t msg = { .slot = slot, .bank_seq = bank_seq, .bank_idx = bank_idx };
  ulong seq = g_seq++;
  model_grant( bank_idx, seq );
  fd_geyser_core_root_advanced( g_core, &msg, seq );
}

static void
drive_dead( ulong slot ) {
  fd_replay_slot_dead_t msg = { .slot = slot };
  fd_geyser_core_slot_dead( g_core, &msg, g_seq++ );
}

static void
drive_drop( ulong bank_idx ) {
  fd_geyser_core_drop_bank_ref( g_core, bank_idx, g_seq++ );
}

/* drive_acct_write feeds the account record of one account a
   transaction wrote: touched_idx-th in that transaction's touched list,
   data_sz bytes of data. */

static int
drive_acct_write( ulong         bank_seq,
                  ulong         slot,
                  ulong         commit_index,
                  uint          touched_idx,
                  uchar const * signature,
                  uchar const * key,
                  ulong         lamports,
                  ulong         data_sz ) {
  static uchar data[ 256 ];
  FD_TEST( data_sz<=sizeof(data) );
  uchar keys[ 1 ][ 32 ];
  fd_memcpy( keys[ 0 ], key, 32UL );

  fd_event_internal_runtime_write_touched_t touched[1] = {{
    .key_idx    = 0U,
    .executable = 0U,
    .lamports   = lamports,
    .data_off   = 0UL,
    .data_sz    = data_sz
  }};
  fd_memset( touched->owner, 0x50, 32UL );

  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->bank_seq             = bank_seq;
  ev->slot                 = slot;
  ev->phase                = 1U;
  if( signature ) fd_memcpy( ev->signature, signature, 64UL );
  ev->commit_index_in_slot = commit_index;
  ev->touched_idx          = touched_idx;
  ev->accounts_included    = 1;
  ev->keys_cnt             = 1UL;
  ev->touched_cnt          = 1UL;
  ev->account_data_cnt     = data_sz;

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = data
  };
  return fd_geyser_core_runtime_write_record( g_core, &parts );
}

/* drive_commit feeds one transaction: its commit record, naming the
   touched_cnt of its two accounts it wrote, then one account record per
   written account with data_sz bytes of data each. */

static int
drive_commit( ulong bank_seq,
              ulong slot,
              ulong index_in_slot,
              ulong commit_index,
              ulong touched_cnt,
              ulong data_sz ) {
  static uchar payload[ 64 ];
  static uchar keys[ 2 ][ 32 ];
  static ulong pre [ 2 ];
  static ulong post[ 2 ];
  static uchar writable[ 2 ] = { 1, 1 };
  static fd_event_internal_commit_touched_t touched[ 2 ];

  FD_TEST( touched_cnt<=2UL );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_memset( keys[ i ], (int)(0x40+i), 32UL );
    pre [ i ] = 100UL+i;
    post[ i ] = 200UL+i;
  }
  for( ulong i=0UL; i<touched_cnt; i++ ) {
    touched[ i ].key_idx    = (uint)i;
    touched[ i ].executable = 0U;
    touched[ i ].lamports   = 200UL+i;
    touched[ i ].data_sz    = data_sz;
    fd_memset( touched[ i ].owner, 0x50, 32UL );
  }

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq             = bank_seq;
  ev->slot                 = slot;
  ev->index_in_slot        = index_in_slot;
  ev->commit_index_in_slot = commit_index;
  ev->accounts_included    = 1;
  ev->payload_cnt          = sizeof(payload);
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
  int err = fd_geyser_core_commit_record( g_core, &parts );
  if( FD_UNLIKELY( err ) ) return err;
  for( ulong i=0UL; i<touched_cnt; i++ ) {
    err = drive_acct_write( bank_seq, slot, commit_index, (uint)i, ev->signature, keys[ i ], 200UL+i, data_sz );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return 0;
}

/* drive_write feeds one runtime write record of pubkey. */

static int
drive_write( ulong               bank_seq,
             ulong               slot,
             uint                phase,
             ulong               write_seq,
             fd_pubkey_t const * pubkey ) {
  static uchar data[ 32 ];
  uchar keys[ 1 ][ 32 ];
  fd_memcpy( keys[ 0 ], pubkey->uc, 32UL );

  fd_event_internal_runtime_write_touched_t touched[1] = {{
    .key_idx    = 0U,
    .executable = 0U,
    .lamports   = 1UL,
    .data_off   = 0UL,
    .data_sz    = sizeof(data)
  }};

  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->bank_seq          = bank_seq;
  ev->slot              = slot;
  ev->phase             = phase;
  ev->accounts_included = 1;
  ev->write_seq         = write_seq;
  ev->keys_cnt          = 1UL;
  ev->touched_cnt       = 1UL;
  ev->account_data_cnt  = sizeof(data);

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = data
  };
  return fd_geyser_core_runtime_write_record( g_core, &parts );
}

/* drive_sysvars feeds the four sysvar writes a block produces. */

static void
drive_sysvars( ulong bank_seq,
               ulong slot,
               int   cnt ) {
  fd_pubkey_t const * sysvar[ 4 ] = { &fd_sysvar_clock_id, &fd_sysvar_slot_hashes_id,
                                      &fd_sysvar_recent_block_hashes_id, &fd_sysvar_slot_history_id };
  for( int i=0; i<cnt; i++ ) FD_TEST( !drive_write( bank_seq, slot, i<2 ? 0U : 2U, (ulong)i, sysvar[ i ] ) );
}

/* Expectations *******************************************************/

static ev_t const *
ev_at( ulong idx ) {
  FD_TEST( idx<g_ev_cnt );
  return g_ev + idx;
}

static void
expect_status( ulong idx,
               ulong slot,
               int   status,
               ulong bank_id ) {
  ev_t const * e = ev_at( idx );
  if( FD_UNLIKELY( e->kind!=EV_STATUS || e->slot!=slot || e->status!=status ||
                   ( bank_id!=ULONG_MAX && ( !e->has_bank_id || e->bank_id!=bank_id ) ) ||
                   ( bank_id==ULONG_MAX && e->has_bank_id ) ) )
    FD_LOG_ERR(( "event %lu: kind %d slot %lu status %d bank_id %lu (has %d), expected status %d slot %lu bank_id %lu",
                 idx, e->kind, e->slot, e->status, e->bank_id, e->has_bank_id, status, slot, bank_id ));
}

static void
expect_meta( ulong idx,
             ulong slot,
             ulong bank_id ) {
  ev_t const * e = ev_at( idx );
  FD_TEST( e->kind==EV_META );
  FD_TEST( e->slot==slot );
  FD_TEST( e->bank_id==bank_id );
}

static void
expect_discard( ulong idx,
                ulong bank_id,
                int   reason ) {
  ev_t const * e = ev_at( idx );
  if( FD_UNLIKELY( e->kind!=EV_DISCARD || e->bank_id!=bank_id || e->reason!=reason ) )
    FD_LOG_ERR(( "event %lu: kind %d bank_id %lu reason %d, expected discard of %lu reason %d",
                 idx, e->kind, e->bank_id, e->reason, bank_id, reason ));
}

static ulong
count_status( ulong slot,
              int   status ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<g_ev_cnt; i++ ) {
    if( g_ev[ i ].kind==EV_STATUS && g_ev[ i ].slot==slot && g_ev[ i ].status==status ) cnt++;
  }
  return cnt;
}

static ulong
count_discard( ulong bank_id,
               int   reason ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<g_ev_cnt; i++ ) {
    if( g_ev[ i ].kind==EV_DISCARD && g_ev[ i ].bank_id==bank_id && g_ev[ i ].reason==reason ) cnt++;
  }
  return cnt;
}

/* Every reference the core took has to have gone back, and replay's
   model must hold none. */

static void
expect_refs_balanced( void ) {
  fd_geyser_core_metrics_t const * m = fd_geyser_core_metrics( g_core );
  if( FD_UNLIKELY( m->ref_acquired_cnt!=m->ref_released_cnt ) )
    FD_LOG_ERR(( "acquired %lu references, released %lu", m->ref_acquired_cnt, m->ref_released_cnt ));
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );
  FD_TEST( m->ref_acquired_cnt+g_grant_unseen==g_grant_cnt );
  model_expect_drained();
}

/* Tests **************************************************************/

/* A bank comes into being, freezes and is reported, and its reference
   goes back as soon as the callbacks have returned. */

static void
test_processed( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );

  FD_TEST( g_ev_cnt==3UL );
  expect_status( 0UL, 10UL, FD_GEYSER_SLOT_CREATED_BANK, 1UL );
  expect_meta  ( 1UL, 10UL, 1UL );
  expect_status( 2UL, 10UL, FD_GEYSER_SLOT_PROCESSED,    1UL );
  FD_TEST( ev_at( 0UL )->has_parent && ev_at( 0UL )->parent_slot==9UL ); /* the parent slot is known without its bank */

  drive_slot( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1010UL );
  FD_TEST( g_ev_cnt==6UL );
  expect_status( 3UL, 11UL, FD_GEYSER_SLOT_CREATED_BANK, 2UL );
  FD_TEST( ev_at( 3UL )->has_parent && ev_at( 3UL )->parent_slot==10UL );
  expect_meta  ( 4UL, 11UL, 2UL );
  FD_TEST( ev_at( 4UL )->block_height==101UL );
  expect_status( 5UL, 11UL, FD_GEYSER_SLOT_PROCESSED,    2UL );

  /* The same bank published twice is reported once, and the second
     reference goes back too. */
  drive_slot( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1010UL );
  FD_TEST( g_ev_cnt==6UL );

  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 2UL ) );
  expect_refs_balanced();
}

/* Two banks of one slot: confirming one discards the other. */

static void
test_equivocation_oc( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 10UL, 9UL, 2UL, ULONG_MAX, 1UL, 100UL, 1000UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );

  ulong base = g_ev_cnt;
  drive_oc( 10UL, 2UL, 1UL );

  expect_discard( base,      1UL, FD_GEYSER_DISCARD_LOSER );
  expect_status ( base+1UL, 10UL, FD_GEYSER_SLOT_CONFIRMED, 2UL );
  FD_TEST( g_ev_cnt==base+2UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );

  /* A second notification for the same bank is not reported twice. */
  drive_oc( 10UL, 2UL, 1UL );
  FD_TEST( g_ev_cnt==base+2UL );

  expect_refs_balanced();
}

/* Rooting reports the banks the root passed over, oldest first, even
   across a skipped slot, and discards what does not descend from the
   new root. */

static void
test_root_ancestors( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 11UL, 10UL, 2UL, 1UL,       1UL, 101UL, 1010UL );
  /* slot 12 is skipped */
  drive_slot( 13UL, 11UL, 3UL, 2UL,       2UL, 102UL, 1020UL );
  /* a fork off slot 10 that the root does not cover */
  drive_slot( 14UL, 10UL, 4UL, 1UL,       3UL, 101UL, 1005UL );

  ulong base = g_ev_cnt;
  drive_root( 13UL, 3UL, 2UL );

  expect_status( base,      10UL, FD_GEYSER_SLOT_FINALIZED, 1UL );
  expect_status( base+1UL,  11UL, FD_GEYSER_SLOT_FINALIZED, 2UL );
  expect_status( base+2UL,  13UL, FD_GEYSER_SLOT_FINALIZED, 3UL );

  /* Everything that is not the root or below it on the rooted fork is
     pruned, which is the two finalized ancestors and the fork. */
  FD_TEST( count_discard( 1UL, FD_GEYSER_DISCARD_PRUNED )==1UL );
  FD_TEST( count_discard( 2UL, FD_GEYSER_DISCARD_PRUNED )==1UL );
  FD_TEST( count_discard( 4UL, FD_GEYSER_DISCARD_PRUNED )==1UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );
  FD_TEST( fd_geyser_core_bank_slot( g_core, 3UL )==13UL );

  /* No confirmed status without alpenglow and without an optimistic
     confirmation notification. */
  FD_TEST( !count_status( 13UL, FD_GEYSER_SLOT_CONFIRMED ) );

  expect_refs_balanced();
}

/* Under alpenglow a newly rooted bank is reported confirmed and then
   finalized. */

static void
test_alpenglow_root( void ) {
  core_new( 1, 0, 0UL );

  drive_slot( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 11UL, 10UL, 2UL, 1UL,       1UL, 101UL, 1010UL );

  ulong base = g_ev_cnt;
  drive_root( 11UL, 2UL, 1UL );

  expect_status( base,     10UL, FD_GEYSER_SLOT_CONFIRMED, 1UL );
  expect_status( base+1UL, 10UL, FD_GEYSER_SLOT_FINALIZED, 1UL );
  expect_status( base+2UL, 11UL, FD_GEYSER_SLOT_CONFIRMED, 2UL );
  expect_status( base+3UL, 11UL, FD_GEYSER_SLOT_FINALIZED, 2UL );

  /* A later root does not report the same bank again. */
  drive_slot( 12UL, 11UL, 3UL, 2UL, 2UL, 102UL, 1020UL );
  ulong base2 = g_ev_cnt;
  drive_root( 12UL, 3UL, 2UL );
  expect_status( base2,     12UL, FD_GEYSER_SLOT_CONFIRMED, 3UL );
  expect_status( base2+1UL, 12UL, FD_GEYSER_SLOT_FINALIZED, 3UL );
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_FINALIZED )==1UL );

  expect_refs_balanced();
}

/* Rooting one of two banks of a slot discards the other. */

static void
test_equivocation_root( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 10UL, 9UL, 2UL, ULONG_MAX, 1UL, 100UL, 1000UL );

  ulong base = g_ev_cnt;
  drive_root( 10UL, 2UL, 1UL );

  expect_discard( base,     1UL,  FD_GEYSER_DISCARD_LOSER );
  expect_status ( base+1UL, 10UL, FD_GEYSER_SLOT_FINALIZED, 2UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );

  expect_refs_balanced();
}

/* A dead slot takes its banks with it and is reported without a bank
   id. */

static void
test_dead( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );

  ulong base = g_ev_cnt;
  drive_dead( 10UL );

  expect_discard( base,     1UL,  FD_GEYSER_DISCARD_DEAD );
  expect_status ( base+1UL, 10UL, FD_GEYSER_SLOT_DEAD, ULONG_MAX );
  FD_TEST( !fd_geyser_core_bank_cnt( g_core ) );

  /* A dead slot the core never saw a bank for is still reported. */
  drive_dead( 11UL );
  expect_status( g_ev_cnt-1UL, 11UL, FD_GEYSER_SLOT_DEAD, ULONG_MAX );

  expect_refs_balanced();
}

/* A claim keeps the reference; releasing the claim gives it back.  A
   bank whose references are already back cannot be claimed: it may
   have been recycled by replay, so there is nothing left to keep. */

static void
test_claim( void ) {
  core_new( 0, 0, 0UL );

  /* Nothing to claim before the bank exists. */
  FD_TEST( fd_geyser_bank_hold( g_core, 1UL )==-1 );

  /* A record creates the bank before it freezes, and a claim taken
     then keeps the reference the freeze grants. */
  FD_TEST( !drive_commit( 1UL, 20UL, 0UL, 0UL, 1UL, 8UL ) );
  FD_TEST( !fd_geyser_bank_hold( g_core, 1UL ) );
  drive_slot( 20UL, 19UL, 1UL, ULONG_MAX, 0UL, 200UL, 2000UL );
  FD_TEST( fd_geyser_core_ref_held_cnt( g_core )==1UL );
  FD_TEST( model_live( 0UL )==1UL );

  /* A second claim is fine while a reference is held. */
  FD_TEST( !fd_geyser_bank_hold( g_core, 1UL ) );
  fd_geyser_bank_release( g_core, 1UL );
  FD_TEST( fd_geyser_core_ref_held_cnt( g_core )==1UL );
  fd_geyser_bank_release( g_core, 1UL );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  /* The references are back, so the bank cannot be claimed again. */
  FD_TEST( fd_geyser_bank_hold( g_core, 1UL )==-1 );
  expect_refs_balanced();
}

/* A drop request is answered in the same call, whatever a consumer
   claims, and the bank stops being sealed. */

static void
test_drop_bank_ref( void ) {
  core_new( 0, 0, 0UL );

  FD_TEST( !drive_commit( 1UL, 10UL, 0UL, 0UL, 1UL, 8UL ) );
  FD_TEST( !fd_geyser_bank_hold( g_core, 1UL ) );
  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 7UL, 100UL, 1000UL );
  FD_TEST( fd_geyser_core_ref_held_cnt( g_core )==1UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 1UL ) );

  ulong base = g_ev_cnt;
  drive_drop( 7UL );

  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );
  FD_TEST( !model_live( 7UL ) );
  expect_discard( base, 1UL, FD_GEYSER_DISCARD_DROPPED );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 1UL ) );

  /* The bank stays in the graph so that nothing is delivered for it at
     a deferred level, and a claim on it is refused. */
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );
  FD_TEST( fd_geyser_bank_hold( g_core, 1UL )==-1 );

  /* A later confirmation of the dropped bank reports the status: the
     level was reached, only the content is gone. */
  ulong ev_cnt = g_ev_cnt;
  drive_oc( 10UL, 1UL, 7UL );
  FD_TEST( g_ev_cnt==ev_cnt+1UL );
  expect_status( ev_cnt, 10UL, FD_GEYSER_SLOT_CONFIRMED, 1UL );
  ev_cnt = g_ev_cnt;

  /* A drop for a bank index the core knows nothing about is a
     no-op. */
  ulong msgs = g_release_msg_cnt;
  drive_drop( 3UL );
  FD_TEST( g_ev_cnt==ev_cnt );
  FD_TEST( g_release_msg_cnt==msgs );

  /* A second drop for a bank whose references already went back sends
     nothing either. */
  drive_drop( 7UL );
  FD_TEST( g_release_msg_cnt==msgs );

  expect_refs_balanced();
}

/* A bank that never seals produces no status at a deferred level. */

static void
test_incomplete_suppressed( void ) {
  core_new( 0, 1 /* records_gate */, 0UL );

  drive_slot( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 11UL, 10UL, 2UL, 1UL,       1UL, 101UL, 1010UL );

  /* The parent's transaction count is known, so slot 11 executed ten
     transactions and no record of them arrived. */
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );

  drive_oc( 11UL, 2UL, 1UL );
  drive_root( 11UL, 2UL, 1UL );
  FD_TEST( !count_status( 11UL, FD_GEYSER_SLOT_CONFIRMED ) );
  FD_TEST( !count_status( 11UL, FD_GEYSER_SLOT_FINALIZED ) );

  /* The processed status is unaffected by the seal. */
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_PROCESSED )==1UL );

  /* Both banks owe a status, so they are kept until their records
     arrive or the root leaves them behind, and neither holds a
     reference while it waits. */
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==2UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );

  expect_refs_balanced();
}

/* A record that arrives after the bank was confirmed carries the
   confirmed status with it. */

static void
test_pending_confirmed( void ) {
  core_new( 0, 1 /* records_gate */, 0UL );

  /* Slot 10 executed nothing and seals at once; slot 11 executed one
     transaction whose record has not arrived. */
  drive_slot_txns( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL, 0UL );
  drive_sysvars( 1UL, 10UL, 4 );
  drive_slot_txns( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1001UL, 1UL );
  drive_sysvars( 2UL, 11UL, 4 );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 1UL ) );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );

  drive_oc( 11UL, 2UL, 1UL );
  FD_TEST( !count_status( 11UL, FD_GEYSER_SLOT_CONFIRMED ) );
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==1UL );

  /* The record completes the bank, and the status it was owed goes out
     on the spot. */
  FD_TEST( !drive_commit( 2UL, 11UL, 0UL, 0UL, 0UL, 0UL ) );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 2UL ) );
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_CONFIRMED )==1UL );
  FD_TEST( !fd_geyser_core_pending_cnt( g_core ) );

  /* The transaction is reported before the status, so a consumer has
     the block in hand when the level arrives. */
  ulong txn_idx = ULONG_MAX;
  ulong cfm_idx = ULONG_MAX;
  for( ulong i=0UL; i<g_ev_cnt; i++ ) {
    if( g_ev[ i ].kind==EV_TXN ) txn_idx = i;
    if( g_ev[ i ].kind==EV_STATUS && g_ev[ i ].slot==11UL &&
        g_ev[ i ].status==FD_GEYSER_SLOT_CONFIRMED ) cfm_idx = i;
  }
  FD_TEST( txn_idx!=ULONG_MAX && cfm_idx!=ULONG_MAX && txn_idx<cfm_idx );

  expect_refs_balanced();
}

/* A record that arrives after the bank was rooted carries the
   finalized status with it, and the reference replay granted for the
   root went back when it was rooted. */

static void
test_pending_finalized( void ) {
  core_new( 0, 1 /* records_gate */, 0UL );

  drive_slot_txns( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL, 0UL );
  drive_sysvars( 1UL, 10UL, 4 );
  drive_slot_txns( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1001UL, 1UL );
  drive_sysvars( 2UL, 11UL, 4 );

  drive_root( 11UL, 2UL, 1UL );
  FD_TEST( count_status( 10UL, FD_GEYSER_SLOT_FINALIZED )==1UL ); /* it sealed in time */
  FD_TEST( !count_status( 11UL, FD_GEYSER_SLOT_FINALIZED ) );
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==1UL );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  FD_TEST( !drive_commit( 2UL, 11UL, 0UL, 0UL, 0UL, 0UL ) );
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( !fd_geyser_core_pending_cnt( g_core ) );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  expect_refs_balanced();
}

/* A record that never arrives costs its bank the level: the core gives
   up on it once the root has moved on. */

static void
test_pending_timeout( void ) {
  core_new( 0, 1 /* records_gate */, 0UL );

  drive_slot_txns( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL, 0UL );
  drive_sysvars( 1UL, 10UL, 4 );
  drive_slot_txns( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1001UL, 1UL );
  drive_sysvars( 2UL, 11UL, 4 );

  drive_root( 11UL, 2UL, 1UL );
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==1UL );

  /* The root moves past the bound, one slot at a time, each of those
     banks accounting for its own record. */
  ulong base = g_ev_cnt;
  for( ulong i=0UL; i<FD_GEYSER_PENDING_MAX_SLOTS+2UL; i++ ) {
    ulong slot     = 12UL+i;
    ulong bank_seq = 3UL+i;
    drive_slot_txns( slot, slot-1UL, bank_seq, bank_seq-1UL, bank_seq%BANK_IDX_MAX, 102UL+i, 1002UL+i, 0UL );
    drive_sysvars( bank_seq, slot, 4 );
    drive_root( slot, bank_seq, bank_seq%BANK_IDX_MAX );
  }

  /* Its finalized status went out without the content, and the bank
     stays in the graph. */
  FD_TEST( !fd_geyser_core_pending_cnt( g_core ) );
  FD_TEST( !count_discard( 2UL, FD_GEYSER_DISCARD_PENDING ) );
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );
  FD_TEST( fd_geyser_core_metrics( g_core )->pending_timeout_cnt==1UL );
  FD_TEST( g_ev_cnt>base );

  /* The banks that did account for their records were finalized as
     they went, and the one that never did held none of them back. */
  FD_TEST( count_status( 12UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( count_status( 12UL+FD_GEYSER_PENDING_MAX_SLOTS+1UL, FD_GEYSER_SLOT_FINALIZED )==1UL );

  expect_refs_balanced();
}

/* A bank that owes a status waits for its own records only: one that
   seals goes out whatever the banks around it are still waiting for,
   and one that can never seal holds nothing back. */

static void
test_pending_order( void ) {
  core_new( 0, 1 /* records_gate */, 0UL );

  drive_slot_txns( 10UL,  9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL, 2UL );
  drive_slot_txns( 11UL, 10UL, 2UL, 1UL,       1UL, 101UL, 1002UL, 2UL );
  drive_sysvars( 1UL, 10UL, 4 );
  drive_sysvars( 2UL, 11UL, 4 );

  /* Each block executed two transactions, and one record of slot 10
     has arrived. */
  FD_TEST( !drive_commit( 1UL, 10UL, 0UL, 0UL, 0UL, 0UL ) );

  drive_root( 11UL, 2UL, 1UL );
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==2UL );
  FD_TEST( !count_status( 10UL, FD_GEYSER_SLOT_FINALIZED ) );
  FD_TEST( !count_status( 11UL, FD_GEYSER_SLOT_FINALIZED ) );

  /* The younger bank's records arrive and it is finalized at once,
     while the older one is still waiting for its own. */
  FD_TEST( !drive_commit( 2UL, 11UL, 0UL, 0UL, 0UL, 0UL ) );
  FD_TEST( !drive_commit( 2UL, 11UL, 1UL, 1UL, 0UL, 0UL ) );
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( !count_status( 10UL, FD_GEYSER_SLOT_FINALIZED ) );
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==1UL );

  /* The older one follows when its last record arrives. */
  FD_TEST( !drive_commit( 1UL, 10UL, 1UL, 1UL, 0UL, 0UL ) );
  FD_TEST( count_status( 10UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( !fd_geyser_core_pending_cnt( g_core ) );

  /* A bank that never accounts for its records holds back neither the
     root walk nor the banks behind it: slot 13 is finalized as it is
     rooted, and slot 12 is given up on when its reference is taken
     back, which is when its own status goes out. */
  drive_slot_txns( 12UL, 11UL, 3UL, 2UL, 2UL, 102UL, 1004UL, 2UL );
  drive_slot_txns( 13UL, 12UL, 4UL, 3UL, 3UL, 103UL, 1004UL, 0UL );
  drive_sysvars( 3UL, 12UL, 4 );
  drive_sysvars( 4UL, 13UL, 4 );

  drive_root( 13UL, 4UL, 3UL );
  FD_TEST( count_status( 13UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( !count_status( 12UL, FD_GEYSER_SLOT_FINALIZED ) );
  FD_TEST( fd_geyser_core_pending_cnt( g_core )==1UL );

  drive_drop( 2UL );
  FD_TEST( !fd_geyser_core_pending_cnt( g_core ) );
  FD_TEST( !count_discard( 3UL, FD_GEYSER_DISCARD_PENDING ) );
  FD_TEST( count_status( 12UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( fd_geyser_core_metrics( g_core )->pending_dropped_cnt==1UL );

  expect_refs_balanced();
}

/* Replay restarting its bank sequence flushes the graph. */

static void
test_bank_seq_reset( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 200UL, 199UL, 500UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 201UL, 200UL, 501UL, 500UL,     1UL, 101UL, 1010UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );

  ulong base = g_ev_cnt;
  drive_slot( 300UL, 299UL, 1UL, ULONG_MAX, 2UL, 200UL, 2000UL );

  FD_TEST( count_discard( 500UL, FD_GEYSER_DISCARD_FLUSH )==1UL );
  FD_TEST( count_discard( 501UL, FD_GEYSER_DISCARD_FLUSH )==1UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );
  FD_TEST( fd_geyser_core_metrics( g_core )->flush_cnt==1UL );
  expect_status( base+2UL, 300UL, FD_GEYSER_SLOT_CREATED_BANK, 1UL );

  /* A fork completing a little out of order is not a restart. */
  drive_slot( 299UL, 298UL, 2UL, ULONG_MAX, 3UL, 199UL, 1990UL );
  FD_TEST( fd_geyser_core_metrics( g_core )->flush_cnt==1UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );

  expect_refs_balanced();
}

/* Banks that never resolve and fall far behind are dropped. */

static void
test_stale_sweep( void ) {
  core_new( 0, 0, 8UL /* stale_slots */ );

  drive_slot( 10UL, 9UL,  1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_slot( 18UL, 17UL, 2UL, ULONG_MAX, 1UL, 108UL, 1080UL );

  fd_geyser_core_housekeeping( g_core );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );

  drive_slot( 20UL, 19UL, 3UL, ULONG_MAX, 2UL, 110UL, 1100UL );
  fd_geyser_core_housekeeping( g_core );

  /* Slot 10 is more than eight slots behind slot 20, slot 18 is
     not. */
  FD_TEST( count_discard( 1UL, FD_GEYSER_DISCARD_STALE )==1UL );
  FD_TEST( !count_discard( 2UL, FD_GEYSER_DISCARD_STALE ) );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==2UL );

  expect_refs_balanced();
}

/* A tile that boots into a running validator is in the same position
   as one that lost notifications: replay may hold references granted
   to whatever ran in the slot before, and the core has no record of
   them.  The sweep the first notification bounds gives back exactly
   those, and leaves the grant published at that notification, which
   the core is about to read. */

static void
test_boot_sweep( void ) {
  core_new( 0, 0, 0UL );

  /* References granted to whatever ran in the slot before. */
  model_grant( 3UL,  g_seq++ ); g_grant_unseen++;
  model_grant( 3UL,  g_seq++ ); g_grant_unseen++;
  model_grant( 17UL, g_seq++ ); g_grant_unseen++;

  /* A reference granted with the notification the tile is about to
     read. */
  ulong first_seq = g_seq;
  model_grant( 21UL, first_seq ); g_grant_unseen++;

  fd_geyser_core_link_gap( g_core, first_seq );

  FD_TEST( !model_live( 3UL  ) );
  FD_TEST( !model_live( 17UL ) );
  FD_TEST( model_live( 21UL )==1UL );
  FD_TEST( g_release_msg_cnt>=BANK_IDX_MAX );
  FD_TEST( !fd_geyser_core_bank_cnt( g_core ) );

  /* The graph builds from that notification on, and the reference the
     sweep spared goes back when the core is done with it. */
  drive_slot( 50UL, 49UL, 7UL, ULONG_MAX, 21UL, 500UL, 5000UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );

  expect_refs_balanced();
}

/* An input gap flushes the graph and sweeps every bank index, so that
   no reference replay granted can be lost. */

static void
test_link_gap( void ) {
  core_new( 0, 0, 0UL );

  FD_TEST( !drive_commit( 1UL, 10UL, 0UL, 0UL, 1UL, 8UL ) );
  FD_TEST( !fd_geyser_bank_hold( g_core, 1UL ) );
  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  FD_TEST( fd_geyser_core_ref_held_cnt( g_core )==1UL );

  /* A reference replay granted for a notification the core never saw,
     which is what the sweep has to recover. */
  model_grant( 42UL, g_seq++ );
  g_grant_unseen++;
  FD_TEST( model_live( 42UL )==1UL );

  fd_geyser_core_link_gap( g_core, g_seq );

  FD_TEST( count_discard( 1UL, FD_GEYSER_DISCARD_FLUSH )==1UL );
  FD_TEST( !fd_geyser_core_bank_cnt( g_core ) );
  FD_TEST( g_release_msg_cnt>=BANK_IDX_MAX );
  model_expect_drained();

  /* The graph resynchronizes from the next notification. */
  drive_slot( 30UL, 29UL, 100UL, ULONG_MAX, 5UL, 300UL, 3000UL );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );
  expect_refs_balanced();
}

/* The pool is bounded: a fork history longer than it holds drops its
   oldest banks instead of growing. */

static void
test_pool_full( void ) {
  core_new( 0, 0, 0UL );

  /* Twice the live bank count of records, all unrooted. */
  for( ulong i=0UL; i<3UL*BANK_IDX_MAX; i++ ) {
    drive_slot( 1000UL+i, 999UL+i, 1UL+i, ULONG_MAX, i%BANK_IDX_MAX, 100UL+i, 1000UL );
  }

  FD_TEST( fd_geyser_core_bank_cnt( g_core )<=2UL*BANK_IDX_MAX );
  FD_TEST( fd_geyser_core_metrics( g_core )->pool_full_cnt>0UL );
  expect_refs_balanced();
}

/* A root the core never saw still gives its reference back. */

static void
test_unknown_root( void ) {
  core_new( 0, 0, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  drive_root( 12UL, 99UL, 3UL );

  FD_TEST( fd_geyser_core_metrics( g_core )->unknown_bank_cnt==1UL );
  FD_TEST( count_discard( 1UL, FD_GEYSER_DISCARD_PRUNED )==1UL );
  expect_refs_balanced();
}

/* A bank whose records arrived before replay ever named it, and which
   is then rooted: the root names the bank's pool index, so the
   reference it grants can be given back by name.  Before the index
   was adopted the release named no index at all. */

static void
test_root_names_record_bank( void ) {
  core_new( 0, 0, 0UL );

  /* A record creates the bank; replay has not completed its slot */
  FD_TEST( !drive_commit( 5UL, 20UL, 0UL, 0UL, 1UL, 8UL ) );
  FD_TEST( fd_geyser_core_bank_cnt( g_core )==1UL );

  drive_root( 20UL, 5UL, 3UL );

  FD_TEST( !fd_geyser_core_metrics( g_core )->ref_unnamed_cnt );
  FD_TEST( model_live( 3UL )==0UL );
  expect_refs_balanced();

  /* A root naming a pool index replay does not have is refused
     outright, rather than released under an index that is not one. */
  core_new( 0, 0, 0UL );
  FD_TEST( !drive_commit( 6UL, 21UL, 0UL, 0UL, 1UL, 8UL ) );
  fd_replay_root_advanced_t msg = { .slot = 21UL, .bank_seq = 6UL, .bank_idx = BANK_IDX_MAX };
  fd_geyser_core_root_advanced( g_core, &msg, g_seq++ );
  FD_TEST( fd_geyser_core_metrics( g_core )->unknown_bank_cnt==1UL );
  expect_refs_balanced();
}

static void
test_end_of_startup( void ) {
  core_new( 0, 0, 0UL );
  fd_geyser_core_end_of_startup( g_core );
  FD_TEST( g_ev_cnt==1UL && ev_at( 0UL )->kind==EV_STARTUP );
  fd_geyser_core_end_of_startup( g_core );
  FD_TEST( g_ev_cnt==1UL );
}

/* A long run of slots with a trailing root, the shape of a live
   validator, leaves nothing behind. */

static void
test_long_run( void ) {
  core_new( 0, 0, 0UL );

  for( ulong slot=1UL; slot<=500UL; slot++ ) {
    drive_slot( slot, slot-1UL, slot, slot>1UL ? slot-1UL : ULONG_MAX,
                slot%BANK_IDX_MAX, slot, 10UL*slot );
    if( slot>32UL ) {
      ulong rooted = slot-32UL;
      drive_oc  ( rooted, rooted, rooted%BANK_IDX_MAX );
      drive_root( rooted, rooted, rooted%BANK_IDX_MAX );
    }
    fd_geyser_core_housekeeping( g_core );
  }

  FD_TEST( fd_geyser_core_bank_cnt( g_core )<=33UL );
  FD_TEST( count_status( 400UL, FD_GEYSER_SLOT_PROCESSED )==1UL );
  FD_TEST( count_status( 400UL, FD_GEYSER_SLOT_CONFIRMED )==1UL );
  FD_TEST( count_status( 400UL, FD_GEYSER_SLOT_FINALIZED )==1UL );
  FD_TEST( !fd_geyser_core_metrics( g_core )->pool_full_cnt );
  expect_refs_balanced();
}

/* A drop request decided before a bank index was recycled must not
   take back the grant of the bank that is at the index now, which the
   core has not read yet. */

static void
test_drop_after_recycle( void ) {
  core_new( 0, 0, 0UL );

  /* The bank at index 7 is published and its reference goes straight
     back, so replay is free to recycle the index. */
  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 7UL, 100UL, 1000UL );
  FD_TEST( !model_live( 7UL ) );

  /* Replay publishes the drop of the old bank, then recycles index 7
     and grants a reference for the new bank there.  Both are ahead of
     the core, which is still at the drop. */
  ulong drop_seq  = g_seq++;
  ulong grant_seq = g_seq++;
  model_grant( 7UL, grant_seq );

  fd_geyser_core_drop_bank_ref( g_core, 7UL, drop_seq );
  if( FD_UNLIKELY( model_live( 7UL )!=1UL ) )
    FD_LOG_ERR(( "the drop took back the grant published at seq %lu", grant_seq ));

  /* The core reads the new bank and owns that grant. */
  fd_replay_slot_completed_t msg = {
    .slot              = 11UL,
    .parent_slot       = 10UL,
    .bank_seq          = 2UL,
    .parent_bank_seq   = ULONG_MAX,
    .bank_idx          = 7UL,
    .block_height      = 101UL,
    .transaction_count = 1010UL
  };
  fd_geyser_core_slot_completed( g_core, &msg, grant_seq );
  FD_TEST( !model_live( 7UL ) ); /* given back with a bound above it */

  expect_refs_balanced();
}

/* The sweep after an input gap must give back the grants that went
   missing and leave the ones that are still on their way. */

static void
test_link_gap_queued_grant( void ) {
  core_new( 0, 0, 0UL );

  /* A grant the core never reads, because the frag that carried it
     was overrun. */
  ulong lost_seq = g_seq++;
  model_grant( 5UL, lost_seq );
  g_grant_unseen++;

  /* Two frags replay published after it that the core is about to
     read: the first one after the gap, and one behind it. */
  ulong first_seq = g_seq++;
  ulong next_seq  = g_seq++;
  model_grant( 6UL, first_seq );
  model_grant( 8UL, next_seq  );

  fd_geyser_core_link_gap( g_core, first_seq );

  FD_TEST( !model_live( 5UL ) );        /* lost, recovered by the sweep */
  FD_TEST( model_live( 6UL )==1UL );    /* the frag the core is about to read */
  FD_TEST( model_live( 8UL )==1UL );    /* still queued */

  /* The core reads them and gives both back. */
  fd_replay_slot_completed_t a = { .slot = 20UL, .parent_slot = 19UL, .bank_seq = 10UL,
                                   .parent_bank_seq = ULONG_MAX, .bank_idx = 6UL,
                                   .block_height = 200UL, .transaction_count = 2000UL };
  fd_geyser_core_slot_completed( g_core, &a, first_seq );
  fd_replay_slot_completed_t b = { .slot = 21UL, .parent_slot = 20UL, .bank_seq = 11UL,
                                   .parent_bank_seq = 10UL, .bank_idx = 8UL,
                                   .block_height = 201UL, .transaction_count = 2010UL };
  fd_geyser_core_slot_completed( g_core, &b, next_seq );

  FD_TEST( !model_live( 6UL ) );
  FD_TEST( !model_live( 8UL ) );
  expect_refs_balanced();
}

/* Banks whose identifiers all hash to one place fill a probe
   sequence.  The core drops its graph and carries on instead of
   dying. */

static void
test_map_full( void ) {
  core_new( 0, 0, 0UL );

  /* The core indexes banks by bank_seq; collect enough identifiers
     that share a home slot to overrun one probe sequence.  The map
     has four entries per pool record, and the pool holds twice the
     live bank count. */
  ulong map_sz = fd_ulong_pow2_up( 4UL*2UL*BANK_IDX_MAX );
  ulong home   = fd_ulong_hash( 1UL ) & (map_sz-1UL);

  ulong seq[ 48 ];
  ulong cnt = 0UL;
  for( ulong s=1UL; s<10000000UL && cnt<48UL; s++ ) {
    if( ( fd_ulong_hash( s ) & (map_sz-1UL) )==home ) seq[ cnt++ ] = s;
  }
  FD_TEST( cnt==48UL );

  for( ulong i=0UL; i<cnt; i++ ) {
    drive_slot( 100UL+i, 99UL+i, seq[ i ], ULONG_MAX, i%BANK_IDX_MAX, 100UL+i, 1000UL );
  }

  FD_TEST( fd_geyser_core_metrics( g_core )->map_full_cnt>0UL );
  FD_TEST( fd_geyser_core_metrics( g_core )->flush_cnt>0UL );

  /* The graph works after the flush. */
  ulong base = g_ev_cnt;
  drive_slot( 500UL, 499UL, 900001UL, ULONG_MAX, 3UL, 500UL, 5000UL );
  expect_status( base, 500UL, FD_GEYSER_SLOT_CREATED_BANK, 900001UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 900001UL ) );
  expect_refs_balanced();
}

/* Records ************************************************************/

static ulong
count_kind( int kind ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<g_ev_cnt; i++ ) cnt += g_ev[ i ].kind==kind;
  return cnt;
}

/* The records of a bank arrive before it freezes: the first one puts
   the bank in the graph and reports the synthesized CreatedBank, and
   the notification that freezes it fills in its parent and its block
   summary without reporting CreatedBank again.  The bank is sealed
   only once its transaction count matches and all four sysvar writes
   have been seen. */

static void
test_records_seal( void ) {
  core_new( 0, 1, 0UL );

  /* The first bank of a run has no parent in the graph, so its executed
     transaction count is unknown and it never seals.  It is here to be
     the parent of the bank under test. */
  drive_sysvars( 1UL, 10UL, 4 );
  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 1UL ) );

  ulong base = g_ev_cnt;

  /* The first record of the child creates it. */
  FD_TEST( !drive_commit( 2UL, 11UL, 0UL, 0UL, 2UL, 8UL ) );
  expect_status( base, 11UL, FD_GEYSER_SLOT_CREATED_BANK, 2UL );
  FD_TEST( !ev_at( base )->has_parent );
  FD_TEST( g_ev[ base+1UL ].kind==EV_TXN );
  FD_TEST( g_ev[ base+2UL ].kind==EV_ACCOUNT );
  FD_TEST( g_ev[ base+3UL ].kind==EV_ACCOUNT );
  FD_TEST( g_ev[ base+2UL ].data_sz==8UL );
  FD_TEST( g_ev[ base+2UL ].write_version<g_ev[ base+3UL ].write_version );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );

  FD_TEST( !drive_commit( 2UL, 11UL, 1UL, 1UL, 1UL, 8UL ) );
  drive_sysvars( 2UL, 11UL, 4 );

  /* A phase 0 write orders before a transaction write, a phase 2 write
     after it. */
  FD_TEST( !drive_commit( 2UL, 11UL, 2UL, 2UL, 0UL, 0UL ) );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );

  /* Freezing the bank fills in the parent and seals it: three records
     for three executed transactions. */
  ulong pre_completed = g_ev_cnt;
  drive_slot( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1003UL );
  expect_meta  ( pre_completed,      11UL, 2UL );
  expect_status( pre_completed+1UL,  11UL, FD_GEYSER_SLOT_PROCESSED, 2UL );
  FD_TEST( ev_at( pre_completed )->has_parent && ev_at( pre_completed )->parent_slot==10UL );
  FD_TEST( count_status( 11UL, FD_GEYSER_SLOT_CREATED_BANK )==1UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 2UL ) );

  /* A bank whose parent the core never saw still seals, because replay
     counts the transactions of the block itself. */
  drive_sysvars( 9UL, 20UL, 4 );
  FD_TEST( !drive_commit( 9UL, 20UL, 0UL, 0UL, 1UL, 8UL ) );
  drive_slot_counted( 20UL, 19UL, 9UL, ULONG_MAX, 4UL, 200UL, 1UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 9UL ) );

  fd_geyser_core_metrics_t const * m = fd_geyser_core_metrics( g_core );
  FD_TEST( m->txn_record_cnt==4UL   );
  FD_TEST( m->write_record_cnt==12UL );
  FD_TEST( m->account_cnt==16UL      ); /* 4 written by transactions, 12 sysvars */
  FD_TEST( !m->record_dropped_cnt   );
  FD_TEST( count_kind( EV_TXN )==4UL );

  expect_refs_balanced();
}

/* A bank whose records do not add up is not sealed, and neither is one
   that is missing a sysvar write. */

static void
test_records_short( void ) {
  core_new( 0, 1, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );

  /* Two records for three executed transactions. */
  drive_sysvars( 2UL, 11UL, 4 );
  FD_TEST( !drive_commit( 2UL, 11UL, 0UL, 0UL, 1UL, 8UL ) );
  FD_TEST( !drive_commit( 2UL, 11UL, 1UL, 1UL, 1UL, 8UL ) );
  drive_slot( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1003UL );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );
  FD_TEST( fd_geyser_core_metrics( g_core )->bank_incomplete_cnt[ FD_GEYSER_INCOMPLETE_RECORDS ]>0UL );

  /* The missing record arrives late and the bank seals. */
  FD_TEST( !drive_commit( 2UL, 11UL, 2UL, 2UL, 1UL, 8UL ) );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 2UL ) );

  /* Three sysvar writes are not enough. */
  drive_sysvars( 3UL, 12UL, 3 );
  FD_TEST( !drive_commit( 3UL, 12UL, 0UL, 0UL, 1UL, 8UL ) );
  drive_slot( 12UL, 11UL, 3UL, 2UL, 2UL, 102UL, 1004UL );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 3UL ) );
  FD_TEST( fd_geyser_core_metrics( g_core )->bank_incomplete_cnt[ FD_GEYSER_INCOMPLETE_SYSVARS ]>0UL );

  /* The fourth arrives and it seals. */
  FD_TEST( !drive_write( 3UL, 12UL, 2U, 3UL, &fd_sysvar_slot_history_id ) );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 3UL ) );

  expect_refs_balanced();
}

/* A gap on a record link gives up on the banks in flight, and leaves
   the banks that already sealed alone. */

static void
test_record_gap( void ) {
  core_new( 0, 1, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );

  /* A bank sealed before the gap. */
  drive_sysvars( 2UL, 11UL, 4 );
  FD_TEST( !drive_commit( 2UL, 11UL, 0UL, 0UL, 1UL, 8UL ) );
  drive_slot( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1001UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 2UL ) );

  /* A bank in flight. */
  drive_sysvars( 3UL, 12UL, 4 );
  FD_TEST( !drive_commit( 3UL, 12UL, 0UL, 0UL, 1UL, 8UL ) );

  fd_geyser_core_record_gap( g_core );

  FD_TEST( fd_geyser_bank_is_complete( g_core, 2UL ) ); /* sealed before the gap */
  drive_slot( 12UL, 11UL, 3UL, 2UL, 2UL, 102UL, 1002UL );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 3UL ) ); /* records may have been lost */
  FD_TEST( fd_geyser_core_metrics( g_core )->bank_incomplete_cnt[ FD_GEYSER_INCOMPLETE_GAP ]>0UL );
  FD_TEST( fd_geyser_core_metrics( g_core )->record_gap_cnt==1UL );

  /* A bank that comes into being after the gap is unaffected. */
  drive_sysvars( 4UL, 13UL, 4 );
  FD_TEST( !drive_commit( 4UL, 13UL, 0UL, 0UL, 1UL, 8UL ) );
  drive_slot( 13UL, 12UL, 4UL, 3UL, 3UL, 103UL, 1003UL );
  FD_TEST( fd_geyser_bank_is_complete( g_core, 4UL ) );

  expect_refs_balanced();
}

/* Records naming a bank that is gone change nothing. */

static void
test_records_bank_gone( void ) {
  core_new( 0, 1, 0UL );

  drive_slot( 10UL, 9UL, 1UL, ULONG_MAX, 0UL, 100UL, 1000UL );

  /* A bank whose reference replay took back. */
  drive_sysvars( 2UL, 11UL, 4 );
  drive_slot( 11UL, 10UL, 2UL, 1UL, 1UL, 101UL, 1001UL );
  drive_drop( 1UL );
  FD_TEST( !fd_geyser_bank_is_complete( g_core, 2UL ) );

  ulong base = g_ev_cnt;
  FD_TEST( drive_commit( 2UL, 11UL, 5UL, 5UL, 1UL, 8UL )==-1 );
  FD_TEST( drive_write( 2UL, 11UL, 0U, 9UL, &fd_sysvar_clock_id )==-1 );
  FD_TEST( g_ev_cnt==base );
  FD_TEST( fd_geyser_core_metrics( g_core )->record_dropped_cnt==2UL );

  /* A bank the root left behind.  Its records are not tracked again. */
  drive_sysvars( 3UL, 12UL, 4 );
  FD_TEST( !drive_commit( 3UL, 12UL, 0UL, 0UL, 1UL, 8UL ) );
  drive_slot( 12UL, 11UL, 3UL, 2UL, 2UL, 102UL, 1002UL );
  drive_root( 12UL, 3UL, 2UL );

  base = g_ev_cnt;
  FD_TEST( drive_commit( 4UL, 12UL, 1UL, 1UL, 1UL, 8UL )==-1 );
  FD_TEST( g_ev_cnt==base );

  expect_refs_balanced();
}

/* Records whose fields do not address the record itself are dropped. */

static void
test_records_malformed( void ) {
  core_new( 0, 1, 0UL );

  uchar keys[ 2 ][ 32 ] = {{0}};
  ulong lamports[ 2 ]   = { 0UL, 0UL };
  uchar writable[ 2 ]   = { 1, 1 };
  uchar data    [ 8 ]   = {0};

  fd_event_internal_commit_touched_t touched[1] = {{
    .key_idx = 0U, .lamports = 1UL, .data_sz = 8UL
  }};

  fd_event_internal_commit_t ev[1];
  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = NULL,
    .keys          = (uchar const (*)[ 32UL ])keys,
    .pre_lamports  = lamports,
    .post_lamports = lamports,
    .is_writable   = writable,
    .touched       = touched
  };

  /* No keys at all. */
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq = 1UL;
  ev->slot     = 10UL;
  FD_TEST( fd_geyser_core_commit_record( g_core, &parts )==-1 );

  /* Balance arrays that do not match the keys. */
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq         = 1UL;
  ev->slot             = 10UL;
  ev->keys_cnt         = 2UL;
  ev->pre_lamports_cnt = 1UL;
  FD_TEST( fd_geyser_core_commit_record( g_core, &parts )==-1 );

  /* A written account naming a key that is not there. */
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq          = 1UL;
  ev->slot              = 10UL;
  ev->keys_cnt          = 2UL;
  ev->pre_lamports_cnt  = 2UL;
  ev->post_lamports_cnt = 2UL;
  ev->is_writable_cnt   = 2UL;
  ev->touched_cnt       = 1UL;
  touched->key_idx      = 7U;
  FD_TEST( fd_geyser_core_commit_record( g_core, &parts )==-1 );

  /* Loaded address counts that overrun the keys. */
  touched->key_idx      = 0U;
  ev->acct_addr_cnt     = 3U;
  FD_TEST( fd_geyser_core_commit_record( g_core, &parts )==-1 );
  ev->acct_addr_cnt     = 1U;
  ev->adtl_writable_cnt = 2U;
  FD_TEST( fd_geyser_core_commit_record( g_core, &parts )==-1 );

  /* A well formed record is still accepted afterwards. */
  ev->acct_addr_cnt     = 2U;
  ev->adtl_writable_cnt = 0U;
  FD_TEST( !fd_geyser_core_commit_record( g_core, &parts ) );

  FD_TEST( fd_geyser_core_metrics( g_core )->record_dropped_cnt==5UL );
  FD_TEST( fd_geyser_core_metrics( g_core )->txn_record_cnt==1UL );

  /* A runtime write record with no keys, and one naming a key that is
     not there. */
  fd_event_internal_runtime_write_touched_t wtouched[1] = {{ .key_idx = 3U }};
  fd_event_internal_runtime_write_t wev[1];
  fd_event_internal_runtime_write_parts_t wparts = {
    .prefix       = wev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = wtouched,
    .account_data = data
  };
  fd_memset( wev, 0, sizeof(fd_event_internal_runtime_write_t) );
  wev->bank_seq = 1UL;
  wev->slot     = 10UL;
  FD_TEST( fd_geyser_core_runtime_write_record( g_core, &wparts )==-1 );
  wev->keys_cnt    = 1UL;
  wev->touched_cnt = 1UL;
  FD_TEST( fd_geyser_core_runtime_write_record( g_core, &wparts )==-1 );
  wev->phase = 5U;
  FD_TEST( fd_geyser_core_runtime_write_record( g_core, &wparts )==-1 );

  expect_refs_balanced();
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_processed();             FD_LOG_NOTICE(( "pass: processed"             ));
  test_equivocation_oc();       FD_LOG_NOTICE(( "pass: equivocation_oc"       ));
  test_equivocation_root();     FD_LOG_NOTICE(( "pass: equivocation_root"     ));
  test_root_ancestors();        FD_LOG_NOTICE(( "pass: root_ancestors"        ));
  test_alpenglow_root();        FD_LOG_NOTICE(( "pass: alpenglow_root"        ));
  test_dead();                  FD_LOG_NOTICE(( "pass: dead"                  ));
  test_claim();                 FD_LOG_NOTICE(( "pass: claim"                 ));
  test_drop_bank_ref();         FD_LOG_NOTICE(( "pass: drop_bank_ref"         ));
  test_drop_after_recycle();    FD_LOG_NOTICE(( "pass: drop_after_recycle"    ));
  test_incomplete_suppressed(); FD_LOG_NOTICE(( "pass: incomplete_suppressed" ));
  test_pending_confirmed();     FD_LOG_NOTICE(( "pass: pending_confirmed"     ));
  test_pending_finalized();     FD_LOG_NOTICE(( "pass: pending_finalized"     ));
  test_pending_timeout();       FD_LOG_NOTICE(( "pass: pending_timeout"       ));
  test_pending_order();         FD_LOG_NOTICE(( "pass: pending_order"         ));
  test_bank_seq_reset();        FD_LOG_NOTICE(( "pass: bank_seq_reset"        ));
  test_stale_sweep();           FD_LOG_NOTICE(( "pass: stale_sweep"           ));
  test_boot_sweep();            FD_LOG_NOTICE(( "pass: boot_sweep"            ));
  test_link_gap();              FD_LOG_NOTICE(( "pass: link_gap"              ));
  test_link_gap_queued_grant(); FD_LOG_NOTICE(( "pass: link_gap_queued_grant" ));
  test_map_full();              FD_LOG_NOTICE(( "pass: map_full"              ));
  test_pool_full();             FD_LOG_NOTICE(( "pass: pool_full"             ));
  test_unknown_root();          FD_LOG_NOTICE(( "pass: unknown_root"          ));
  test_root_names_record_bank(); FD_LOG_NOTICE(( "pass: root_names_record_bank" ));
  test_end_of_startup();        FD_LOG_NOTICE(( "pass: end_of_startup"        ));
  test_long_run();              FD_LOG_NOTICE(( "pass: long_run"              ));
  test_records_seal();          FD_LOG_NOTICE(( "pass: records_seal"          ));
  test_records_short();         FD_LOG_NOTICE(( "pass: records_short"         ));
  test_record_gap();            FD_LOG_NOTICE(( "pass: record_gap"            ));
  test_records_bank_gone();     FD_LOG_NOTICE(( "pass: records_bank_gone"     ));
  test_records_malformed();     FD_LOG_NOTICE(( "pass: records_malformed"     ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
