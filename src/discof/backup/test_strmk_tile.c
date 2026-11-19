/* strmk key store, transaction resolution and stream tests */

#define _GNU_SOURCE
#define FD_TILE_TEST
#include "fd_strmk_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/accdb/fd_accdb.h"

/* What the tile published last on the file server link. */

static ulong          test_publish_cnt;
static ulong          test_publish_sig;
static fd_strmk_msg_t test_publish_msg;
static void *         test_publish_mem;

static ulong
test_stem_publish( fd_stem_context_t * stem    FD_PARAM_UNUSED,
                   ulong               out_idx FD_PARAM_UNUSED,
                   ulong               sig,
                   ulong               chunk,
                   ulong               sz,
                   ulong               ctl     FD_PARAM_UNUSED,
                   ulong               tsorig  FD_PARAM_UNUSED,
                   ulong               tspub   FD_PARAM_UNUSED ) {
  test_publish_cnt++;
  test_publish_sig = sig;
  if( sz==sizeof(fd_strmk_msg_t) ) test_publish_msg = *(fd_strmk_msg_t const *)fd_chunk_to_laddr_const( test_publish_mem, chunk );
  return 0UL;
}

/* Accounts the tile reads: a lookup table and an upgradeable program. */

#define TEST_ACC_MAX (2UL)
static ulong       test_acc_cnt;
static fd_pubkey_t test_acc_key  [ TEST_ACC_MAX ];
static fd_pubkey_t test_acc_owner[ TEST_ACC_MAX ];
static uchar       test_acc_data [ TEST_ACC_MAX ][ 256 ];
static ulong       test_acc_len  [ TEST_ACC_MAX ];

static int
test_accdb_read( fd_accdb_t *       accdb FD_PARAM_UNUSED,
                 fd_accdb_fork_id_t fork_id FD_PARAM_UNUSED,
                 uchar const *      pubkey,
                 ulong *            out_lamports,
                 int *              out_executable,
                 uchar *            out_owner,
                 uchar *            out_data,
                 ulong *            out_data_len ) {
  for( ulong i=0UL; i<test_acc_cnt; i++ ) {
    if( memcmp( pubkey, test_acc_key[ i ].uc, 32UL ) ) continue;
    *out_lamports   = 1UL;
    *out_executable = 0;
    *out_data_len   = test_acc_len[ i ];
    memcpy( out_owner, test_acc_owner[ i ].uc, 32UL );
    if( out_data ) memcpy( out_data, test_acc_data[ i ], test_acc_len[ i ] );
    return FD_ACCDB_READ_ONE_NOCACHE_CACHE;
  }
  *out_lamports = 0UL;
  *out_data_len = 0UL;
  return FD_ACCDB_READ_ONE_NOCACHE_MISS;
}

#define fd_stem_publish           test_stem_publish
#define fd_accdb_read_one_nocache test_accdb_read
#include "fd_strmk_tile.c"
#undef fd_accdb_read_one_nocache
#undef fd_stem_publish
#include "../../util/tmpl/fd_unit_test.c"

#include <stdlib.h>

struct keys_env {
  fd_strmk_t * ctx;
  void *       map_mem;
  void *       pool_mem;
  void *       raw_mem;
};

typedef struct keys_env keys_env_t;

static void *
alloc( ulong align,
       ulong sz ) {
  void * mem = aligned_alloc( align, fd_ulong_align_up( sz, align ) );
  FD_TEST( mem );
  return mem;
}

/* keys_env_create sets up a store with the tile's full capacity, so
   that the pool index walks match the tile. */

static keys_env_t *
keys_env_create( keys_env_t * env ) {
  env->ctx      = alloc( alignof(fd_strmk_t),    sizeof(fd_strmk_t) );
  env->map_mem  = alloc( strmk_key_map_align(),  strmk_key_map_footprint( strmk_key_map_chain_cnt_est( STRMK_KEY_MAX ) ) );
  env->pool_mem = alloc( strmk_key_pool_align(), strmk_key_pool_footprint( STRMK_KEY_MAX ) );
  env->raw_mem  = alloc( 4096UL, FD_SSMANIFEST_BUF_MIN );
  memset( env->ctx, 0, sizeof(fd_strmk_t) );
  env->ctx->raw = env->raw_mem;
  env->ctx->key_map  = strmk_key_map_join( strmk_key_map_new( env->map_mem, strmk_key_map_chain_cnt_est( STRMK_KEY_MAX ), 42UL ) );
  env->ctx->key_pool = strmk_key_pool_join( strmk_key_pool_new( env->pool_mem, STRMK_KEY_MAX ) );
  FD_TEST( env->ctx->key_map && env->ctx->key_pool );
  for( ulong i=0UL; i<STRMK_KEY_MAX; i++ ) strmk_key_pool_ele( env->ctx->key_pool, i )->slot = ULONG_MAX;
  env->ctx->cur = UINT_MAX;
  return env;
}

static void
keys_env_destroy( keys_env_t * env ) {
  free( env->raw_mem );
  free( env->pool_mem );
  free( env->map_mem );
  free( env->ctx );
}

/* keys_fill stores cnt distinct keys first_key, first_key+1, ... at
   slot, a transaction's worth at a time. */

static void
keys_fill( keys_env_t * env,
           ulong        slot,
           ulong        cnt,
           ulong        first_key ) {
  fd_pubkey_t keys[ STRMK_TXN_KEYS_MAX ];
  for( ulong i=0UL; i<cnt; i+=STRMK_TXN_KEYS_MAX ) {
    ulong n = fd_ulong_min( STRMK_TXN_KEYS_MAX, cnt-i );
    memset( keys, 0, sizeof(keys) );
    for( ulong j=0UL; j<n; j++ ) keys[ j ].ul[0] = first_key+i+j;
    strmk_store_keys( env->ctx, slot, keys, n );
  }
}

static int
key_stored( keys_env_t * env,
            ulong        first_word ) {
  fd_pubkey_t key = { .ul = { first_word } };
  return !!strmk_key_map_ele_query( env->ctx->key_map, &key, NULL, env->ctx->key_pool );
}

/* A key is stored once, with the newest slot that touched it. */

FD_UNIT_TEST( keys_dedup ) {
  keys_env_t env[1];
  keys_env_create( env );
  keys_fill( env, 100UL, 3UL, 1UL );
  keys_fill( env, 101UL, 3UL, 2UL );
  keys_fill( env,  99UL, 1UL, 1UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==4UL );
  fd_pubkey_t key = { .ul = { 2UL } };
  FD_TEST( strmk_key_map_ele_query( env->ctx->key_map, &key, NULL, env->ctx->key_pool )->slot==101UL );
  key.ul[0] = 1UL;
  FD_TEST( strmk_key_map_ele_query( env->ctx->key_map, &key, NULL, env->ctx->key_pool )->slot==100UL );
  FD_TEST( env->ctx->metrics.key_cnt==7UL && env->ctx->metrics.key_stored_cnt==4UL );
  keys_env_destroy( env );
}

/* Pruning frees the keys last touched at or below a slot. */

FD_UNIT_TEST( keys_prune ) {
  keys_env_t env[1];
  keys_env_create( env );
  keys_fill( env, 100UL, 2UL, 1UL );
  keys_fill( env, 101UL, 2UL, 3UL );
  keys_fill( env, 102UL, 1UL, 1UL );
  strmk_key_prune( env->ctx, 101UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==1UL );
  fd_pubkey_t key = { .ul = { 1UL } };
  FD_TEST( strmk_key_map_ele_query( env->ctx->key_map, &key, NULL, env->ctx->key_pool ) );
  key.ul[0] = 3UL;
  FD_TEST( !strmk_key_map_ele_query( env->ctx->key_map, &key, NULL, env->ctx->key_pool ) );
  keys_env_destroy( env );
}

/* A full pool frees the keys older than the window, else drops. */

FD_UNIT_TEST( keys_full ) {
  keys_env_t env[1];
  keys_env_create( env );
  keys_fill( env, 100UL, STRMK_KEY_MAX, 1UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==STRMK_KEY_MAX );
  keys_fill( env, 101UL, 1UL, STRMK_KEY_MAX+1UL );
  FD_TEST( env->ctx->metrics.key_dropped_cnt==1UL );
  keys_fill( env, 100UL+STRMK_WINDOW, 1UL, STRMK_KEY_MAX+1UL );
  FD_TEST( env->ctx->metrics.key_dropped_cnt==1UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==1UL );
  keys_env_destroy( env );
}

/* A transaction's keys: its account keys, each lookup table and the
   addresses it picks from the table, read where the block's parent
   had it.  Bad indices and unreadable tables give nothing. */

FD_UNIT_TEST( txn_keys ) {
  keys_env_t env[1];
  keys_env_create( env );

  fd_strmk_txn_msg_t msg[1];
  memset( msg, 0, sizeof(*msg) );
  msg->slot               = 7UL;
  msg->parent_fork_id.val = 3;
  uchar *    payload = msg->txn->payload;
  fd_txn_t * txn     = TXN( msg->txn );
  /* payload: keys 1 and 2, the table key 10, writable index 2, readonly indices 0 and 7 */
  ((fd_pubkey_t *)payload)[ 0 ].ul[0] = 1UL;
  ((fd_pubkey_t *)payload)[ 1 ].ul[0] = 2UL;
  ((fd_pubkey_t *)payload)[ 2 ].ul[0] = 10UL;
  payload[ 96 ] = 2; payload[ 97 ] = 0; payload[ 98 ] = 7;
  txn->acct_addr_cnt         = 2;
  txn->acct_addr_off         = 0;
  txn->instr_cnt             = 0;
  txn->addr_table_lookup_cnt = 1;
  fd_txn_acct_addr_lut_t * lut = fd_txn_get_address_tables( txn );
  lut->addr_off     = 64;
  lut->writable_off = 96; lut->writable_cnt = 1;
  lut->readonly_off = 97; lut->readonly_cnt = 2;

  /* the table has addresses 100, 101 and 102 */
  test_acc_cnt = 1UL;
  test_acc_key  [ 0 ].ul[0] = 10UL;
  test_acc_owner[ 0 ]       = fd_solana_address_lookup_table_program_id;
  test_acc_len  [ 0 ]       = FD_LOOKUP_TABLE_META_SIZE+3UL*32UL;
  memset( test_acc_data[ 0 ], 0, sizeof(test_acc_data[ 0 ]) );
  fd_alut_meta_t const meta = { .discriminant = FD_ALUT_STATE_DISC_LOOKUP_TABLE, .deactivation_slot = ULONG_MAX };
  FD_TEST( !fd_alut_state_encode( &meta, test_acc_data[ 0 ], FD_LOOKUP_TABLE_META_SIZE ) );
  for( ulong i=0UL; i<3UL; i++ ) ((fd_pubkey_t *)( test_acc_data[ 0 ]+FD_LOOKUP_TABLE_META_SIZE ))[ i ].ul[0] = 100UL+i;

  strmk_store_txn( env->ctx, msg );
  FD_TEST( env->ctx->metrics.key_cnt==5UL && strmk_key_pool_used( env->ctx->key_pool )==5UL );
  FD_TEST( key_stored( env, 1UL ) && key_stored( env, 2UL ) && key_stored( env, 10UL ) );
  FD_TEST( key_stored( env, 102UL ) && key_stored( env, 100UL ) && !key_stored( env, 101UL ) );

  /* a table that does not exist: only the table key */
  test_acc_cnt = 0UL;
  ((fd_pubkey_t *)payload)[ 2 ].ul[0] = 11UL;
  strmk_store_txn( env->ctx, msg );
  FD_TEST( env->ctx->metrics.key_cnt==8UL && key_stored( env, 11UL ) );
  keys_env_destroy( env );
}

/* Reading an upgradeable program for a stream sends its program data
   account too. */

FD_UNIT_TEST( programdata_key ) {
  keys_env_t env[1];
  keys_env_create( env );
  fd_strmk_t * ctx = env->ctx;
  ctx->cur = 0U;

  /* program 20 points at program data 21 */
  test_acc_cnt = 1UL;
  test_acc_key  [ 0 ].ul[0] = 20UL;
  test_acc_owner[ 0 ]       = fd_solana_bpf_loader_upgradeable_program_id;
  fd_bpf_state_t const state = { .discriminant = FD_BPF_STATE_PROGRAM, .inner.program.programdata_address.ul = { 21UL } };
  FD_TEST( !fd_bpf_state_encode( &state, test_acc_data[ 0 ], sizeof(test_acc_data[ 0 ]), &test_acc_len[ 0 ] ) );

  fd_pubkey_t program = { .ul = { 20UL } };
  strmk_appendvec_add( ctx, &ctx->stream[ 0 ], &program );
  FD_TEST( key_stored( env, 21UL ) && !key_stored( env, 20UL ) ); /* the caller stores the program's key */
  FD_TEST( ctx->metrics.account_cnt==1UL && ctx->metrics.tombstone_cnt==1UL ); /* program data missing at the start slot */
  FD_TEST( ctx->raw_sz==2UL*sizeof(snap_acc_hdr_t)+40UL );
  keys_env_destroy( env );
}

/* The stop message closes the stream, if any, and answers replay. */

FD_UNIT_TEST( stop ) {
  keys_env_t env[1];
  keys_env_create( env );
  env->ctx->replay_out_idx = 1UL;
  fd_stem_context_t stem[ 1 ] = { { 0 } };
  test_publish_cnt = 0UL;
  after_frag( env->ctx, 0UL, 0UL, REPLAY_SIG_STREAM_STOP, 0UL, 0UL, 0UL, stem );
  FD_TEST( test_publish_cnt==1UL && test_publish_sig==0UL && env->ctx->cur==UINT_MAX );
  keys_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void)populate_allowed_fds;
  (void)populate_allowed_seccomp;
  (void)privileged_init;
  (void)unprivileged_init;
  (void)metrics_write;

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
