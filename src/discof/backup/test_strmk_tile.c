/* strmk key store tests */

#define FD_TILE_TEST
#include "fd_strmk_tile.c"
#include "../../util/tmpl/fd_unit_test.c"

#include <stdlib.h>

struct keys_env {
  fd_strmk_t * ctx;
  void *       map_mem;
  void *       pool_mem;
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
  memset( env->ctx, 0, sizeof(fd_strmk_t) );
  env->ctx->key_map  = strmk_key_map_join( strmk_key_map_new( env->map_mem, strmk_key_map_chain_cnt_est( STRMK_KEY_MAX ), 42UL ) );
  env->ctx->key_pool = strmk_key_pool_join( strmk_key_pool_new( env->pool_mem, STRMK_KEY_MAX ) );
  FD_TEST( env->ctx->key_map && env->ctx->key_pool );
  for( ulong i=0UL; i<STRMK_KEY_MAX; i++ ) strmk_key_pool_ele( env->ctx->key_pool, i )->slot = ULONG_MAX;
  env->ctx->cur = UINT_MAX;
  return env;
}

static void
keys_env_destroy( keys_env_t * env ) {
  free( env->pool_mem );
  free( env->map_mem );
  free( env->ctx );
}

/* keys_msg fills a key message with keys first_key, first_key+1, ... */

static void
keys_msg( fd_strmk_keys_msg_t * msg,
          ulong                 slot,
          ulong                 key_cnt,
          ulong                 first_key ) {
  memset( msg, 0, sizeof(*msg) );
  msg->slot    = slot;
  msg->key_cnt = key_cnt;
  for( ulong i=0UL; i<key_cnt; i++ ) msg->keys[ i ].ul[0] = first_key+i;
}

/* keys_fill stores cnt distinct keys at slot. */

static void
keys_fill( keys_env_t * env,
           ulong        slot,
           ulong        cnt,
           ulong        first_key ) {
  fd_strmk_keys_msg_t msg[1];
  for( ulong i=0UL; i<cnt; i+=FD_STRMK_READ_KEYS_MAX ) {
    keys_msg( msg, slot, fd_ulong_min( FD_STRMK_READ_KEYS_MAX, cnt-i ), first_key+i );
    strmk_store_keys( env->ctx, msg );
  }
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
