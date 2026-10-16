/* strmk key store tests */

#define FD_TILE_TEST
#include "fd_strmk_tile.c"
#include "../../util/tmpl/fd_unit_test.c"

#include <stdlib.h>

#define BLOCK_MAX (8UL)
#define KEY_MAX   (1024UL)

struct keys_env {
  fd_strmk_t *    ctx;
  void *          map_mem;
  void *          pool_mem;
  strmk_block_t * block;
};

typedef struct keys_env keys_env_t;

static void *
alloc( ulong align,
       ulong sz ) {
  void * mem = aligned_alloc( align, fd_ulong_align_up( sz, align ) );
  FD_TEST( mem );
  return mem;
}

static keys_env_t *
keys_env_create( keys_env_t * env,
                 ulong        key_max ) {
  env->ctx      = alloc( alignof(fd_strmk_t),    sizeof(fd_strmk_t) );
  env->map_mem  = alloc( strmk_key_map_align(),  strmk_key_map_footprint( strmk_key_map_chain_cnt_est( key_max ) ) );
  env->pool_mem = alloc( strmk_key_pool_align(), strmk_key_pool_footprint( key_max ) );
  env->block    = alloc( alignof(strmk_block_t), BLOCK_MAX*sizeof(strmk_block_t) );
  memset( env->ctx, 0, sizeof(fd_strmk_t) );
  env->ctx->key_map  = strmk_key_map_join( strmk_key_map_new( env->map_mem, strmk_key_map_chain_cnt_est( key_max ), 42UL ) );
  env->ctx->key_pool = strmk_key_pool_join( strmk_key_pool_new( env->pool_mem, key_max ) );
  FD_TEST( env->ctx->key_map && env->ctx->key_pool );
  env->ctx->block     = env->block;
  env->ctx->block_max = BLOCK_MAX;
  for( ulong i=0UL; i<BLOCK_MAX; i++ ) env->block[ i ].bank_seq = ULONG_MAX;
  return env;
}

static void
keys_env_destroy( keys_env_t * env ) {
  free( env->block );
  free( env->pool_mem );
  free( env->map_mem );
  free( env->ctx );
}

/* keys_msg fills a key message with keys first_key, first_key+1, ... */

static void
keys_msg( fd_strmk_keys_msg_t * msg,
          ulong                 bank_idx,
          ulong                 bank_seq,
          ulong                 slot,
          ulong                 key_cnt,
          ulong                 first_key ) {
  memset( msg, 0, sizeof(*msg) );
  msg->slot     = slot;
  msg->bank_idx = bank_idx;
  msg->bank_seq = bank_seq;
  msg->key_cnt  = key_cnt;
  for( ulong i=0UL; i<key_cnt; i++ ) msg->keys[ i ].ul[0] = first_key+i;
}

/* block_keys counts a block's stored keys. */

static ulong
block_keys( keys_env_t * env,
            ulong        bank_idx ) {
  ulong cnt = 0UL;
  for( uint idx=env->block[ bank_idx ].key_head_idx; idx!=UINT_MAX; cnt++ ) {
    idx = strmk_key_pool_ele( env->ctx->key_pool, idx )->block_next;
  }
  return cnt;
}

/* A block stores each key once. */

FD_UNIT_TEST( keys_dedup ) {
  keys_env_t env[1];
  keys_env_create( env, KEY_MAX );
  fd_strmk_keys_msg_t msg[1];
  keys_msg( msg, 1UL, 7UL, 100UL, 3UL, 1UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 1UL, 7UL, 100UL, 3UL, 2UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( env->block[ 1 ].bank_seq==7UL && env->block[ 1 ].slot==100UL );
  FD_TEST( block_keys( env, 1UL )==4UL );
  FD_TEST( env->ctx->block_cnt==1UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==4UL );
  FD_TEST( env->ctx->metrics.key_cnt==6UL && env->ctx->metrics.key_stored_cnt==4UL );
  keys_env_destroy( env );
}

/* The same key in two blocks is stored for both. */

FD_UNIT_TEST( keys_per_block ) {
  keys_env_t env[1];
  keys_env_create( env, KEY_MAX );
  fd_strmk_keys_msg_t msg[1];
  keys_msg( msg, 1UL, 7UL, 100UL, 1UL, 1UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 2UL, 8UL, 101UL, 1UL, 1UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( env->ctx->block_cnt==2UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==2UL );
  keys_env_destroy( env );
}

/* A bank reused for a new block drops the old block's keys. */

FD_UNIT_TEST( keys_bank_reused ) {
  keys_env_t env[1];
  keys_env_create( env, KEY_MAX );
  fd_strmk_keys_msg_t msg[1];
  keys_msg( msg, 1UL, 7UL, 100UL, 3UL, 1UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 1UL, 9UL, 105UL, 2UL, 1UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( env->block[ 1 ].bank_seq==9UL && env->block[ 1 ].slot==105UL );
  FD_TEST( block_keys( env, 1UL )==2UL );
  FD_TEST( env->ctx->block_cnt==1UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==2UL );
  keys_env_destroy( env );
}

/* A late message from the block a bank held before is dropped. */

FD_UNIT_TEST( keys_stale ) {
  keys_env_t env[1];
  keys_env_create( env, KEY_MAX );
  fd_strmk_keys_msg_t msg[1];
  keys_msg( msg, 3UL, 9UL, 101UL, 5UL, 100UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 3UL, 7UL, 100UL, 2UL, 1UL   ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 3UL, 9UL, 101UL, 3UL, 105UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( env->block[ 3 ].bank_seq==9UL && env->block[ 3 ].slot==101UL );
  FD_TEST( block_keys( env, 3UL )==8UL );
  FD_TEST( env->ctx->block_cnt==1UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==8UL );
  keys_env_destroy( env );
}

/* A full pool drops keys. */

FD_UNIT_TEST( keys_full ) {
  keys_env_t env[1];
  keys_env_create( env, 4UL );
  fd_strmk_keys_msg_t msg[1];
  keys_msg( msg, 1UL, 7UL, 100UL, 3UL, 1UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 2UL, 8UL, 101UL, 3UL, 1UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( block_keys( env, 1UL )==3UL && block_keys( env, 2UL )==1UL );
  FD_TEST( env->ctx->metrics.key_dropped_cnt==2UL );
  keys_env_destroy( env );
}

/* A new block frees the blocks that fell out of the window. */

FD_UNIT_TEST( keys_window ) {
  keys_env_t env[1];
  keys_env_create( env, KEY_MAX );
  fd_strmk_keys_msg_t msg[1];
  keys_msg( msg, 1UL, 7UL, 100UL, 2UL, 1UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 2UL, 8UL, 101UL, 2UL, 1UL ); strmk_store_keys( env->ctx, msg );
  keys_msg( msg, 3UL, 9UL, 100UL+STRMK_WINDOW-1UL, 1UL, 1UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( env->ctx->block_cnt==3UL );
  keys_msg( msg, 4UL, 10UL, 100UL+STRMK_WINDOW, 1UL, 1UL ); strmk_store_keys( env->ctx, msg );
  FD_TEST( env->block[ 1 ].bank_seq==ULONG_MAX && env->block[ 2 ].bank_seq==8UL );
  FD_TEST( env->ctx->block_cnt==3UL );
  FD_TEST( strmk_key_pool_used( env->ctx->key_pool )==4UL );
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
