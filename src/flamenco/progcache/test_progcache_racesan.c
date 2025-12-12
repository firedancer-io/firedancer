#include "test_progcache_common.c"
#include "../runtime/fd_system_ids.h"
#include "../../util/racesan/fd_racesan_async.h"
#include <regex.h>

#define FIBER_MAX 2
#define FIBER_STACK_MAX (1UL<<20)
static void * g_fiber_stack[ FIBER_MAX ];

FD_IMPORT_BINARY( valid_program_data, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

struct test_case {
  char const * name;
  void      (* fn)( fd_wksp_t * wksp );
};

static int
match_test_name( char const * test_name,
                 int          argc,
                 char **      argv ) {
  if( argc<=1 ) return 1;
  for( int i=1; i<argc; i++ ) {
    if( argv[ i ][ strspn( argv[ i ], " \t\n\r" ) ]=='\0' ) continue;
    if( strstr( test_name, argv[ i ] ) ) return 1;
  }
  return 0;
}

/* Exercise fd_progcache_query against a locked funk chain */

__attribute__((no_sanitize_address)) static void
test_query_contended_async( void * ctx ) {
  test_env_t * env = ctx;
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_set_root( pair->xid );
  pair->key[0] = test_key( 1UL );
  FD_TEST( !fd_progcache_peek( env->progcache, pair->xid, pair->key->uc, 0UL ) );
}

static void
test_query_contended( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  static fd_racesan_async_t async[1];
  FD_TEST( fd_racesan_async_new( async, g_fiber_stack[0], FIBER_STACK_MAX, test_query_contended_async, env ) );

  fd_funk_rec_map_t * rec_map = env->progcache->funk->rec_map;
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_set_root( pair->xid );
  pair->key[0] = test_key( 1UL );
  ulong chain_idx = fd_funk_rec_map_iter_chain_idx( rec_map, pair );

  ulong lock_seq[1] = {chain_idx};
  FD_TEST( fd_funk_rec_map_iter_lock( rec_map, lock_seq, 1UL, FD_MAP_FLAG_BLOCKING )==FD_MAP_SUCCESS );
  FD_COMPILER_MFENCE();
  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_COMPILER_MFENCE();
  FD_TEST( fd_racesan_async_hook_name_eq( async, "fd_progcache_query_wait" ) );

  fd_funk_rec_map_iter_unlock( rec_map, lock_seq, 1UL );
  FD_COMPILER_MFENCE();
  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_EXIT );
  FD_COMPILER_MFENCE();

  fd_racesan_async_delete( async );
  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* Simultaneously insert two records into the same fork node.  This
   creates a data race at the fork node's linked list. */

__attribute__((no_sanitize_address)) static void
test_pull_contended_txn_async( void * ctx ) {
  ulong        idx = ((ulong)ctx)&1UL;
  test_env_t * env = (test_env_t *)( ((ulong)ctx) & (~1UL) );

  fd_funk_txn_xid_t xid = { .ul = { 1UL, 1UL } };
  fd_funk_rec_key_t key = test_key( idx );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  FD_TEST( fd_progcache_pull( env->progcache, env->accdb, &xid, key.uc, &load_env ) );
}

static void
test_pull_contended_txn( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_map_t * rec_map = env->progcache->funk->rec_map;
  fd_funk_xid_key_pair_t pair[2];
  pair[0].xid[0] = pair[1].xid[0] = fork_a;
  pair[0].key[0] = test_key( 0UL );
  pair[1].key[0] = test_key( 1UL );
  /* Ensure both keys are inserted into different map chains.
     Otherwise, the map chain lock prevents a data race from occuring. */
  FD_TEST( fd_funk_rec_map_iter_chain_idx( rec_map, &pair[0] )!=
           fd_funk_rec_map_iter_chain_idx( rec_map, &pair[1] ) );

  create_test_account(
      env,
      pair[0].xid, pair[0].key,
      &fd_solana_bpf_loader_program_id,
      valid_program_data, valid_program_data_sz,
      1 );
  create_test_account(
      env,
      pair[1].xid, pair[1].key,
      &fd_solana_bpf_loader_program_id,
      valid_program_data, valid_program_data_sz,
      1 );

  static fd_racesan_async_t async0[1];
  static fd_racesan_async_t async1[1];
  FD_TEST( fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, test_pull_contended_txn_async, env ) );
  FD_TEST( fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, test_pull_contended_txn_async, (void *)( (ulong)env+1UL ) ) );

  FD_TEST( fd_racesan_async_step_until( async0, "fd_progcache_rec_push_tail_start", 100UL )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_step_until( async1, "fd_progcache_rec_push_tail_start", 100UL )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_step( async0 )==FD_RACESAN_ASYNC_RET_EXIT );
  FD_TEST( fd_racesan_async_step( async1 )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_hook_name_eq( async1, "fd_progcache_rec_push_tail_start" ) );
  FD_TEST( fd_racesan_async_step( async1 )==FD_RACESAN_ASYNC_RET_EXIT );

  fd_racesan_async_delete( async0 );
  fd_racesan_async_delete( async1 );
  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  for( ulong i=0UL; i<FIBER_MAX; i++ ) {
    g_fiber_stack[ i ] = fd_racesan_stack_create( FIBER_STACK_MAX );
  }

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

# define TEST( name ) { #name, name }
  struct test_case cases[] = {
    TEST( test_query_contended ),
    TEST( test_pull_contended_txn ),
    {0}
  };
# undef TEST

  for( struct test_case * tc = cases; tc->name; tc++ ) {
    if( match_test_name( tc->name, argc, argv ) ) {
      FD_LOG_NOTICE(( "Running %s", tc->name ));
      tc->fn( wksp );
    }
  }

  for( ulong i=0UL; i<FIBER_MAX; i++ ) {
    fd_racesan_stack_destroy( g_fiber_stack[ i ], FIBER_STACK_MAX );
  }

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
