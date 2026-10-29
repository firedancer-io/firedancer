
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../accdb/fd_accdb.h"
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

FD_FN_UNUSED static fd_pubkey_t
test_key( ulong x ) {
  fd_pubkey_t key = {0};
  key.ul[0] = x;
  return key;
}

#define TEST_ACCOUNT_DATA_MAX (1UL<<20)
struct test_account {
  fd_acc_t entry[1];
  uchar    buf[ TEST_ACCOUNT_DATA_MAX ];
};
typedef struct test_account test_account_t;

FD_FN_UNUSED static test_account_t *
test_account_init( test_account_t * acc,
                   void const *     address,
                   void const *     owner,
                   _Bool            executable,
                   void const *     data,
                   ulong            data_sz ) {
  if( data_sz > TEST_ACCOUNT_DATA_MAX ) FD_LOG_ERR(( "test_account_init: data_sz %lu exceeds max %lu", data_sz, TEST_ACCOUNT_DATA_MAX ));
  memset( acc->entry, 0, sizeof(fd_acc_t) );
  memcpy( acc->entry->pubkey, address, 32 );
  memcpy( acc->entry->owner, owner, 32 );
  acc->entry->lamports   = 42UL;
  acc->entry->executable = executable;
  acc->entry->data_len   = data_sz;
  acc->entry->data       = acc->buf;
  if( data_sz ) memcpy( acc->entry->data, data, data_sz );
  return acc;
}

FD_FN_UNUSED static test_account_t *
test_account_init_v3( test_account_t * acc,
                      uchar *          buf,
                      ulong            buf_max,
                      void const *     address,
                      void const *     progdata_address ) {

  struct __attribute__((packed)) {
    uint        kind;
    fd_pubkey_t progdata_address;
  } v3_state = {
    .kind             = FD_BPF_STATE_PROGRAM,
    .progdata_address = FD_LOAD( fd_pubkey_t, progdata_address )
  };
  FD_TEST( buf_max>=sizeof(v3_state) );
  fd_memcpy( buf, &v3_state, sizeof(v3_state) );

  memset( acc->entry, 0, sizeof(fd_acc_t) );
  memcpy( acc->entry->pubkey, address, 32 );
  memcpy( acc->entry->owner, &fd_solana_bpf_loader_upgradeable_program_id, 32 );
  acc->entry->lamports   = 42UL;
  acc->entry->executable = 1;
  acc->entry->data_len   = sizeof(v3_state);
  acc->entry->data       = buf;
  return acc;
}

FD_FN_UNUSED static test_account_t *
test_account_init_v3_data( test_account_t * acc,
                           uchar *          buf,
                           ulong            buf_max,
                           void const *     address,
                           void const *     data,
                           ulong            data_sz,
                           ulong            slot ) {
  struct __attribute__((packed)) {
    uint  kind;
    ulong slot;
    uchar has_upgrade_authority;
  } v3_state = {
    .kind                  = FD_BPF_STATE_PROGRAM_DATA,
    .slot                  = slot,
    .has_upgrade_authority = 0
  };
  FD_TEST( buf_max>=PROGRAMDATA_METADATA_SIZE+data_sz );
  fd_memset( buf, 0, PROGRAMDATA_METADATA_SIZE );
  fd_memcpy( buf, &v3_state, sizeof(v3_state) );
  fd_memcpy( buf+PROGRAMDATA_METADATA_SIZE, data, data_sz );

  memset( acc->entry, 0, sizeof(fd_acc_t) );
  memcpy( acc->entry->pubkey, address, 32 );
  memcpy( acc->entry->owner, &fd_solana_bpf_loader_upgradeable_program_id, 32 );
  acc->entry->lamports   = 42UL;
  acc->entry->executable = 0;
  acc->entry->data_len   = PROGRAMDATA_METADATA_SIZE+data_sz;
  acc->entry->data       = buf;
  (void)slot;
  return acc;
}

/* Test fork graph.  progcache forks are accdb forks, so the tests drive a
   small in-memory accdb (memfd backed, no account data) through
   attach/root/cancel the way replay does.  test_fork_* wraps one accdb op
   together with the progcache op replay pairs with it, in the same order.

   test_accdb is process global: every progcache instance a test creates
   shares it.  test_fork_reset tears the fork graph back down to a single
   root (generation 0 is always rooted, mirroring a snapshot root). */

#define TEST_ACCDB_MAX_LIVE_SLOTS (64UL)

static fd_accdb_t *       test_accdb;
static void *             test_accdb_join_mem;
static void *             test_accdb_shmem_mem;
static int                test_accdb_fd = -1;
static fd_accdb_fork_id_t test_fork_root;

FD_FN_UNUSED static void
test_accdb_drain( void ) {
  int charge_busy = 0;
  while( fd_accdb_cmd_pending( test_accdb ) ) fd_accdb_background( test_accdb, &charge_busy );
}

FD_FN_UNUSED static void
test_accdb_init( void ) {
  if( test_accdb ) return;
  ulong const max_accounts       = 64UL;
  ulong const writes_per_slot    = 64UL;
  ulong const partition_cnt      = 4UL;
  ulong const partition_sz       = 16UL<<20; /* fits a worst-case account write */
  ulong const cache_footprint    = 32UL<<20;
  ulong const cache_min_reserved = 2UL;

  test_accdb_fd = memfd_create( "progcache_test_accdb", 0 );
  FD_TEST( test_accdb_fd>=0 );
  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, TEST_ACCDB_MAX_LIVE_SLOTS, writes_per_slot, partition_cnt,
                                             cache_footprint, cache_min_reserved, 1UL, 0UL );
  FD_TEST( shmem_fp );
  test_accdb_shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( test_accdb_shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( test_accdb_shmem_mem, max_accounts, TEST_ACCDB_MAX_LIVE_SLOTS, writes_per_slot, partition_cnt,
                          partition_sz, cache_footprint, cache_min_reserved, 0, 42UL, 1UL, 0UL ) );
  FD_TEST( shmem );
  test_accdb_join_mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( TEST_ACCDB_MAX_LIVE_SLOTS, 0 ) );
  FD_TEST( test_accdb_join_mem );
  test_accdb = fd_accdb_join( fd_accdb_new( test_accdb_join_mem, shmem, test_accdb_fd, 0UL, NULL, NULL, 0UL, 0 ) );
  FD_TEST( test_accdb );
  test_fork_root = fd_accdb_attach_child( test_accdb, (fd_accdb_fork_id_t){ .val=USHORT_MAX } );
}

/* test_fork_reset drops every fork and starts over from a fresh root.  The
   progcache instances using the test accdb must be reset too (their records
   reference the old forks). */

FD_FN_UNUSED static void
test_fork_reset( void ) {
  test_accdb_init();
  test_accdb_drain();
  fd_accdb_reset( test_accdb );
  test_accdb_drain();
  test_fork_root = fd_accdb_attach_child( test_accdb, (fd_accdb_fork_id_t){ .val=USHORT_MAX } );
}

FD_FN_UNUSED static fd_accdb_fork_id_t
test_fork_root_id( void ) {
  test_accdb_init();
  return test_fork_root;
}

FD_FN_UNUSED static fd_accdb_fork_id_t
test_fork_attach( fd_accdb_fork_id_t parent ) {
  test_accdb_init();
  return fd_accdb_attach_child( test_accdb, parent );
}

/* test_fork_advance_root roots fork (a child of the current root), cancelling
   its siblings, in progcache then accdb. */

FD_FN_UNUSED static void
test_fork_advance_root( fd_progcache_join_t * join,
                        fd_accdb_fork_id_t    fork ) {
  fd_progcache_advance_root( join, test_accdb, fork );
  fd_accdb_advance_root( test_accdb, fork );
  test_accdb_drain();
  test_fork_root = fork;
}

/* test_fork_cancel cancels fork and its subtree in progcache then accdb. */

FD_FN_UNUSED static void
test_fork_cancel( fd_progcache_join_t * join,
                  fd_accdb_fork_id_t    fork ) {
  fd_progcache_cancel_fork( join, test_accdb, fork );
  fd_accdb_purge( test_accdb, fork );
  test_accdb_drain();
}

/* progcache internals.  Absent from fd_progcache_user.h: no production caller
   has a use for a lookup that cannot fill, so the composition below lives with
   the tests rather than in the library. */

fd_progcache_rec_t * /* read locked */
fd_progcache_query( fd_progcache_t *    cache,
                    fd_accdb_t const *  accdb,
                    fd_accdb_fork_id_t  fork_id,
                    fd_pubkey_t const * key,
                    ulong               feature_slot,
                    ulong               deploy_slot );

/* fd_progcache_peek looks up an entry without filling: a miss returns NULL
   rather than loading the program.  Tests use it as a reader that leaves the
   cache unchanged, which is what lets them assert whether a concurrent fill
   happened.  The returned record is read locked; release it with
   fd_progcache_rec_close. */

FD_FN_UNUSED static fd_progcache_rec_t * /* read locked */
fd_progcache_peek( fd_progcache_t *    cache,
                   fd_accdb_fork_id_t  fork_id,
                   fd_pubkey_t const * prog_addr,
                   ulong               feature_slot,
                   ulong               deploy_slot ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  return fd_progcache_query( cache, test_accdb, fork_id, prog_addr, feature_slot, deploy_slot );
}

/* test_progcache_pull is fd_progcache_pull on the test accdb. */

FD_FN_UNUSED static fd_progcache_rec_t * /* read locked */
test_progcache_pull( fd_progcache_t *           cache,
                     fd_accdb_fork_id_t         fork_id,
                     fd_pubkey_t const *        prog_addr,
                     fd_prog_load_env_t const * env,
                     fd_acc_t const *           prog_ro ) {
  return fd_progcache_pull( cache, test_accdb, fork_id, prog_addr, env, prog_ro );
}

/* test_rec_lookup fetches the mapped record inserted on fork for key, or
   NULL. */

FD_FN_UNUSED static fd_progcache_rec_t const *
test_rec_lookup( fd_progcache_join_t * join,
                 fd_accdb_fork_id_t    fork,
                 fd_pubkey_t const *   key ) {
  fd_progcache_rec_key_t pair = { .gen = fd_accdb_fork_generation( test_accdb, fork ), .fork_id = fork.val, .prog = *key };
  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_query_try( join->rec.map, &pair, NULL, query, 0 );
  if( query_err==FD_MAP_ERR_KEY ) return NULL;
  if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
  return fd_prog_recm_query_ele_const( query );
}
