/* test_progcache_verify.c - Test program for comprehensive progcache verification */

#include "fd_progcache_verify.h"
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "fd_progcache_rec.h"
#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_txn.h"
#include "../../funk/fd_funk_rec.h"
#include "../../funk/fd_funk_val.h"
#include "../../util/wksp/fd_wksp.h"
#include "../runtime/fd_runtime_const.h"

/* Example usage of the comprehensive progcache verification */
int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create a workspace for testing */
  ulong page_cnt = 1024UL;
  ulong page_sz  = FD_WKSP_ALIGN;
  char * _wksp = aligned_alloc( FD_WKSP_ALIGN, page_cnt * page_sz );
  FD_TEST( _wksp );

  ulong part_max = 1UL;
  ulong data_max = page_cnt * page_sz;
  fd_wksp_t * wksp = fd_wksp_new( _wksp, "test_progcache_verify", 0U, part_max, data_max );
  FD_TEST( wksp );

  /* Setup funk instance */
  ulong txn_max = 64UL;
  ulong rec_max = 1024UL;

  void * funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), 1UL );
  FD_TEST( funk_mem );

  ulong wksp_tag = 1UL;
  ulong seed = 0UL;
  fd_funk_t * funk = fd_funk_new( funk_mem, wksp_tag, seed, txn_max, rec_max );
  FD_TEST( funk );

  /* Create admin and user progcache interfaces */
  fd_progcache_admin_t admin_cache[1];
  fd_progcache_t user_cache[1];

  /* Join admin interface */
  FD_TEST( fd_progcache_admin_join( admin_cache, funk ) );

  /* Setup scratch buffer for user cache */
  uchar scratch[ FD_PROGCACHE_SCRATCH_FOOTPRINT ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));

  /* Join user interface */
  FD_TEST( fd_progcache_join( user_cache, funk, scratch, sizeof(scratch) ) );

  /* Set up epoch_slot0 for testing */
  ulong epoch_slot0 = 1000UL;

  FD_LOG_NOTICE(( "Running comprehensive progcache verification..." ));

  /* Test 1: Verify empty progcache */
  FD_LOG_INFO(( "Test 1: Empty progcache verification" ));
  int result = fd_progcache_verify_comprehensive( admin_cache, user_cache, epoch_slot0 );
  FD_TEST( result == FD_FUNK_SUCCESS );
  FD_LOG_INFO(( "Test 1: PASSED" ));

  /* Test 2: Create some fork structure and verify */
  FD_LOG_INFO(( "Test 2: Fork structure verification" ));

  /* Create a simple fork: root -> fork_a -> fork_b */
  fd_funk_txn_xid_t fork_a = { .ul = { epoch_slot0 + 10UL, 1UL } };
  fd_funk_txn_xid_t fork_b = { .ul = { epoch_slot0 + 20UL, 2UL } };

  /* Create transactions */
  fd_funk_txn_prepare( funk, NULL, &fork_a );
  fd_funk_txn_t * txn_a = fd_funk_txn_query( &fork_a, funk->txn_map );
  FD_TEST( txn_a );

  fd_funk_txn_xid_t const * parent_b = &fork_a;
  fd_funk_txn_prepare( funk, parent_b, &fork_b );
  fd_funk_txn_t * txn_b = fd_funk_txn_query( &fork_b, funk->txn_map );
  FD_TEST( txn_b );

  /* Load fork in user cache */
  user_cache->fork_depth = 2UL;
  user_cache->fork[0] = fork_b;
  user_cache->fork[1] = fork_a;

  result = fd_progcache_verify_comprehensive( admin_cache, user_cache, epoch_slot0 );
  FD_TEST( result == FD_FUNK_SUCCESS );
  FD_LOG_INFO(( "Test 2: PASSED" ));

  /* Test 3: Add a non-executable progcache entry and verify */
  FD_LOG_INFO(( "Test 3: Non-executable record verification" ));

  uchar prog_addr[32] = {0};
  prog_addr[0] = 0x01; /* Simple test address */

  /* Create a non-executable record */
  fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( funk->rec_pool, NULL, 0, NULL );
  FD_TEST( rec );
  memset( rec, 0, sizeof(fd_funk_rec_t) );
  fd_funk_val_init( rec );

  /* Set up the record */
  rec->tag = 0;
  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;
  memcpy( rec->pair.key, prog_addr, 32UL );
  fd_funk_txn_xid_copy( rec->pair.xid, &fork_b );

  /* Allocate value storage */
  void * val = fd_funk_val_truncate( rec, funk->alloc, funk->wksp, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t), NULL );
  FD_TEST( val );

  fd_progcache_rec_t * prog_rec = (fd_progcache_rec_t *)val;
  prog_rec->slot = fork_b.ul[0];
  prog_rec->executable = 0;
  prog_rec->invalidate = 0;

  result = fd_progcache_verify_comprehensive( admin_cache, user_cache, epoch_slot0 );
  FD_TEST( result == FD_FUNK_SUCCESS );
  FD_LOG_INFO(( "Test 3: PASSED" ));

  /* Test 4: Test the enhanced verify function */
  FD_LOG_INFO(( "Test 4: Enhanced verify function" ));
  fd_progcache_verify_enhanced( admin_cache );
  FD_LOG_INFO(( "Test 4: PASSED" ));

  /* Test 5: Intentionally create an invalid condition to test error detection */
  FD_LOG_INFO(( "Test 5: Invalid condition detection" ));

  /* Save original values */
  ulong orig_fork_depth = user_cache->fork_depth;

  /* Create invalid fork depth */
  user_cache->fork_depth = FD_PROGCACHE_DEPTH_MAX + 1UL;

  result = fd_progcache_verify_comprehensive( admin_cache, user_cache, epoch_slot0 );
  FD_TEST( result == FD_FUNK_ERR_INVAL );
  FD_LOG_INFO(( "Test 5: PASSED (correctly detected invalid fork depth)" ));

  /* Restore valid state */
  user_cache->fork_depth = orig_fork_depth;

  /* Cleanup */
  fd_progcache_admin_leave( admin_cache, NULL );
  fd_progcache_leave( user_cache, NULL );
  fd_funk_delete( funk );
  fd_wksp_free_laddr( funk_mem );
  fd_wksp_delete( wksp );
  free( _wksp );

  FD_LOG_NOTICE(( "All progcache verification tests passed!" ));

  fd_halt();
  return 0;
}
