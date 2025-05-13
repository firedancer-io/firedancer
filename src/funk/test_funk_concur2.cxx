#include "fd_funk_rec.h"
#include "fd_funk_txn.h"
#include "test_funk_common.hpp"
#include <cstdio>
#include <pthread.h>

#define NUM_THREADS 16
#define MAX_TXN_CNT 512
#define NUM_KEYS    2

static volatile uint exp_val[NUM_KEYS] = {0};

struct test_funk_txn_pair {
  fd_funk_t     * funk;
  fd_funk_txn_t * txn;
};
typedef struct test_funk_txn_pair test_funk_txn_pair_t;


static void * work_thread( void * arg ) {
  test_funk_txn_pair_t * pair = (test_funk_txn_pair_t *)arg;
  fd_funk_t * funk = pair->funk;
  fd_funk_txn_t * txn = pair->txn;

  for( ulong i=0UL; i<1024UL; i++ ) {
    uint key_idx = (uint)lrand48() % NUM_KEYS;
    fd_funk_rec_key_t key = {};
    key.ul[0] = key_idx;

    /* First try to clone the record from the ancestor. */
    fd_funk_rec_try_clone_safe( funk, txn, &key, alignof(ulong), sizeof(ulong) );

    /* Ensure that the record exists for the current txn. */

    fd_funk_rec_query_t query_check[1];
    fd_funk_rec_t const * rec_check = fd_funk_rec_query_try( funk, txn, &key, query_check );
    FD_TEST( rec_check );

    /* Now modify the record. */

    fd_funk_rec_query_t query_modify[1];
    fd_funk_rec_t * rec = fd_funk_rec_modify( funk, txn, &key, query_modify );
    FD_TEST( rec );
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
    ulong * val_ul = (ulong *)val;
    *val_ul += 1UL;
    fd_funk_rec_modify_publish( query_modify );

    /* Increment the value. */
    FD_ATOMIC_FETCH_AND_ADD( &exp_val[key_idx], 1 );

  }
  return NULL;

}

int main( int argc, char ** argv ) {
  srand(1234);

  fd_boot( &argc, &argv );

  ulong       txn_max  = MAX_TXN_CNT;
  uint        rec_max  = 1<<20;
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous(
      FD_SHMEM_GIGANTIC_PAGE_SZ,
      1U,
      fd_shmem_cpu_idx( numa_idx ),
      "wksp",
      0UL );
  FD_TEST( wksp );
  void * mem = fd_wksp_alloc_laddr(
      wksp,
      fd_funk_align(),
      fd_funk_footprint( txn_max, rec_max ),
      FD_FUNK_MAGIC );
  FD_TEST( mem );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, fd_funk_new( mem, 1, 1234U, txn_max, rec_max ) );
  FD_TEST( funk );

  /* Insert the records with their initial values. (0) */
  for( uint i = 0; i < NUM_KEYS; ++i ) {
    fd_funk_rec_key_t key = {};
    key.ul[0] = i;
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, NULL, &key, prepare, NULL );
    FD_TEST( rec );

    void * val = fd_funk_val_truncate(
        rec,
        fd_funk_alloc( funk ),
        fd_funk_wksp( funk ),
        alignof(ulong),
        sizeof(ulong),
        NULL
    );
    FD_TEST( val );

    /* Set the value to 0. */
    ulong * val_ul = (ulong *)val;
    *val_ul = 0UL;
    fd_funk_rec_publish( funk, prepare );
  }

  fd_funk_txn_t *   parent_txn = NULL;
  fd_funk_txn_xid_t xid = {};

  /* Number of iterations to run. */
  for( ulong i=0UL; i<MAX_TXN_CNT; i++ ) {
    xid.ul[0]++;
    fd_funk_txn_t * txn = fd_funk_txn_prepare( funk, parent_txn, &xid, 1 );
    FD_TEST( txn );
    parent_txn = txn;

    /* Skip adding a record into the txn once in a while. This lets us
       test whether the global querying logic is working as expected. */
    if( !((uint)lrand48() % 20U) ) {
      continue;
    }

    test_funk_txn_pair_t pair = { funk, txn };

    pthread_t thread[NUM_THREADS];
    for( uint i = 0; i < NUM_THREADS; ++i ) {
      pthread_create( &thread[i], NULL, work_thread, (void *)&pair );
    }

    for( uint i = 0; i < NUM_THREADS; ++i ) {
      pthread_join( thread[i], NULL );
    }

    /* Now query and compare the values. If this value didn't match,
       this would imply that there was a race condition that caused
       the record to get cloned non-atomically. */
    for( uint i=0U; i<NUM_KEYS; i++ ) {
      fd_funk_rec_key_t key = {};
      key.ul[0] = i;
      fd_funk_rec_query_t query = {};
      fd_funk_rec_t const * rec = fd_funk_rec_query_try( funk, txn, &key, &query );
      FD_TEST( rec );
      ulong * val_ul = (ulong *)fd_funk_val( rec, fd_funk_wksp( funk ) );
      FD_TEST( *val_ul == exp_val[i] );
    }
  }

  FD_LOG_NOTICE(( "test passed!" ));

}
