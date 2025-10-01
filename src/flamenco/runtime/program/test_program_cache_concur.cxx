#include "../../../funk/fd_funk_rec.h"
#include "../../../funk/fd_funk_txn.h"
#include "../../../funk/test_funk_common.hpp"
#include "fd_program_cache.h"
#include <cstdio>
#include <pthread.h>

#define NUM_THREADS 4
#define MAX_TXN_CNT 4096
#define NUM_KEYS    64

static volatile uint exp_val[NUM_KEYS] = {0};

struct test_funk_thread_arg {
  fd_funk_t *       funk;
  fd_funk_txn_xid_t xid;
  uint              start_idx;
  uint              end_idx;
};
typedef struct test_funk_thread_arg test_funk_thread_arg_t;

static void * work_thread( void * _arg ) {
  test_funk_thread_arg_t *  arg = (test_funk_thread_arg_t *)_arg;
  fd_funk_t *               funk = arg->funk;
  fd_funk_txn_xid_t const * xid  = &arg->xid;

  for( ulong i=0UL; i<1024UL; i++ ) {
    uint key_idx = ((uint)lrand48() % (arg->end_idx - arg->start_idx)) + arg->start_idx;

    /* Increment the value. */
    FD_ATOMIC_FETCH_AND_ADD( &exp_val[key_idx], 1 );

    /* Update the record. */
    fd_funk_rec_key_t key = {};
    key.ul[0] = key_idx;
    fd_funk_rec_insert_para( funk, xid, &key, alignof(uint), sizeof(uint), (void*)&exp_val[key_idx] );
  }
  return NULL;

}

int main( int argc, char ** argv ) {
  srand(1234);

  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );

  ulong       txn_max  = MAX_TXN_CNT;
  uint        rec_max  = 1<<20;
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( page_sz, page_cnt, near_cpu, "wksp", 0UL );
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
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, fd_funk_last_publish( funk ), &key, prepare, NULL );
    FD_TEST( rec );

    void * val = fd_funk_val_truncate(
        rec,
        fd_funk_alloc( funk ),
        fd_funk_wksp( funk ),
        alignof(uint),
        sizeof(uint),
        NULL
    );
    FD_TEST( val );

    /* Set the value to 0. */
    uint * val_ul = (uint *)val;
    *val_ul = 0U;
    fd_funk_rec_publish( funk, prepare );
  }

  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_funk_txn_xid_t xid = {{0}};

  /* Number of iterations to run. */
  for( ulong i=0UL; i<MAX_TXN_CNT; i++ ) {
    xid.ul[0]++;
    fd_funk_txn_prepare( funk, &parent_xid, &xid );
    parent_xid = xid;

    /* Skip adding a record into the txn once in a while. This lets us
       test whether the global querying logic is working as expected. */
    if( !((uint)lrand48() % 20U) ) {
      continue;
    }

    test_funk_thread_arg_t arg[NUM_THREADS];
    pthread_t thread[NUM_THREADS];
    for( uint i = 0; i < NUM_THREADS; ++i ) {
      arg[i].funk = funk;
      arg[i].xid = xid;
      arg[i].start_idx = (i * NUM_KEYS) / NUM_THREADS;
      arg[i].end_idx = ((i + 1) * NUM_KEYS) / NUM_THREADS;
      pthread_create( &thread[i], NULL, work_thread, (void *)&arg[i] );
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
      fd_funk_rec_t const * rec = fd_funk_rec_query_try( funk, &xid, &key, &query );
      FD_TEST( rec );
      uint * val_ul = (uint *)fd_funk_val( rec, fd_funk_wksp( funk ) );
      if( FD_UNLIKELY( *val_ul != exp_val[i] ) ) {
        FD_LOG_ERR(( "val_ul=%u exp_val=%u", *val_ul, exp_val[i] ));
      }
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
