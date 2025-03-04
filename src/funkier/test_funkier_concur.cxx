#include "test_funkier_common.hpp"
#include <stdio.h>
#include "pthread.h"

#define NUM_THREADS 10
#define MAX_TXN_CNT 64

class TestState {
  public:
    fd_funkier_t * _funk = NULL;
    fd_wksp_t * _wksp = NULL;
    struct ThreadPair {
        TestState * _state;
        ulong _rec_offset;
    } _pairs[NUM_THREADS];

    TestState( fd_funkier_t * funk ) : _funk(funk), _wksp(fd_funkier_wksp(funk)) {
      for( uint i = 0; i < NUM_THREADS; ++i ) {
        _pairs[i] = ThreadPair{ this, (ulong)i };
      }
    }

    fd_funkier_txn_t * pick_txn(bool unfrozen) {
      fd_funkier_txn_t * txns[MAX_TXN_CNT+1];
      uint txns_cnt = 0;
      if( !unfrozen || !fd_funkier_last_publish_is_frozen( _funk )) txns[txns_cnt++] = NULL;
      fd_funkier_txn_all_iter_t txn_iter[1];
      for( fd_funkier_txn_all_iter_new( _funk, txn_iter ); !fd_funkier_txn_all_iter_done( txn_iter ); fd_funkier_txn_all_iter_next( txn_iter ) ) {
        fd_funkier_txn_t * txn = fd_funkier_txn_all_iter_ele( txn_iter );
        if( !unfrozen || !fd_funkier_txn_is_frozen( txn )) {
          assert(txns_cnt < MAX_TXN_CNT);
          txns[txns_cnt++] = txn;
        }
      }
      return txns[lrand48()%txns_cnt];
    }

    uint count_txns() {
      fd_funkier_txn_all_iter_t txn_iter[1];
      uint cnt = 0;
      for( fd_funkier_txn_all_iter_new( _funk, txn_iter ); !fd_funkier_txn_all_iter_done( txn_iter ); fd_funkier_txn_all_iter_next( txn_iter ) ) ++cnt;
      return cnt;
    }
};

enum { STARTUP, PAUSE, RUN, DONE };
static volatile int runstate = (int)STARTUP;
static volatile uint runcnt = 0;
static volatile uint insertcnt = 0;

static void * work_thread(void * arg) {
  auto p = *(TestState::ThreadPair*)arg;
  fd_funkier_rec_key_t key;
  memset(&key, 0, sizeof(key));
  key.ul[0] = p._rec_offset;
  auto * state = p._state;
  auto * funk = state->_funk;
  auto * wksp = state->_wksp;

  while( runstate == (int)STARTUP ) continue;
  while( runstate != (int)DONE ) {
    while( runstate == (int)PAUSE ) continue;

    FD_ATOMIC_FETCH_AND_ADD( &runcnt, 1 );

    while( runstate == (int)RUN) {
      fd_funkier_txn_t * txn = state->pick_txn(true);
      fd_funkier_rec_prepare_t prepare[1];
      fd_funkier_rec_t * rec = fd_funkier_rec_prepare(funk, txn, &key, prepare, NULL);
      if( rec == NULL ) continue;
      void * val = fd_funkier_val_truncate(rec, sizeof(ulong), fd_funkier_alloc(funk, wksp), wksp, NULL);
      memcpy(val, &key.ul[0], sizeof(ulong));
      fd_funkier_rec_publish( prepare );

      FD_ATOMIC_FETCH_AND_ADD( &insertcnt, 1 );

      for(;;) {
        fd_funkier_rec_query_t query[1];
        fd_funkier_rec_t const * rec2 = fd_funkier_rec_query_try_global(funk, txn, &key, NULL, query);
        assert(rec2 && fd_funkier_val_sz(rec2) == sizeof(ulong));
        ulong val2;
        memcpy(&val2, fd_funkier_val(rec2, wksp), sizeof(ulong));
        if( fd_funkier_rec_query_test( query ) ) continue;
        assert(val2 == key.ul[0]);
        break;
      }

      key.ul[0] += NUM_THREADS;
    }

    FD_ATOMIC_FETCH_AND_SUB( &runcnt, 1 );
  }

  return NULL;
}

int main(int argc, char** argv) {
  srand(1234);

  fd_boot( &argc, &argv );

  ulong txn_max = MAX_TXN_CNT;
  ulong rec_max = 1<<20;
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1U, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_funkier_align(), fd_funkier_footprint( txn_max, rec_max ), FD_FUNKIER_MAGIC );
  fd_funkier_t * funk = fd_funkier_join( fd_funkier_new( mem, 1, 1234U, txn_max, rec_max ) );
  TestState state(funk);

  pthread_t thr[NUM_THREADS];
  for( uint i = 0; i < NUM_THREADS; ++i ) {
    FD_TEST( pthread_create(&thr[i], NULL, work_thread, &state._pairs[i]) == 0 );
  }

  runstate = (int)PAUSE;

  fd_funkier_txn_xid_t xid;
  memset(&xid, 0, sizeof(xid));

  for (uint loop = 0; loop < 60U; ++loop) {
    for( uint i = 0; i < 2; ++i ) {
      auto * txn = state.pick_txn(false);
      if( txn == NULL ) continue;
      fd_funkier_txn_publish(funk, txn, 1);
    }
    for( uint i = 0; i < 20; ++i ) {
      auto * parent = state.pick_txn(false);
      xid.ul[0]++;
      fd_funkier_txn_prepare(funk, parent, &xid, 1);
    }

    runstate = (int)RUN;
    FD_LOG_NOTICE(( "running (%u transactions)", state.count_txns() ));
    sleep(2);
    runstate = (int)PAUSE;
    while( runcnt ) continue;
    FD_LOG_NOTICE(( "paused (%u inserts)", insertcnt ));

#ifdef FD_FUNKIER_HANDHOLDING
    FD_TEST( !fd_funkier_verify( funk ) );
#endif

  }

  runstate = (int)DONE;
  for( uint i = 0; i < NUM_THREADS; ++i ) {
    pthread_join( thr[i], NULL );
  }

  fd_funkier_delete( fd_funkier_leave( funk ) );

  printf("test passed!\n");
  return 0;
}
