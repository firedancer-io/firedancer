#include "test_funk_common.hpp"
#include <cstdio>
#include <pthread.h>

#define NUM_THREADS 10
#define MAX_TXN_CNT 64

class TestState {
  public:
    fd_funk_t * _funk = NULL;
    fd_wksp_t * _wksp = NULL;
    struct ThreadPair {
        TestState * _state;
        ulong _rec_offset;
    } _pairs[NUM_THREADS];

    TestState( fd_funk_t * funk ) : _funk(funk), _wksp(fd_funk_wksp(funk)) {
      for( uint i = 0; i < NUM_THREADS; ++i ) {
        _pairs[i] = ThreadPair{ this, (ulong)i };
      }
    }

    fd_funk_txn_t * pick_txn(bool unfrozen) {
      fd_funk_txn_t * txns[MAX_TXN_CNT+1];
      uint txns_cnt = 0;
      if( !unfrozen || !fd_funk_last_publish_is_frozen( _funk )) txns[txns_cnt++] = NULL;
      fd_funk_txn_all_iter_t txn_iter[1];
      for( fd_funk_txn_all_iter_new( _funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) {
        fd_funk_txn_t * txn = fd_funk_txn_all_iter_ele( txn_iter );
        if( !unfrozen || !fd_funk_txn_is_frozen( txn )) {
          assert(txns_cnt < MAX_TXN_CNT);
          txns[txns_cnt++] = txn;
        }
      }
      return txns[lrand48()%txns_cnt];
    }

    uint count_txns() {
      fd_funk_txn_all_iter_t txn_iter[1];
      uint cnt = 0;
      for( fd_funk_txn_all_iter_new( _funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) ++cnt;
      return cnt;
    }
};

enum { STARTUP, PAUSE, RUN, DONE };
static volatile int runstate = (int)STARTUP;
static volatile uint runcnt = 0;
static volatile uint insertcnt = 0;

static void * work_thread(void * arg) {
  auto p = *(TestState::ThreadPair*)arg;
  fd_funk_rec_key_t key;
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
      fd_funk_txn_t * txn = state->pick_txn(true);
      fd_funk_rec_prepare_t prepare[1];
      fd_funk_rec_t * rec = fd_funk_rec_prepare(funk, txn, &key, prepare, NULL);
      if( rec == NULL ) continue;
      void * val = fd_funk_val_truncate(
          rec,
          fd_funk_alloc( funk ),
          wksp,
          0UL,
          sizeof(ulong),
          NULL);
      memcpy(val, &key.ul[0], sizeof(ulong));
      fd_funk_rec_publish( funk, prepare );

      FD_ATOMIC_FETCH_AND_ADD( &insertcnt, 1 );

      for(;;) {
        fd_funk_rec_query_t query[1];
        fd_funk_rec_t const * rec2 = fd_funk_rec_query_try_global(funk, txn, &key, NULL, query);
        assert(rec2 && fd_funk_val_sz(rec2) == sizeof(ulong));
        ulong val2;
        memcpy(&val2, fd_funk_val(rec2, wksp), sizeof(ulong));
        if( fd_funk_rec_query_test( query ) ) continue;
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
  uint  rec_max = 1<<20;
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1U, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), FD_FUNK_MAGIC );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, fd_funk_new( mem, 1, 1234U, txn_max, rec_max ) );
  FD_TEST( funk );
  TestState state(funk);

  pthread_t thr[NUM_THREADS];
  for( uint i = 0; i < NUM_THREADS; ++i ) {
    FD_TEST( pthread_create(&thr[i], NULL, work_thread, &state._pairs[i]) == 0 );
  }

  runstate = (int)PAUSE;

  fd_funk_txn_xid_t xid;
  memset(&xid, 0, sizeof(xid));

  for (uint loop = 0; loop < 10U; ++loop) {
    for( uint i = 0; i < 2; ++i ) {
      auto * txn = state.pick_txn(false);
      if( txn == NULL ) continue;
      fd_funk_txn_publish(funk, txn, 1);
    }
    for( uint i = 0; i < 20; ++i ) {
      auto * parent = state.pick_txn(false);
      xid.ul[0]++;
      fd_funk_txn_prepare(funk, parent, &xid, 1);
    }

    runstate = (int)RUN;
    FD_LOG_NOTICE(( "running (%u transactions)", state.count_txns() ));
    sleep(2);
    runstate = (int)PAUSE;
    while( runcnt ) continue;
    FD_LOG_NOTICE(( "paused (%u inserts)", insertcnt ));

    FD_TEST( !fd_funk_verify( funk ) );

  }

  runstate = (int)DONE;
  for( uint i = 0; i < NUM_THREADS; ++i ) {
    pthread_join( thr[i], NULL );
  }

  fd_funk_leave( funk, NULL );
  fd_funk_delete( mem );

  printf("test passed!\n");
  return 0;
}
