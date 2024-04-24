#include "test_funk_common.hpp"
#include <stdio.h>
#include "pthread.h"

static volatile int stop_flag = 0;
static void * read_thread(void * arg) {
  fake_funk * ff = (fake_funk *)arg;
  ulong cnt = 0;
  while( !stop_flag ) {
    ff->random_safe_read();
    ++cnt;
  }
  FD_LOG_NOTICE(( "%lu concurrent reads", cnt ));
  return NULL;
}

int main(int argc, char** argv) {
  srand(1234);

  fake_funk ff(&argc, &argv);

  pthread_t thr = 0;
  FD_TEST( pthread_create(&thr, NULL, read_thread, &ff) == 0 );
  
  for (uint loop = 0; loop < 100000U; ++loop) {
    for (uint i = 0; i < 10; ++i)
      ff.random_insert();
    ff.verify();
    for (uint i = 0; i < 10; ++i)
      ff.random_new_txn();
    ff.verify();
    for (uint i = 0; i < 50; ++i)
      ff.random_insert();
    ff.verify();
    for (uint i = 0; i < 20; ++i)
      ff.random_remove();
    ff.verify();
    ff.random_publish();
    ff.verify();
    for (uint i = 0; i < 10; ++i)
      ff.random_new_txn();
    ff.verify();
    for (uint i = 0; i < 50; ++i)
      ff.random_insert();
    ff.verify();
    for (uint i = 0; i < 10; ++i)
      ff.random_remove();
    ff.verify();
    ff.random_cancel();
    ff.verify();
  }

  stop_flag = 1;
  pthread_join( thr, NULL );

  printf("test passed!\n");
  return 0;
}
