// sudo build/native/gcc/bin/fd_shmem_cfg init 0700 asiegel ""

#define FUNK_RECONNECT_TEST 1

#include <stdio.h>
#include <errno.h>
#include <string.h>
extern "C" {
#include "../util/fd_util.h"
#include "../util/shmem/fd_shmem_private.h"
}
#include "test_funk_common.hpp"

int main(int argc, char** argv) {
  fd_boot( &argc, &argv );

  srand(1234);

  fake_funk ff(&argc, &argv);
  ff.verify();
  for(uint loop = 0;;++loop) {
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
    ff.random_publish_into_parent();
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
    for (uint i = 0; i < 10; ++i)
      ff.random_new_txn();
    ff.verify();
    for (uint i = 0; i < 50; ++i)
      ff.random_insert();
    ff.verify();
    for (uint i = 0; i < 10; ++i)
      ff.random_remove();
    ff.verify();
    ff.random_publish_into_parent();
    ff.verify();
    if( loop % 100 == 0 ) FD_LOG_NOTICE(( "iter %u", loop ));
  }

  printf("test passed!\n");
  return 0;
}
