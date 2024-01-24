#include "test_funk_common.hpp"
#include <stdio.h>

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  srand(1234);

  fake_funk ff(&argc, &argv);
  for (uint loop = 0; loop < 100U; ++loop) {
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
    ff.random_merge();
    ff.verify();
  }

  printf("test passed!\n");
  return 0;
}
