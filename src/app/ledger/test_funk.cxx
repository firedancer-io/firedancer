#include "../../util/fd_util.h"
extern "C" {
#include "fd_funk.h"
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  unlink("testback");
  ulong footprint = fd_funk_footprint_min();
  void* mem = fd_funk_new(malloc(footprint), footprint, "testback");
  auto* funk = fd_funk_join(mem);

  mem = fd_funk_leave(funk);
  fd_funk_delete(mem);
  free(mem);
  
  return 0;
}
