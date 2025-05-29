#include <stdio.h>
#include "fd_f25519.h"

int main(int argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {
  fd_f25519_t a;
  int result;

  // Read input a
  for (int i = 0; i < 5; i++) {
    if (scanf("%lu", &a.el[i]) != 1) {
      fprintf(stderr, "Error reading input\n");
      return 1;
    }
  }

  // Perform operation
  result = fd_f25519_is_zero(&a);

  // Output result
  printf("%d\nDONE.\n", result);
  return 0;
}
