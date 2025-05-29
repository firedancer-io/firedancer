#include <stdio.h>
#include "fd_f25519.h"

int main(int argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {
  fd_f25519_t a, r;

  // Read input a
  for (int i = 0; i < 5; i++) {
    if (scanf("%lu", &a.el[i]) != 1) {
      fprintf(stderr, "Error reading input\n");
      return 1;
    }
  }

  // Perform operation
  fd_f25519_set(&r, &a);

  // Output result
  for (int i = 0; i < 5; i++) {
    printf("%lu ", r.el[i]);
  }
  printf("\nDONE.\n");
  return 0;
}
