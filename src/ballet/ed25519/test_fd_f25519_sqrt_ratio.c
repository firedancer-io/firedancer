#include <stdio.h>
#include "fd_f25519.h"

int main(int argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {
  fd_f25519_t u, v, r;
  int result;

  // Read input u
  for (int i = 0; i < 5; i++) {
    if (scanf("%lu", &u.el[i]) != 1) {
      fprintf(stderr, "Error reading input u\n");
      return 1;
    }
  }

  // Read input v
  for (int i = 0; i < 5; i++) {
    if (scanf("%lu", &v.el[i]) != 1) {
      fprintf(stderr, "Error reading input v\n");
      return 1;
    }
  }

  // Perform operation
  result = fd_f25519_sqrt_ratio(&r, &u, &v);

  // Output result
  printf("Return: %d\n", result);
  for (int i = 0; i < 5; i++) {
    printf("%lu ", r.el[i]);
  }
  printf("\nDONE.\n");
  return 0;
}
