#include <stdio.h>
#include "fd_f25519.h"

int main(int argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {
  fd_f25519_t a;
  uchar out[32];

  // Read input a
  for (int i = 0; i < 5; i++) {
    if (scanf("%lu", &a.el[i]) != 1) {
      fprintf(stderr, "Error reading input\n");
      return 1;
    }
  }

  // Convert to bytes
  fd_f25519_tobytes(out, &a);

  // Output result
  for (int i = 0; i < 32; i++) {
    printf("%02x", out[i]);
  }
  printf("\nDONE.\n");
  return 0;
}
