#include <stdio.h>
#include "fd_f25519.h"

int main(int argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {
  fd_f25519_t r;
  uchar buf[32];

  // Read 32 bytes
  for (int i = 0; i < 32; i++) {
    unsigned int temp;
    if (scanf("%02x", &temp) != 1) {
      fprintf(stderr, "Error reading input\n");
      return 1;
    }
    buf[i] = (uchar)temp;
  }

  // Convert from bytes
  fd_f25519_frombytes(&r, buf);

  // Output result
  for (int i = 0; i < 5; i++) {
    printf("%lu ", r.el[i]);
  }
  printf("\nDONE.\n");
  return 0;
}
