#include "fd_x25519.h"
#include <stdio.h>
int main(int     argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {

  // Create symbolic inputs for private key and peer public key
  unsigned char private_key[32];
  unsigned char peer_pubkey[32];

  // Read symbolic inputs (angr will hook these)
  // Using a simple pattern to identify byte reads in the binary
  for(int i = 0; i < 32; i++) {
    private_key[i] = (uchar) getchar();
  }
  for(int i = 0; i < 32; i++) {
    peer_pubkey[i] = (uchar) getchar();
  }

  // Run the cryptographic operation
  unsigned char shared_secret[32];
  void* result = fd_x25519_exchange(shared_secret, private_key, peer_pubkey);

  // Write output (angr will monitor this)
  for(int i = 0; i < 32; i++) {
    putchar(shared_secret[i]);
  }
  puts("DONE.");

  // Return success/failure indicator
  return result == NULL ? 1 : 0;
}
