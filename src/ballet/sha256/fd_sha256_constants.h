#ifndef HEADER_fd_src_ballet_sha256_constants_h
#define HEADER_fd_src_ballet_sha256_constants_h

/* We don't want to use FD_IMPORT_BINARY here, because we want to make
   the values available to the compiler for constant propogation.  Using
   FD_IMPORT_BINARY means they wouldn't be available until link-time. */
static uint const fd_sha256_K[64] __attribute__((aligned(64))) = {
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
  0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
  0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
  0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
  0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
  0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
  0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

#define FD_SHA256_INITIAL_A 0x6a09e667U
#define FD_SHA256_INITIAL_B 0xbb67ae85U
#define FD_SHA256_INITIAL_C 0x3c6ef372U
#define FD_SHA256_INITIAL_D 0xa54ff53aU
#define FD_SHA256_INITIAL_E 0x510e527fU
#define FD_SHA256_INITIAL_F 0x9b05688cU
#define FD_SHA256_INITIAL_G 0x1f83d9abU
#define FD_SHA256_INITIAL_H 0x5be0cd19U

#endif /* HEADER_fd_src_ballet_sha256_constants_h */
