/* fd_aes_gcm_ref.c was imported from the OpenSSL project circa 2023-Aug.
   Original source file:  crypto/modes/gcm128.c */

#include "fd_aes_gcm.h"

/*
 * Copyright 2010-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NOTE: TABLE_BITS and all non-4bit implementations have been removed in 3.1.
 *
 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
 * never be set to 8. 8 is effectively reserved for testing purposes.
 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
 * whole spectrum of possible table driven implementations. Why? In
 * non-"Shoup's" case memory access pattern is segmented in such manner,
 * that it's trivial to see that cache timing information can reveal
 * fair portion of intermediate hash value. Given that ciphertext is
 * always available to attacker, it's possible for him to attempt to
 * deduce secret parameter H and if successful, tamper with messages
 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
 * not as trivial, but there is no reason to believe that it's resistant
 * to cache-timing attack. And the thing about "8-bit" implementation is
 * that it consumes 16 (sixteen) times more memory, 4KB per individual
 * key + 1KB shared. Well, on pros side it should be twice as fast as
 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
 * was observed to run ~75% faster, closer to 100% for commercial
 * compilers... Yet "4-bit" procedure is preferred, because it's
 * believed to provide better security-performance balance and adequate
 * all-round performance. "All-round" refers to things like:
 *
 * - shorter setup time effectively improves overall timing for
 *   handling short messages;
 * - larger table allocation can become unbearable because of VM
 *   subsystem penalties (for example on Windows large enough free
 *   results in VM working set trimming, meaning that consequent
 *   malloc would immediately incur working set expansion);
 * - larger table has larger cache footprint, which can affect
 *   performance of other code paths (not necessarily even from same
 *   thread in Hyper-Threading world);
 *
 * Value of 1 is not appropriate for performance reasons.
 */

#define REDUCE1BIT(V)                                \
  do {                                               \
    if (sizeof(ulong)==8) {                         \
      ulong T = 0xe100000000000000UL & (0-(V.lo&1)); \
      V.lo  = (V.hi<<63)|(V.lo>>1);                  \
      V.hi  = (V.hi>>1 )^T;                          \
    }                                                \
    else {                                           \
      ulong T = 0xe1000000U & (0-(uint)(V.lo&1));    \
      V.lo  = (V.hi<<63)|(V.lo>>1);                  \
      V.hi  = (V.hi>>1 )^((ulong)T<<32);             \
    }                                                \
  } while(0)

void
fd_gcm_init_4bit( fd_gcm128_t Htable[16],
                  ulong const H[2] )
{
  fd_gcm128_t V;

  Htable[0].hi = 0;
  Htable[0].lo = 0;
  V.hi = H[0];
  V.lo = H[1];

  Htable[8] = V;
  REDUCE1BIT(V);
  Htable[4] = V;
  REDUCE1BIT(V);
  Htable[2] = V;
  REDUCE1BIT(V);
  Htable[1] = V;
  Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
  V = Htable[4];
  Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
  Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
  Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
  V = Htable[8];
  Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
  Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
  Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
  Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
  Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
  Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
  Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
}

#define PACK(s) ((ulong)(s)<<(sizeof(ulong)*8-16))

static const ulong rem_4bit[16] = {
  PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
  PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
  PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
  PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)
};

void
fd_gcm_gmult_4bit( ulong             Xi[2],
                   fd_gcm128_t const Htable[16]) {

  fd_gcm128_t Z;
  int cnt = 15;
  ulong rem, nlo, nhi;

  nlo = ((uchar const *)Xi)[15];
  nhi = nlo >> 4;
  nlo &= 0xf;

  Z.hi = Htable[nlo].hi;
  Z.lo = Htable[nlo].lo;

  while (1) {
    rem = (ulong)Z.lo & 0xf;
    Z.lo = (Z.hi << 60) | (Z.lo >> 4);
    Z.hi = (Z.hi >> 4);
    Z.hi ^= rem_4bit[rem];

    Z.hi ^= Htable[nhi].hi;
    Z.lo ^= Htable[nhi].lo;

    if (--cnt < 0)
      break;

    nlo = ((uchar const *)Xi)[cnt];
    nhi = nlo >> 4;
    nlo &= 0xf;

    rem = (ulong)Z.lo & 0xf;
    Z.lo = (Z.hi << 60) | (Z.lo >> 4);
    Z.hi = (Z.hi >> 4);
    Z.hi ^= rem_4bit[rem];

    Z.hi ^= Htable[nlo].hi;
    Z.lo ^= Htable[nlo].lo;
  }

  Xi[0] = fd_ulong_bswap( Z.hi );
  Xi[1] = fd_ulong_bswap( Z.lo );
}

/*
 * Streamed gcm_mult_4bit, see CRYPTO_gcm128_[en|de]crypt for
 * details... Compiler-generated code doesn't seem to give any
 * performance improvement, at least not on x86[_64]. It's here
 * mostly as reference and a placeholder for possible future
 * non-trivial optimization[s]...
 */
void
fd_gcm_ghash_4bit( ulong             Xi[2],
                   fd_gcm128_t const Htable[16],
                   uchar const *     inp,
                   ulong             len ) {

  fd_gcm128_t Z;
  int cnt;
  ulong rem, nlo, nhi;

  do {
    cnt = 15;
    nlo = ((uchar const *)Xi)[15];
    nlo ^= inp[15];
    nhi = nlo >> 4;
    nlo &= 0xf;

    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while (1) {
      rem = (ulong)Z.lo & 0xf;
      Z.lo = (Z.hi << 60) | (Z.lo >> 4);
      Z.hi = (Z.hi >> 4);
      Z.hi ^= rem_4bit[rem];

      Z.hi ^= Htable[nhi].hi;
      Z.lo ^= Htable[nhi].lo;

      if (--cnt < 0)
        break;

      nlo = ((uchar const *)Xi)[cnt];
      nlo ^= inp[cnt];
      nhi = nlo >> 4;
      nlo &= 0xf;

      rem = (ulong)Z.lo & 0xf;
      Z.lo = (Z.hi << 60) | (Z.lo >> 4);
      Z.hi = (Z.hi >> 4);
      Z.hi ^= rem_4bit[rem];

      Z.hi ^= Htable[nlo].hi;
      Z.lo ^= Htable[nlo].lo;
    }

    Xi[0] = fd_ulong_bswap( Z.hi );
    Xi[1] = fd_ulong_bswap( Z.lo );

    inp += 16;
    /* Block size is 128 bits so len is a multiple of 16 */
    len -= 16;
  } while (len > 0);
}
