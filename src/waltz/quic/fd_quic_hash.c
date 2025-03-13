/*
   Modified Fixed 16-byte SipHash C implementation

   Original authors:
   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
   Daniel J. Bernstein <djb@cr.yp.to>

   The original authors placed the original work in the public domain.
 */

#include "fd_quic_hash.h"

/* default: SipHash-2-4 */
#ifndef cROUNDS
#define cROUNDS 2
#endif
#ifndef dROUNDS
#define dROUNDS 4
#endif

#define ROTL(x, b) (ulong)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                                                      \
    (p)[0] = (uchar)((v));                                                   \
    (p)[1] = (uchar)((v) >> 0x08);                                           \
    (p)[2] = (uchar)((v) >> 0x10);                                           \
    (p)[3] = (uchar)((v) >> 0x18);

#define U64TO8_LE(p, v)                                                      \
    U32TO8_LE((p),     (uint)((v)));                                         \
    U32TO8_LE((p) + 4, (uint)((v) >> 32));

#define U8TO64_LE(p)                                                         \
    (((ulong)((p)[0]))         | ((ulong)((p)[1]) << 0x08) |                 \
     ((ulong)((p)[2]) << 0x10) | ((ulong)((p)[3]) << 0x18) |                 \
     ((ulong)((p)[4]) << 0x20) | ((ulong)((p)[5]) << 0x28) |                 \
     ((ulong)((p)[6]) << 0x30) | ((ulong)((p)[7]) << 0x38))

#define SIPROUND                                                             \
    do {                                                                     \
        v0 += v1;                                                            \
        v1 = ROTL(v1, 13);                                                   \
        v1 ^= v0;                                                            \
        v0 = ROTL(v0, 32);                                                   \
        v2 += v3;                                                            \
        v3 = ROTL(v3, 16);                                                   \
        v3 ^= v2;                                                            \
        v0 += v3;                                                            \
        v3 = ROTL(v3, 21);                                                   \
        v3 ^= v0;                                                            \
        v2 += v1;                                                            \
        v1 = ROTL(v1, 17);                                                   \
        v1 ^= v2;                                                            \
        v2 = ROTL(v2, 32);                                                   \
    } while (0)

void
fd_quic_hash_128( uchar const data[16],
                  uchar const seed[16],
                  uchar       out[16] ) {

  const uchar *ni = (const uchar *)data;
  const uchar *kk = (const uchar *)seed;

  ulong v0 = 0x736f6d6570736575;
  ulong v1 = 0x646f72616e646f6d;
  ulong v2 = 0x6c7967656e657261;
  ulong v3 = 0x7465646279746573;
  ulong k0 = U8TO64_LE(kk);
  ulong k1 = U8TO64_LE(kk + 8);
  ulong m;
  int i;
  ulong b = ((ulong)16) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  v1 ^= 0xee;

  /* unrolled two loops, since the input is 16 bytes */
  m = U8TO64_LE(ni);
  v3 ^= m;

  for (i = 0; i < cROUNDS; ++i)
      SIPROUND;

  v0 ^= m;

  ni += 8;

  m = U8TO64_LE(ni);
  v3 ^= m;

  for (i = 0; i < cROUNDS; ++i)
      SIPROUND;

  v0 ^= m;

  /* siphash codes for leftover bytes here, but our input is
     always 16 bytes, which is a multiple of 8 */

  v3 ^= b;

  for (i = 0; i < cROUNDS; ++i)
      SIPROUND;

  v0 ^= b;

  v2 ^= 0xee;

  for (i = 0; i < dROUNDS; ++i)
      SIPROUND;

  b = v0 ^ v1 ^ v2 ^ v3;
  U64TO8_LE(out, b);

  v1 ^= 0xdd;

  for (i = 0; i < dROUNDS; ++i)
      SIPROUND;

  b = v0 ^ v1 ^ v2 ^ v3;
  U64TO8_LE(out + 8, b);
}
