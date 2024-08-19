#include "base_enc.h"
#include <stdint.h>

static const int8_t b58digits_map[] = {
  -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
  -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
  -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
  22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
  -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
  47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

typedef ulong b58_maxint_t;
typedef uint  b58_almostmaxint_t;
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)
static const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);

int
b58tobin(void * bin, ulong * binszp, const char *b58, ulong b58sz) {
  ulong binsz = *binszp;
  const unsigned char *b58u = (void*)b58;
  unsigned char *binu = bin;
  ulong outisz = (binsz + sizeof(b58_almostmaxint_t) - 1) / sizeof(b58_almostmaxint_t);
  b58_almostmaxint_t outi[outisz];
  b58_maxint_t t;
  b58_almostmaxint_t c;
  ulong i, j;
  uint8_t bytesleft = binsz % sizeof(b58_almostmaxint_t);
  b58_almostmaxint_t zeromask = ( bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0 );
  unsigned zerocount = 0;

  memset( outi, 0, sizeof(b58_almostmaxint_t)*outisz );

  // Leading zeros, just count
  for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
    ++zerocount;

  for ( ; i < b58sz; ++i) {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return 1;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return 1;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--; ) {
      t = ((b58_maxint_t)outi[j]) * 58 + c;
      c = (unsigned)(t >> b58_almostmaxint_bits);
      outi[j] = (unsigned)(t & b58_almostmaxint_mask);
    }
    if (c)
      // Output number too big (carry to the next int32)
      return 1;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return 1;
  }

  j = 0;
  if (bytesleft) {
    for (i = bytesleft; i > 0; --i) {
      *(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
    }
    ++j;
  }

  for (; j < outisz; ++j) {
    for (i = sizeof(*outi); i > 0; --i) {
      *(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
    }
  }

  // Count canonical base58 byte count
  binu = bin;
  for (i = 0; i < binsz; ++i) {
    if (binu[i])
      break;
    --*binszp;
  }
  *binszp += zerocount;

  return 0;
}
