#include <stdlib.h>
#include <stdint.h>

#include "../../util/fd_util.h"
// #include "fd_falcon.c"

/* Reference implementation, copied from Falcon-impl-20211101. */
size_t
comp_decode(
	int16_t *x, unsigned logn,
	const void *in, size_t max_in_len)
{
	const uint8_t *buf;
	size_t n, u, v;
	uint32_t acc;
	unsigned acc_len;

	n = (size_t)1 << logn;
	buf = in;
	acc = 0;
	acc_len = 0;
	v = 0;
	for (u = 0; u < n; u ++) {
		unsigned b, s, m;

		/*
		 * Get next eight bits: sign and low seven bits of the
		 * absolute value.
		 */
		if (v >= max_in_len) {
			return 0;
		}
		acc = (acc << 8) | (uint32_t)buf[v ++];
		b = acc >> acc_len;
		s = b & 128;
		m = b & 127;

		/*
		 * Get next bits until a 1 is reached.
		  */
		for (;;) {
			if (acc_len == 0) {
				if (v >= max_in_len) {
					return 0;
				}
				acc = (acc << 8) | (uint32_t)buf[v ++];
				acc_len = 8;
			}
			acc_len --;
			if (((acc >> acc_len) & 1) != 0) {
				break;
			}
			m += 128;
			if (m > 2047) {
				return 0;
			}
		}

		/*
		 * "-0" is forbidden.
		 */
		if (s && m == 0) {
			return 0;
		}

		x[u] = (int16_t)(s ? -(int)m : (int)m);
	}

	/*
	 * Unused bits in the last byte must be zero.
	 */
	if ((acc & ((1u << acc_len) - 1u)) != 0) {
		return 0;
	}

	return v;
}

#define MAX 897
#define MIN 600

void
cbmc_main( void ) {
  ulong sz;
  __VERIFIER_assume( sz<=MAX && sz>=MIN );
  uchar * input = malloc( sz );
  __VERIFIER_assume( input!=NULL );

  {
    int16_t out[ 512 ];
    comp_decode( out, 9, input, MAX );
  }

  // fd_falcon_signature_t out[1];
  // int result = fd_falcon_signature_parse( out, input, sz );
  // assert( result==0 || result==-1 );
}
