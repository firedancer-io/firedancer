#include "../../util/fd_util_base.h"

/* hash function based on Murmur3 128 bit hash, optimized for 128 bit input
   and 128 bit output */

void
fd_quic_hash_128( uchar const key[16],
                  uchar const seed[16],
                  uchar       out[16] );
