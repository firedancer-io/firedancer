#include "fd_murmur3.h"

uint fd_murmur3_hash_cstr_to_uint(char const * key, ulong key_len, uint seed) {
  uint hash = seed;

  ulong i = 0;
  for (; i < ((key_len / 4) * 4); i+=4) {
    uint chunk = *(uint const *)(key+i);
    chunk *= 0xcc9e2d51;
    chunk = (chunk << 15) | (chunk >> 17);
    chunk *= 0x1b873593;

    hash ^= chunk;
    hash = (hash << 13) | (hash >> 19);
    hash = (hash * 5) + 0xe6546b64;
  }
  /* NOTE: The following implies that the machine is little endian, on a big endian machine you 
     would need to flip this. */
  /* Handle remaining bytes */
  uint rem_chunk = 0;
  uint shift = 0;
  for (; i < key_len; i++) {
    rem_chunk |= key[i] << shift;
    shift += 8;
  }
    
  rem_chunk *= 0xcc9e2d51;
  rem_chunk = (rem_chunk << 15) | (rem_chunk >> 17);
  rem_chunk *= 0x1b873593;
  hash ^= rem_chunk;

  /* Finalizer */
  hash ^= key_len;
  hash ^= hash >> 16;
  hash *= 0x85ebca6b;
  hash ^= hash >> 13;
  hash *= 0xc2b2ae35;
  hash ^= hash >> 16;

  return hash;
}
