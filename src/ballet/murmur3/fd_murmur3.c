#include "fd_murmur3.h"

static uint
fd_murmur3_32_( void const * _data,
                ulong        sz,
                uint         seed ) {

  uchar const * data   = _data;
  uint          sz_tag = (uint)sz;

  uint c1 = 0xcc9e2d51U;
  uint c2 = 0x1b873593U;
  int  r1 = 15;
  int  r2 = 13;
  uint m  = 5;
  uint n  = 0xe6546b64U;

  uint hash = seed;

  while( sz>=4 ) {
    uint k  = FD_LOAD( uint, data );
         k *= c1;
         k  = fd_uint_rotate_left( k, r1 );
         k *= c2;

    hash ^= k;
    hash  = fd_uint_rotate_left( hash, r2 );
    hash  = hash*m + n;

    data+=4UL;
    sz  -=4UL;
  }

  uint rem = 0;
  switch( sz ) {
  case 3: rem ^= (uint)data[2]<<16U;  __attribute__((fallthrough));
  case 2: rem ^= (uint)data[1]<<8U;   __attribute__((fallthrough));
  case 1: rem ^= (uint)data[0];
          rem *= c1;
          rem  = fd_uint_rotate_left( rem, r1 );
          rem *= c2;
          hash ^= rem;                __attribute__((fallthrough));
  case 0: break;
  }

  hash ^= sz_tag;
  hash ^= hash>>16U;
  hash *= 0x85ebca6bU;
  hash ^= hash>>13U;
  hash *= 0xc2b2ae35U;
  hash ^= hash>>16U;

  return hash;
}

uint
fd_murmur3_32( void const * _data,
               ulong        sz,
               uint         seed ) {
  return fd_murmur3_32_( _data, sz, seed );
}

uint
fd_pchash( uint pc ) {
  uint x = pc;
  x *= 0xcc9e2d51U;
  x  = fd_uint_rotate_left( x, 15 );
  x *= 0x1b873593U;
  x  = fd_uint_rotate_left( x, 13 );
  x *= 5;
  x += 0xe6546b64U;
  x  = fd_uint_rotate_left( x, 13 );
  x *= 5;
  x += 0xe6546b64U;
  x ^= 8;
  x ^= x >> 16;
  x *= 0x85ebca6bU;
  x ^= x >> 13;
  x *= 0xc2b2ae35U;
  x ^= x >> 16;
  return x;
}
