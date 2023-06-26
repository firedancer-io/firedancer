#include "fd_util_base.h"

/* A cleaner implementation of xxhash-r39 (Open Source BSD licensed). */

#define ROTATE_LEFT(x,r) (((x)<<(r)) | ((x)>>(64-(r))))
#define C1 (11400714785074694791UL)
#define C2 (14029467366897019727UL)
#define C3 ( 1609587929392839161UL)
#define C4 ( 9650029242287828579UL)
#define C5 ( 2870177450012600261UL)

ulong
fd_hash( ulong        seed,
         void const * buf,
         ulong        sz ) {
  uchar const * p    = ((uchar const *)buf);
  uchar const * stop = p + sz;

  ulong h;

  if( sz<32 ) h = seed + C5;
  else {
    uchar const * stop32 = stop - 32;
    ulong w = seed + (C1+C2);
    ulong x = seed + C2;
    ulong y = seed;
    ulong z = seed - C1;

    do { /* All complete blocks of 32 */
      w += (((ulong const *)p)[0])*C2; w = ROTATE_LEFT( w, 31 ); w *= C1;
      x += (((ulong const *)p)[1])*C2; x = ROTATE_LEFT( x, 31 ); x *= C1;
      y += (((ulong const *)p)[2])*C2; y = ROTATE_LEFT( y, 31 ); y *= C1;
      z += (((ulong const *)p)[3])*C2; z = ROTATE_LEFT( z, 31 ); z *= C1;
      p += 32;
    } while( p<=stop32 );

    h = ROTATE_LEFT( w, 1 ) + ROTATE_LEFT( x, 7 ) + ROTATE_LEFT( y, 12 ) + ROTATE_LEFT( z, 18 );

    w *= C2; w = ROTATE_LEFT( w, 31 ); w *= C1; h ^= w; h = h*C1 + C4;
    x *= C2; x = ROTATE_LEFT( x, 31 ); x *= C1; h ^= x; h = h*C1 + C4;
    y *= C2; y = ROTATE_LEFT( y, 31 ); y *= C1; h ^= y; h = h*C1 + C4;
    z *= C2; z = ROTATE_LEFT( z, 31 ); z *= C1; h ^= z; h = h*C1 + C4;
  }

  h += ((ulong)sz);

  while( (p+8)<=stop ) { /* Last 1 to 3 complete ulong's */
    ulong w = ((ulong const *)p)[0];
    w *= C2; w = ROTATE_LEFT( w, 31 ); w *= C1; h ^= w; h = ROTATE_LEFT( h, 27 )*C1 + C4;
    p += 8;
  }

  if( (p+4)<=stop ) { /* Last complete uint */
    ulong w = ((ulong)(((uint const *)p)[0]));
    w *= C1; h ^= w; h = ROTATE_LEFT( h, 23 )*C2 + C3;
    p += 4;
  }

  while( p<stop ) { /* Last 1 to 3 uchar's */
    ulong w = ((ulong)(p[0]));
    w *= C5; h ^= w; h = ROTATE_LEFT( h, 11 )*C1;
    p++;
  }

  /* Final avalanche */
  h ^= h >> 33;
  h *= C2;
  h ^= h >> 29;
  h *= C3;
  h ^= h >> 32;

  return h;
}

ulong
fd_hash_memcpy( ulong                    seed,
                void *       FD_RESTRICT dst,
                void const * FD_RESTRICT src,
                ulong                    sz ) {
  uchar       * FD_RESTRICT q    = ((uchar       *)dst);
  uchar const * FD_RESTRICT p    = ((uchar const *)src);
  uchar const * FD_RESTRICT stop = p + sz;

  ulong h;

  if( sz<32 ) h = seed + C5;
  else {
    uchar const * FD_RESTRICT stop32 = stop - 32;
    ulong w = seed + (C1+C2);
    ulong x = seed + C2;
    ulong y = seed;
    ulong z = seed - C1;

    do { /* All complete blocks of 32 */
      ulong p0 = ((ulong const *)p)[0];
      ulong p1 = ((ulong const *)p)[1];
      ulong p2 = ((ulong const *)p)[2];
      ulong p3 = ((ulong const *)p)[3];
      w += p0*C2; w = ROTATE_LEFT( w, 31 ); w *= C1;
      x += p1*C2; x = ROTATE_LEFT( x, 31 ); x *= C1;
      y += p2*C2; y = ROTATE_LEFT( y, 31 ); y *= C1;
      z += p3*C2; z = ROTATE_LEFT( z, 31 ); z *= C1;
      ((ulong *)q)[0] = p0;
      ((ulong *)q)[1] = p1;
      ((ulong *)q)[2] = p2;
      ((ulong *)q)[3] = p3;
      p += 32;
      q += 32;
    } while( p<=stop32 );

    h = ROTATE_LEFT( w, 1 ) + ROTATE_LEFT( x, 7 ) + ROTATE_LEFT( y, 12 ) + ROTATE_LEFT( z, 18 );

    w *= C2; w = ROTATE_LEFT( w, 31 ); w *= C1; h ^= w; h = h*C1 + C4;
    x *= C2; x = ROTATE_LEFT( x, 31 ); x *= C1; h ^= x; h = h*C1 + C4;
    y *= C2; y = ROTATE_LEFT( y, 31 ); y *= C1; h ^= y; h = h*C1 + C4;
    z *= C2; z = ROTATE_LEFT( z, 31 ); z *= C1; h ^= z; h = h*C1 + C4;
  }

  h += ((ulong)sz);

  while( (p+8)<=stop ) { /* Last 1 to 3 complete ulong's */
    ulong p0 = ((ulong const *)p)[0];
    ulong w  = p0*C2; w = ROTATE_LEFT( w, 31 ); w *= C1; h ^= w; h = ROTATE_LEFT( h, 27 )*C1 + C4;
    ((ulong *)q)[0] = p0;
    p += 8;
    q += 8;
  }

  if( (p+4)<=stop ) { /* Last complete uint */
    uint p0 = ((uint const *)p)[0];
    ulong w = ((ulong)p0)*C1; h ^= w; h = ROTATE_LEFT( h, 23 )*C2 + C3;
    ((uint *)q)[0] = p0;
    p += 4;
    q += 4;
  }

  while( p<stop ) { /* Last 1 to 3 uchar's */
    uchar p0 = p[0];
    ulong w  = ((ulong)p0)*C5; h ^= w; h = ROTATE_LEFT( h, 11 )*C1;
    q[0] = p0;
    p++;
    q++;
  }

  /* Final avalanche */
  h ^= h >> 33;
  h *= C2;
  h ^= h >> 29;
  h *= C3;
  h ^= h >> 32;

  return h;
}

#undef C5
#undef C4
#undef C3
#undef C2
#undef C1
#undef ROTATE_LEFT
