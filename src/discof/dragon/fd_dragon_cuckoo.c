/* Ported from yellowstone-grpc-proto/src/cuckoo (Apache-2.0), see
   fd_dragon_cuckoo.h for the license notice and the wire contract. */

#include "fd_dragon_cuckoo.h"
#include "../../ballet/siphash13/fd_siphash13.h" /* FD_SIPHASH_ROUND */
#include <math.h>

/* FD_DRAGON_CUCKOO_KEY_MAX bounds the key a caller may hash, which the
   scratch of fd_dragon_cuckoo_hash_key is sized for. */

#define FD_DRAGON_CUCKOO_KEY_MAX (64UL)

FD_FN_PURE ulong
fd_dragon_cuckoo_siphash24( void const * data,
                            ulong        sz,
                            ulong        k0,
                            ulong        k1 ) {
  uchar const * p = data;
  ulong v[ 4 ] = {
    k0 ^ 0x736f6d6570736575UL,
    k1 ^ 0x646f72616e646f6dUL,
    k0 ^ 0x6c7967656e657261UL,
    k1 ^ 0x7465646279746573UL
  };

  ulong off = 0UL;
  for( ; off+8UL<=sz; off+=8UL ) {
    ulong m = fd_ulong_load_8( p+off );
    v[ 3 ] ^= m;
    FD_SIPHASH_ROUND( v );
    FD_SIPHASH_ROUND( v );
    v[ 0 ] ^= m;
  }

  ulong b = ( sz & 0xffUL )<<56;
  for( ulong i=0UL; off+i<sz; i++ ) b |= (ulong)p[ off+i ]<<( 8UL*i );
  v[ 3 ] ^= b;
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  v[ 0 ] ^= b;

  v[ 2 ] ^= 0xffUL;
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  return v[ 0 ]^v[ 1 ]^v[ 2 ]^v[ 3 ];
}

/* cuckoo_keys derives SipHash's two keys from the seed on the wire
   (hasher.rs keys_from_seed). */

static inline void
cuckoo_keys( ulong   seed,
             ulong * k0,
             ulong * k1 ) {
  *k0 = seed;
  *k1 = fd_ulong_rotate_left( seed, 32 );
}

FD_FN_PURE ulong
fd_dragon_cuckoo_hash_key( ulong         seed,
                           uchar const * key,
                           ulong         key_sz ) {
  if( FD_UNLIKELY( key_sz>FD_DRAGON_CUCKOO_KEY_MAX ) ) key_sz = FD_DRAGON_CUCKOO_KEY_MAX;
  uchar buf[ 8UL+FD_DRAGON_CUCKOO_KEY_MAX ];
  FD_STORE( ulong, buf, key_sz );
  fd_memcpy( buf+8UL, key, key_sz );

  ulong k0, k1;
  cuckoo_keys( seed, &k0, &k1 );
  return fd_dragon_cuckoo_siphash24( buf, 8UL+key_sz, k0, k1 );
}

/* cuckoo_hash_fp hashes a fingerprint the way Rust's Hash for u16
   writes it, which is its two little endian bytes. */

FD_FN_PURE static ulong
cuckoo_hash_fp( ulong  seed,
                ushort fp ) {
  uchar buf[ 2 ] = { (uchar)( fp & 0xffU ), (uchar)( fp>>8 ) };
  ulong k0, k1;
  cuckoo_keys( seed, &k0, &k1 );
  return fd_dragon_cuckoo_siphash24( buf, 2UL, k0, k1 );
}

FD_FN_CONST static inline ushort
cuckoo_fp( ulong hash ) {
  ushort fp = (ushort)( hash>>32 );
  return fp ? fp : (ushort)1;
}

/* cuckoo_index maps a hash to a bucket.  A filter off the wire may have
   any bucket count, not only a power of two, and the index is still in
   bounds: masking leaves only bits that bucket_cnt-1 has, so both
   indices and their xor are at most bucket_cnt-1. */

FD_FN_PURE static inline ulong
cuckoo_index( fd_dragon_cuckoo_t const * f,
              ulong                      hash ) {
  return hash & ( f->bucket_cnt-1UL );
}

FD_FN_CONST ulong
fd_dragon_cuckoo_bucket_cnt( ulong capacity ) {
  /* The bucket count a client's filter has for a given capacity is the
     result of the same floating point expression the Rust
     implementation evaluates (filter.rs with_capacity_and_hasher), so
     that a filter built here has the bucket count the client's filter
     would have. */
  double needed_f = ceil( (double)capacity /
                          ( (double)FD_DRAGON_CUCKOO_LOAD_NUM/(double)FD_DRAGON_CUCKOO_LOAD_DEN *
                            (double)FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET ) );
  if( FD_UNLIKELY( !( needed_f<(double)( 1UL<<61 ) ) ) ) return 0UL;
  ulong needed = (ulong)needed_f;
  if( FD_UNLIKELY( needed<=1UL ) ) return 1UL;
  return fd_ulong_pow2_up( needed );
}

fd_dragon_cuckoo_t *
fd_dragon_cuckoo_init( fd_dragon_cuckoo_t * f,
                       ulong                seed,
                       ushort *             bucket,
                       ulong                bucket_cnt ) {
  f->seed       = seed;
  f->bucket_cnt = bucket_cnt;
  f->bucket     = bucket;
  fd_memset( bucket, 0, bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET*sizeof(ushort) );
  return f;
}

fd_dragon_cuckoo_t *
fd_dragon_cuckoo_decode( fd_dragon_cuckoo_t * f,
                         ulong                seed,
                         uchar const *        data,
                         ulong                data_sz,
                         ushort *             bucket ) {
  ulong bucket_cnt = fd_dragon_cuckoo_wire_bucket_cnt( data_sz );
  ulong entry_cnt  = bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;

  f->seed       = seed;
  f->bucket_cnt = bucket_cnt;
  f->bucket     = bucket;

  if( FD_UNLIKELY( data_sz<FD_DRAGON_CUCKOO_BUCKET_SZ ) ) {
    fd_memset( bucket, 0, entry_cnt*sizeof(ushort) );
    return f;
  }

  /* Fingerprints are little endian on the wire and the host is little
     endian, so the whole buckets copy as they are. */
  fd_memcpy( bucket, data, entry_cnt*sizeof(ushort) );
  return f;
}

void
fd_dragon_cuckoo_encode( fd_dragon_cuckoo_t const * f,
                         uchar *                    out ) {
  fd_memcpy( out, f->bucket,
             f->bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET*sizeof(ushort) );
}

/* cuckoo_try_insert puts fp in the first empty slot of the bucket.
   Returns 1 if it fit. */

static int
cuckoo_try_insert( fd_dragon_cuckoo_t * f,
                   ulong                index,
                   ushort               fp ) {
  ushort * b = f->bucket + index*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
  for( ulong s=0UL; s<FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET; s++ ) {
    if( !b[ s ] ) { b[ s ] = fp; return 1; }
  }
  return 0;
}

int
fd_dragon_cuckoo_insert( fd_dragon_cuckoo_t * f,
                         uchar const *        key,
                         ulong                key_sz ) {
  ulong  h  = fd_dragon_cuckoo_hash_key( f->seed, key, key_sz );
  ushort fp = cuckoo_fp( h );
  ulong  i1 = cuckoo_index( f, h );
  ulong  i2 = i1 ^ cuckoo_index( f, cuckoo_hash_fp( f->seed, fp ) );

  if( cuckoo_try_insert( f, i1, fp ) ) return 1;
  if( cuckoo_try_insert( f, i2, fp ) ) return 1;

  ulong i = i1;
  for( ulong n=0UL; n<FD_DRAGON_CUCKOO_MAX_KICKS; n++ ) {
    ulong    slot = ( n + (ulong)fp ) % FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
    ushort * cell = f->bucket + i*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET + slot;
    ushort   tmp  = *cell;
    *cell = fp;
    fp    = tmp;

    i ^= cuckoo_index( f, cuckoo_hash_fp( f->seed, fp ) );
    if( cuckoo_try_insert( f, i, fp ) ) return 1;
  }
  return 0;
}

int
fd_dragon_cuckoo_remove( fd_dragon_cuckoo_t * f,
                         uchar const *        key,
                         ulong                key_sz ) {
  ulong  h  = fd_dragon_cuckoo_hash_key( f->seed, key, key_sz );
  ushort fp = cuckoo_fp( h );
  ulong  i1 = cuckoo_index( f, h );
  ulong  i2 = i1 ^ cuckoo_index( f, cuckoo_hash_fp( f->seed, fp ) );

  ulong idx[ 2 ] = { i1, i2 };
  for( ulong k=0UL; k<2UL; k++ ) {
    ushort * b = f->bucket + idx[ k ]*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
    for( ulong s=0UL; s<FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET; s++ ) {
      if( b[ s ]==fp ) { b[ s ] = (ushort)0; return 1; }
    }
  }
  return 0;
}

FD_FN_PURE int
fd_dragon_cuckoo_contains( fd_dragon_cuckoo_t const * f,
                           uchar const *              key,
                           ulong                      key_sz ) {
  ulong  h  = fd_dragon_cuckoo_hash_key( f->seed, key, key_sz );
  ushort fp = cuckoo_fp( h );
  ulong  i1 = cuckoo_index( f, h );
  ulong  i2 = i1 ^ cuckoo_index( f, cuckoo_hash_fp( f->seed, fp ) );

  ushort const * b1 = f->bucket + i1*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
  ushort const * b2 = f->bucket + i2*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
  for( ulong s=0UL; s<FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET; s++ ) {
    if( b1[ s ]==fp || b2[ s ]==fp ) return 1;
  }
  return 0;
}
