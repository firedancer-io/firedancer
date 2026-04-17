#include "fd_alut.h"

int
fd_alut_state_encode( uint                   discriminant,
                      fd_alut_meta_t const * meta,
                      uchar *                buf,
                      ulong                  bufsz ) {
  if( FD_UNLIKELY( bufsz<FD_LOOKUP_TABLE_META_SIZE ) ) return -1;

  fd_memset( buf, 0, FD_LOOKUP_TABLE_META_SIZE );
  uchar * p = buf;

  FD_STORE( uint, p, discriminant );
  p += sizeof(uint);

  if( discriminant==FD_ALUT_STATE_DISC_LOOKUP_TABLE ) {
    FD_STORE( ulong, p, meta->deactivation_slot );
    p += sizeof(ulong);

    FD_STORE( ulong, p, meta->last_extended_slot );
    p += sizeof(ulong);

    *p = meta->last_extended_slot_start_index;
    p += 1;

    *p = (uchar)meta->has_authority;
    p += 1;

    if( meta->has_authority ) {
      fd_memcpy( p, meta->authority.key, 32 );
      p += 32;
    } else {
      p += 32;
    }

    FD_STORE( ushort, p, (ushort)0 );
  }

  return 0;
}

int
fd_alut_state_decode( uchar const *    data,
                      ulong            data_sz,
                      uint *           out_discriminant,
                      fd_alut_meta_t * out_meta ) {
  if( FD_UNLIKELY( data_sz<sizeof(uint) ) ) return -1;

  uchar const * p   = data;
  uchar const * end = data + data_sz;

  uint disc = FD_LOAD( uint, p );
  p += sizeof(uint);
  *out_discriminant = disc;

  if( disc==FD_ALUT_STATE_DISC_UNINITIALIZED ) {
    return 0;
  }

  if( FD_UNLIKELY( disc!=FD_ALUT_STATE_DISC_LOOKUP_TABLE ) ) return -1;

  if( FD_UNLIKELY( p + 8 > end ) ) return -1;
  out_meta->deactivation_slot = FD_LOAD( ulong, p );
  p += sizeof(ulong);

  if( FD_UNLIKELY( p + 8 > end ) ) return -1;
  out_meta->last_extended_slot = FD_LOAD( ulong, p );
  p += sizeof(ulong);

  if( FD_UNLIKELY( p + 1 > end ) ) return -1;
  out_meta->last_extended_slot_start_index = *p;
  p += 1;

  if( FD_UNLIKELY( p + 1 > end ) ) return -1;
  uchar has_auth = *p;
  p += 1;
  out_meta->has_authority = has_auth;

  if( has_auth ) {
    if( FD_UNLIKELY( p + 32 > end ) ) return -1;
    fd_memcpy( out_meta->authority.key, p, 32 );
    p += 32;
  } else {
    fd_memset( out_meta->authority.key, 0, 32 );
    p += fd_ulong_min( 32, (ulong)(end - p) );
  }

  (void)p;
  return 0;
}
