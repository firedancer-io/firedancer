#ifndef HEADER_fd_src_ballet_pb_fd_pb_wire_h
#define HEADER_fd_src_ballet_pb_fd_pb_wire_h

/* fd_pb_wire.h provides Protobuf wire format definitions and pure
   functions. */

#include "../../util/bits/fd_bits.h"
#include "../../util/log/fd_log.h"

/* Message structure */

#define FD_PB_WIRE_TYPE_VARINT (0U)
#define FD_PB_WIRE_TYPE_I64    (1U)
#define FD_PB_WIRE_TYPE_LEN    (2U)
#define FD_PB_WIRE_TYPE_I32    (5U)

static inline uint
fd_pb_tag( uint wire_type,
           uint field_id ) {
  return ( field_id<<3 ) | wire_type;
}

static inline uint
fd_pb_tag_wire_type( uint tag ) {
  return tag & 0x7U;
}

static inline uint
fd_pb_tag_field_id( uint tag ) {
  return tag >> 3;
}

/* Max value sizes (template friendly) */

#define fd_pb_bool_max_sz      (1U)
#define fd_pb_varint32_sz_max  (5U)
#define fd_pb_varint64_sz_max (10U)
#define fd_pb_int32_sz_max    fd_pb_varint32_sz_max
#define fd_pb_int64_sz_max    fd_pb_varint64_sz_max
#define fd_pb_uint32_sz_max   fd_pb_varint32_sz_max
#define fd_pb_uint64_sz_max   fd_pb_varint64_sz_max
#define fd_pb_sint32_sz_max   fd_pb_varint32_sz_max
#define fd_pb_sint64_sz_max   fd_pb_varint64_sz_max
#define fd_pb_fixed32_sz_max  sizeof(uint)
#define fd_pb_fixed64_sz_max  sizeof(ulong)

/* Value encoders */

static inline uchar *
fd_pb_append_bool( uchar buf[ fd_pb_bool_max_sz ],
                   int   value ) {
  buf[0] = !!value;
  return buf+1;
}

static inline uchar *
fd_pb_append_varint32( uchar buf[ fd_pb_varint32_sz_max ],
                       uint  value ) {
  /* FIXME could do this much more efficiently with x86 bit-packing
           instructions and mask tricks */
  int msb = fd_uint_find_msb( value|1U )+1;
  buf[ 0 ] = (uchar)( ( msb> 7 ? 0x80 : 0 ) | ( (value>> 0) & 0x7f ) );
  buf[ 1 ] = (uchar)( ( msb>14 ? 0x80 : 0 ) | ( (value>> 7) & 0x7f ) );
  buf[ 2 ] = (uchar)( ( msb>21 ? 0x80 : 0 ) | ( (value>>14) & 0x7f ) );
  buf[ 3 ] = (uchar)( ( msb>28 ? 0x80 : 0 ) | ( (value>>21) & 0x7f ) );
  buf[ 4 ] = (uchar)(                         ( (value>>28) & 0x7f ) );
  return buf+((msb+6)/7);
}

static inline uchar *
fd_pb_append_varint32_sz5( uchar buf[ fd_pb_varint32_sz_max ],
                           uint  value ) {
  /* FIXME could do this more efficiently with x86 bit-packing */
  buf[ 0 ] = (uchar)( 0x80 | ( (value>> 0) & 0x7f ) );
  buf[ 1 ] = (uchar)( 0x80 | ( (value>> 7) & 0x7f ) );
  buf[ 2 ] = (uchar)( 0x80 | ( (value>>14) & 0x7f ) );
  buf[ 3 ] = (uchar)( 0x80 | ( (value>>21) & 0x7f ) );
  buf[ 4 ] = (uchar)(        ( (value>>28) & 0x7f ) );
  return buf+5;
}

static inline uchar *
fd_pb_append_varint64( uchar buf[ fd_pb_varint64_sz_max ],
                       ulong value ) {
  /* FIXME could do this much more efficiently with x86 bit-packing
           instructions and mask tricks */
  int msb = fd_ulong_find_msb( value|1U )+1;
  buf[ 0 ] = (uchar)( ( msb> 7 ? 0x80 : 0 ) | ( (value>> 0) & 0x7f ) );
  buf[ 1 ] = (uchar)( ( msb>14 ? 0x80 : 0 ) | ( (value>> 7) & 0x7f ) );
  buf[ 2 ] = (uchar)( ( msb>21 ? 0x80 : 0 ) | ( (value>>14) & 0x7f ) );
  buf[ 3 ] = (uchar)( ( msb>28 ? 0x80 : 0 ) | ( (value>>21) & 0x7f ) );
  buf[ 4 ] = (uchar)( ( msb>35 ? 0x80 : 0 ) | ( (value>>28) & 0x7f ) );
  buf[ 5 ] = (uchar)( ( msb>42 ? 0x80 : 0 ) | ( (value>>35) & 0x7f ) );
  buf[ 6 ] = (uchar)( ( msb>49 ? 0x80 : 0 ) | ( (value>>42) & 0x7f ) );
  buf[ 7 ] = (uchar)( ( msb>56 ? 0x80 : 0 ) | ( (value>>49) & 0x7f ) );
  buf[ 8 ] = (uchar)( ( msb>63 ? 0x80 : 0 ) | ( (value>>56) & 0x7f ) );
  buf[ 9 ] = (uchar)(                         ( (value>>63) & 0x7f ) );
  return buf+((msb+6)/7);
}

static inline uchar *
fd_pb_append_tag( uchar buf[ fd_pb_int32_sz_max ],
                  ulong tag ) {
  return fd_pb_append_varint32( buf, (uint)tag );
}

static inline uchar *
fd_pb_append_int32( uchar buf[ fd_pb_varint32_sz_max ],
                    int   value ) {
  return fd_pb_append_varint32( buf, (uint)value );
}

static inline ulong
fd_pb_int32_encoded_sz( int value ) {
  uchar dummy[ fd_pb_varint32_sz_max ];
  return (ulong)( fd_pb_append_int32( dummy, value )-dummy );
}

static inline uchar *
fd_pb_append_int64( uchar buf[ fd_pb_int64_sz_max ],
                    long  value ) {
  return fd_pb_append_varint64( buf, (ulong)value );
}

static inline uchar *
fd_pb_append_uint32( uchar buf[ fd_pb_uint32_sz_max ],
                     uint  value ) {
  return fd_pb_append_varint32( buf, value );
}

static inline uchar *
fd_pb_append_uint64( uchar buf[ fd_pb_uint64_sz_max ],
                     ulong value ) {
  return fd_pb_append_varint64( buf, value );
}

static inline uchar *
fd_pb_append_sint32( uchar buf[ fd_pb_sint32_sz_max ],
                     int   value ) {
  return fd_pb_append_varint32( buf, fd_int_zz_enc( value ) );
}

static inline uchar *
fd_pb_append_sint64( uchar buf[ fd_pb_sint64_sz_max ],
                     long  value ) {
  return fd_pb_append_varint64( buf, fd_long_zz_enc( value ) );
}

static inline uchar *
fd_pb_append_fixed32( uchar buf[ sizeof(uint) ],
                      uint  value ) {
  FD_STORE( uint, buf, value );
  return buf+sizeof(uint);
}

static inline uchar *
fd_pb_append_fixed64( uchar buf[ sizeof(ulong) ],
                      ulong value ) {
  FD_STORE( ulong, buf, value );
  return buf+sizeof(ulong);
}

#endif /* HEADER_fd_src_ballet_pb_fd_pb_wire_h */
