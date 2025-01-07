// QUIC parsers

// TODO add platform optimized versions of these
// e.g. 32 bit unaligned fetch w/ byte swap on intel
#define FD_TEMPL_PARSE_IMPL_uchar(p) (                                 \
    ( (uchar)((p)[0]) ) )
#define FD_TEMPL_PARSE_IMPL_ushort(p) (                                \
    ( (ushort)((p)[0]) << (ushort)0x08 ) +                             \
    ( (ushort)((p)[1]) << (ushort)0x00 ) )
#define FD_TEMPL_PARSE_IMPL_uint(p) (                                  \
    (   (uint)((p)[0]) <<   (uint)0x18 ) +                             \
    (   (uint)((p)[1]) <<   (uint)0x10 ) +                             \
    (   (uint)((p)[2]) <<   (uint)0x08 ) +                             \
    (   (uint)((p)[3]) <<   (uint)0x00 ) )
#define FD_TEMPL_PARSE_IMPL_ulong(p) (                                 \
    (  (ulong)((p)[0]) <<  (ulong)0x38 ) +                             \
    (  (ulong)((p)[1]) <<  (ulong)0x30 ) +                             \
    (  (ulong)((p)[2]) <<  (ulong)0x28 ) +                             \
    (  (ulong)((p)[3]) <<  (ulong)0x20 ) +                             \
    (  (ulong)((p)[4]) <<  (ulong)0x18 ) +                             \
    (  (ulong)((p)[5]) <<  (ulong)0x10 ) +                             \
    (  (ulong)((p)[6]) <<  (ulong)0x08 ) +                             \
    (  (ulong)((p)[7]) <<  (ulong)0x00 ) )

/* assigns parsed value
   result is the size of the type */
#define FD_TEMPL_PARSE(TYPE,VAR,p) \
  ( ( (VAR) = (__typeof__((VAR)))FD_TEMPL_PARSE_IMPL_##TYPE((p)) ), sizeof(fd_quic_##TYPE) )


// returns bytes consumed
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                \
  ulong fd_quic_decode_##NAME( fd_quic_##NAME##_t * FD_RESTRICT out,   \
                               uchar const *        FD_RESTRICT buf,   \
                               ulong                            sz ) { \
    (void)out; (void)buf; (void)sz;                                    \
    ulong cur_byte = 0;                                                \
    ulong tmp_len = 0; (void)tmp_len;                                  \
    // TODO check min size here

// consumes single aligned byte in input
#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)                      \
    out->NAME = buf[cur_byte];                                         \
    cur_byte++;


// consumes aligned bytes in input
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                   \
    if( FD_UNLIKELY( cur_byte + sizeof(fd_quic_##TYPE) > sz ) )        \
      return FD_QUIC_PARSE_FAIL;                                       \
    cur_byte += FD_TEMPL_PARSE(TYPE,out->NAME,buf+cur_byte);


// always aligned
// packet numbers have special parsing, due to being protected by
// header protection
// stores the offset for packet processing
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                            \
    if( FD_UNLIKELY( cur_byte >= sz ) ) return FD_QUIC_PARSE_FAIL;     \
    out->NAME##_pnoff = (unsigned)cur_byte;


// consumes varint
// always aligned
// most significant two bits represent the width of the int
// remaining bits are all data bits
#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                            \
  do {                                                                 \
    out->NAME = 0;                                                     \
    if( FD_UNLIKELY( cur_byte >= sz ) ) return FD_QUIC_PARSE_FAIL;     \
    uint msb2 = buf[cur_byte] >> 6u;                                   \
    uint vsz  = 1U<<msb2;                                              \
    if( FD_UNLIKELY( cur_byte+vsz > sz ) ) return FD_QUIC_PARSE_FAIL;  \
    out->NAME = (fd_quic_##TYPE)fd_quic_varint_decode( buf+cur_byte, msb2 ); \
    cur_byte += vsz;                                                   \
  } while(0);


// VAR currently assumed to be aligned bytes
#define FD_TEMPL_MBR_ELEM_VAR(NAME,MIN,MAX,LEN_NAME)                   \
    tmp_len = out->LEN_NAME;                                           \
    if( FD_UNLIKELY( tmp_len<(MIN) || tmp_len>(MAX) ) ) {              \
      return FD_QUIC_PARSE_FAIL;                                       \
    }                                                                  \
    if( FD_UNLIKELY( cur_byte + tmp_len > sz )) {                      \
      return FD_QUIC_PARSE_FAIL;                                       \
    }                                                                  \
    for( ulong j=0; j<tmp_len; ++j ) {                                 \
      out->NAME[j] = buf[cur_byte+j];                                  \
    }                                                                  \
    cur_byte += tmp_len;


// VAR currently assumed to be aligned bytes
#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,MIN,MAX,LEN_NAME)               \
    tmp_len = out->LEN_NAME;                                           \
    if( FD_UNLIKELY( tmp_len<(MIN) || tmp_len>(MAX) ) ) {              \
      return FD_QUIC_PARSE_FAIL;                                       \
    }                                                                  \
    if( FD_UNLIKELY( cur_byte + tmp_len > sz )) {                      \
      return FD_QUIC_PARSE_FAIL;                                       \
    }                                                                  \
    out->NAME = &buf[cur_byte];                                        \
    cur_byte += tmp_len;


#define FD_TEMPL_MBR_ELEM_RAW(NAME,BYTES)                              \
    if( FD_UNLIKELY( cur_byte+(BYTES)>sz ) ) return FD_QUIC_PARSE_FAIL;\
    memcpy( out->NAME, buf+cur_byte, (BYTES) );                        \
    cur_byte += (BYTES);


// at end, return the number of bytes consumed
#define FD_TEMPL_DEF_STRUCT_END(NAME) \
    return cur_byte;                  \
  }

#include "fd_quic_dft.h"

