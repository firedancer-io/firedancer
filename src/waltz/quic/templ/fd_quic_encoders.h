// QUIC encoders
#include "../../../util/log/fd_log.h"

/* TODO replace FD_QUIC_PARSE_FAIL with FD_QUIC_ENCODE_FAIL */

/* TODO add platform optimized versions of these
   e.g. 32 bit unaligned fetch w/ byte swap on intel */
#define FD_TEMPL_ENCODE_IMPL_uchar(p,val) (                            \
    ( (p)[0] = (uchar)( (val) ) ) )
#define FD_TEMPL_ENCODE_IMPL_ushort(p,val) (                           \
    ( (p)[0] = (uchar)( (ushort)(val) >> (ushort)0x08 ) ),             \
    ( (p)[1] = (uchar)( (ushort)(val) >> (ushort)0x00 ) ) )
#define FD_TEMPL_ENCODE_IMPL_uint(p,val) (                             \
    ( (p)[0] = (uchar)(   (uint)(val) >>   (uint)0x18 ) ),             \
    ( (p)[1] = (uchar)(   (uint)(val) >>   (uint)0x10 ) ),             \
    ( (p)[2] = (uchar)(   (uint)(val) >>   (uint)0x08 ) ),             \
    ( (p)[3] = (uchar)(   (uint)(val) >>   (uint)0x00 ) ) )
#define FD_TEMPL_ENCODE_IMPL_ulong(p,val) (                            \
    ( (p)[0] = (uchar)(  (ulong)(val) >>  (ulong)0x38 ) ),             \
    ( (p)[1] = (uchar)(  (ulong)(val) >>  (ulong)0x30 ) ),             \
    ( (p)[2] = (uchar)(  (ulong)(val) >>  (ulong)0x28 ) ),             \
    ( (p)[3] = (uchar)(  (ulong)(val) >>  (ulong)0x20 ) ),             \
    ( (p)[4] = (uchar)(  (ulong)(val) >>  (ulong)0x18 ) ),             \
    ( (p)[5] = (uchar)(  (ulong)(val) >>  (ulong)0x10 ) ),             \
    ( (p)[6] = (uchar)(  (ulong)(val) >>  (ulong)0x08 ) ),             \
    ( (p)[7] = (uchar)(  (ulong)(val) >>  (ulong)0x00 ) ) )

/* encodes the given type, "returns" the number of bytes encoded */
#define FD_TEMPL_ENCODE(TYPE,VAR,p) ( ( FD_TEMPL_ENCODE_IMPL_##TYPE((p),(VAR)) ), sizeof(fd_quic_##TYPE) )

/* returns bytes encoded

   frame is not const, as it may be mutated, for example to store offsets
   to particular bytes in the encoded data */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                \
  static inline                                                        \
  ulong                                                                \
  fd_quic_encode_##NAME( uchar *              buf,                     \
                         ulong                sz,                      \
                         fd_quic_##NAME##_t * frame ) {                \
    (void)frame;                                                       \
    uchar *  orig_buf = buf;                                           \
    uchar *  buf_end  = buf + sz;                                      \
    ulong    tmp_len  = 0;          (void)tmp_len;                     \
    uchar *  type_ptr = NULL;       (void)type_ptr;

/* encodes TYPE into output */
#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)                      \
    if( buf >= buf_end ) return FD_QUIC_PARSE_FAIL;                    \
    buf[0] = ID_LO;                                                    \
    type_ptr = buf++;


/* encodes aligned bytes into output */
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                   \
    if( FD_UNLIKELY( buf+sizeof(fd_quic_##TYPE) > buf_end ) )          \
      return FD_QUIC_PARSE_FAIL;                                       \
    buf += FD_TEMPL_ENCODE(TYPE,frame->NAME,buf);


/* encodes a packet number.  Assumes pkt_number_len == 3 (4 bytes)
   keeps the pointer to the start of the packet number field */
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                            \
    if( FD_UNLIKELY( buf+4 > buf_end ) ) return FD_QUIC_ENCODE_FAIL;   \
    frame->NAME##_pnoff = (unsigned)( buf - orig_buf );                \
    FD_STORE( uint, buf, fd_uint_bswap( (uint)frame->NAME ) );         \
    buf += 4;


/* encodes a VARINT
   always aligned
   most significant two bits represent the width of the int
   remaining bits are all data bits
   checks for capacity before writing */
#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                            \
    if( FD_UNLIKELY( buf+8 > buf_end ) ) return FD_QUIC_ENCODE_FAIL;   \
    buf += fd_quic_varint_encode( buf, frame->NAME );


// VAR currently assumed to be aligned bytes
#define FD_TEMPL_MBR_ELEM_VAR(NAME,MIN,MAX,LEN_NAME)                   \
    tmp_len = frame->LEN_NAME;                                         \
    if( FD_UNLIKELY( tmp_len<(MIN) || tmp_len>(MAX) ) ) {              \
      FD_LOG_DEBUG(( "buffer overflow encoding variable length field." \
            "  field: " #NAME                                          \
            "  MIN: %lu"                                               \
            "  MAX: %lu"                                               \
            "  " #LEN_NAME ": %lu"                                     \
            "  tmp_len: %lu\n",                                        \
            (ulong)MIN,                                                \
            (ulong)MAX,                                                \
            (ulong)frame->LEN_NAME,                                    \
            (ulong)tmp_len ));                                         \
      return FD_QUIC_PARSE_FAIL;                                       \
    }                                                                  \
    if( FD_UNLIKELY( (ulong)buf + tmp_len > (ulong)buf_end ) ) {       \
      return FD_QUIC_PARSE_FAIL;                                       \
    }                                                                  \
    fd_memcpy( buf, frame->NAME, tmp_len );                            \
    buf += tmp_len;


#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,MIN,MAX,LEN_NAME)     \
    FD_TEMPL_MBR_ELEM_VAR(NAME,MIN,MAX,LEN_NAME)

#define FD_TEMPL_MBR_ELEM_RAW(NAME,BYTES)                              \
    if( FD_UNLIKELY( buf+(BYTES) > buf_end ) )                         \
      return FD_QUIC_PARSE_FAIL;                                       \
    memcpy( buf, frame->NAME, (BYTES) );                               \
    buf += (BYTES);

/* at end, return the number of bytes consumed */
#define FD_TEMPL_DEF_STRUCT_END(NAME)                                  \
    return (ulong)( buf-orig_buf );                                    \
  }

#include "fd_quic_dft.h"

