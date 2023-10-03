/* QUIC encoders footprint */

/* used to define functions for determining footprint
   without encoding the data */

/* "returns" the number of bytes encoded */
#define FD_TEMPL_ENCODE_FP(TYPE) ( sizeof(fd_quic_##TYPE) )

/* returns bytes to be encoded */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                    \
  ulong fd_quic_encode_footprint_##NAME( fd_quic_##NAME##_t * frame ) {   \
    (void)frame;                                                           \
    ulong   buf      = 0;                                                 \
    ulong   cur_bit  = 0;          (void)cur_bit;                         \
    ulong   tmp_len  = 0;          (void)tmp_len;                         \

/* 1 byte for TYPE */
#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)                          \
    buf += (cur_bit != 0);                                                 \
    cur_bit = 0;                                                           \
    buf++;


/* determines footprint of element */
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                        \
    buf += (cur_bit != 0);                                                  \
    cur_bit = 0;                                                            \
    buf += FD_TEMPL_ENCODE_FP(TYPE);                                        \


/* determines the encoding footprint of the PKTNUM */
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                              \
    buf += (cur_bit != 0);                                               \
    cur_bit = 0;                                                         \
    buf += (ulong)(frame->NAME##_bits+7u) >> (ulong)3u;


/* determines the encoding footprint of the VARINT */
#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                            \
    buf += (cur_bit != 0);                                             \
    cur_bit = 0;                                                       \
    tmp_len = FD_QUIC_ENCODE_VARINT_LEN(frame->NAME);                  \
    if( tmp_len == FD_QUIC_ENCODE_FAIL ) return FD_QUIC_ENCODE_FAIL;   \
    buf += tmp_len;                                                    \


/* determines the footprint of unaligned bits */
#define FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)                           \
    cur_bit += BITS;                                                     \
    buf += cur_bit >> 3;                                                 \
    cur_bit &= 7;                                                        \

#define FD_TEMPL_MBR_ELEM_BITS_TYPE(NAME,TYPE,BITS,CODE) \
          FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)


/* VAR currently assumed to be aligned bytes */
#define FD_TEMPL_MBR_ELEM_VAR(NAME,BITS_MIN,BITS_MAX,LEN_NAME)           \
    buf += (cur_bit != 0);                                               \
    cur_bit = 0;                                                         \
    tmp_len = frame->LEN_NAME;                                           \
    buf += tmp_len;


/* VAR_RAW currently assumed to be aligned bytes */
#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,BITS_MIN,BITS_MAX,LEN_NAME)       \
    buf += (cur_bit != 0);                                               \
    cur_bit = 0;                                                         \
    tmp_len = frame->LEN_NAME;                                           \
    buf += tmp_len;

/* determine the footprint of encoded ARRAY */
#define FD_TEMPL_MBR_ELEM_ARRAY(NAME,TYPE,BYTES_MIN,BYTES_MAX)           \
    buf += (cur_bit != 0);                                               \
    cur_bit = 0;                                                         \
    tmp_len = frame->NAME##_len * sizeof(fd_quic_##TYPE);                \
    buf += tmp_len * FD_TEMPL_ENCODE_FP(TYPE);                           \

/* FIXED is an array of elements, each of the same size,
   with length constant */
#define FD_TEMPL_MBR_ELEM_FIXED(NAME,TYPE,ELEMS)                         \
    buf += (cur_bit != 0);                                               \
    cur_bit = 0;                                                         \
    buf += ELEMS * sizeof( fd_quic_##TYPE );

/* TODO remove abort() once tested */
#define FD_TEMPL_MBR_OPT(TYPE,NAME,MASK,...)                             \
    if( frame->NAME##_opt ) {                                            \
      __VA_ARGS__                                                        \
    }


/* at end, return the number of bytes consumed */
#define FD_TEMPL_DEF_STRUCT_END(NAME)                                    \
    buf += (cur_bit != 0);                                               \
    return buf;                                                          \
  }

#include "fd_quic_dft.h"

