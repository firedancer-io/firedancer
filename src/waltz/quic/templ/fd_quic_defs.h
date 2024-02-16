// template for definitions

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                        \
  struct fd_quic_##NAME {

#define FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)                 \
    fd_quic_##TYPE NAME;

#define FD_TEMPL_MBR_ELEM_BITS_TYPE(NAME,TYPE,BITS,CODE)       \
    fd_quic_##TYPE NAME;

#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                           \
    fd_quic_##TYPE NAME;

/* hidden does not get serialized nor deserialized */
#define FD_TEMPL_MBR_ELEM_HIDDEN(NAME,TYPE)                    \
    fd_quic_##TYPE NAME;

#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                    \
    fd_quic_##TYPE NAME;

/* don't actually decode the packet number, because it's
   encrypted at this point
   encoding still needs the member, and the length */
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                    \
    fd_quic_##TYPE NAME;                                       \
    unsigned       NAME##_pnoff;                               \
    unsigned       NAME##_bits;

#define FD_TEMPL_MBR_ELEM_VAR(NAME,BITS_MIN,BITS_MAX,LEN_NAME) \
    uchar NAME[(BITS_MAX+7)>>3];

#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,BITS_MIN,BITS_MAX,LEN_NAME) \
    uchar const * NAME;

#define FD_TEMPL_MBR_ELEM_ARRAY(NAME,TYPE,BYTES_MIN,BYTES_MAX) \
    fd_quic_uint   NAME##_len;                                 \
    fd_quic_##TYPE NAME[BYTES_MAX];

#define FD_TEMPL_MBR_ELEM_FIXED(NAME,TYPE,BYTES)               \
    fd_quic_##TYPE NAME[BYTES];

#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)              \
    uchar NAME;

#define FD_TEMPL_MBR_FRAME_TYPE_FLAG(NAME,MASK)                \
    uint NAME;

#define FD_TEMPL_MBR_OPT(STRUCT,NAME,COND,TEMPL)               \
    uchar NAME##_opt;                                          \
    TEMPL

#define FD_TEMPL_DEF_STRUCT_END(NAME)                          \
  };                                                           \
  typedef struct fd_quic_##NAME fd_quic_##NAME##_t;

#include "fd_quic_dft.h"

