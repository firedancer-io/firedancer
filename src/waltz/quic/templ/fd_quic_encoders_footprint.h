/* QUIC encoders footprint */

/* used to define functions for determining footprint upper bound
   without encoding the data */

/* "returns" the number of bytes encoded */
#define FD_TEMPL_ENCODE_FP(TYPE) ( sizeof(fd_quic_##TYPE) )

/* returns bytes to be encoded */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                   \
  ulong fd_quic_encode_footprint_##NAME( fd_quic_##NAME##_t * frame ) {   \
    (void)frame;                                                          \
    ulong   buf      = 0;                                                 \
    ulong   tmp_len  = 0;          (void)tmp_len;                         \

/* 1 byte for TYPE */
#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)                         \
    buf++;


/* determines footprint of element */
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                        \
    buf += FD_TEMPL_ENCODE_FP(TYPE);                                        \


/* worst case pktnum encoded size */
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                            \
    buf += 4;


/* worst case varint encoded size */
#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                            \
    buf += 8;                                                          \


#define FD_TEMPL_MBR_ELEM_VAR(NAME,MIN,MAX,LEN_NAME)                     \
    tmp_len = frame->LEN_NAME;                                           \
    buf += tmp_len;


#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,MIN,MAX,LEN_NAME)                 \
    tmp_len = frame->LEN_NAME;                                           \
    buf += tmp_len;

#define FD_TEMPL_MBR_ELEM_RAW(NAME,BYTES) \
    buf += (BYTES);

/* at end, return the number of bytes consumed */
#define FD_TEMPL_DEF_STRUCT_END(NAME)                                    \
    return buf;                                                          \
  }

#include "fd_quic_dft.h"

