/* QUIC encoders footprint */

/* used to find max encoding sizes for compile time allocations
   constructs structs with char arrays to determine the sizes
   this avoids the need for packed
   then a simple sizeof does the job */

/* returns the max footprint for a given frame */
#define FD_QUIC_MAX_FOOTPRINT(NAME) \
  (sizeof(struct fd_quic_max_fp_struct_##NAME))

/* "returns" the number of bytes encoded */
#define FD_TEMPL_ENCODE_FP(TYPE) ( sizeof(fd_quic_##TYPE) )

/* returns bytes to be encoded */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                    \
  struct fd_quic_max_fp_struct_##NAME {

/* 1 byte for TYPE */
#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)                          \
    char type[1];


/* determines footprint of element */
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                       \
    char NAME[FD_TEMPL_ENCODE_FP(TYPE)];


/* determines the encoding footprint of the PKTNUM */
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                                \
    char NAME[8];


/* determines the encoding footprint of the VARINT */
#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                            \
    char NAME[8];


#define FD_TEMPL_MBR_ELEM_VAR(NAME,MIN,MAX,LEN_NAME) \
    char NAME[MAX];


#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,MIN,MAX,LEN_NAME) \
    char NAME[MAX];


#define FD_TEMPL_MBR_ELEM_RAW(NAME,BYTES) \
    char NAME[BYTES];


/* at end, return the number of bytes consumed */
#define FD_TEMPL_DEF_STRUCT_END(NAME)                                    \
  };

#include "fd_quic_dft.h"

