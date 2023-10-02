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


/* determines the footprint of unaligned bits */
#define FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)                           \
    char NAME[(BITS+7u)>>3u];

#define FD_TEMPL_MBR_ELEM_BITS_TYPE(NAME,TYPE,BITS,CODE) \
          FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)


/* VAR currently assumed to be aligned bytes */
#define FD_TEMPL_MBR_ELEM_VAR(NAME,BITS_MIN,BITS_MAX,LEN_NAME)           \
    char NAME[(BITS_MAX+7u)>>3u];


/* VAR_RAW currently assumed to be aligned bytes */
#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,BITS_MIN,BITS_MAX,LEN_NAME)       \
    char NAME[(BITS_MAX+7u)>>3u];

/* determine the footprint of encoded ARRAY */
#define FD_TEMPL_MBR_ELEM_ARRAY(NAME,TYPE,BYTES_MIN,BYTES_MAX)           \
    char NAME[(FD_TEMPL_ENCODE_FP(TYPE)) * (BYTES_MAX)];

/* FIXED is an array of elements, each of the same size,
   with length constant */
#define FD_TEMPL_MBR_ELEM_FIXED(NAME,TYPE,ELEMS)                         \
    char NAME[ELEMS * sizeof( fd_quic_##TYPE )];

/* TODO remove abort() once tested */
#define FD_TEMPL_MBR_OPT(TYPE,NAME,MASK,...)

/* at end, return the number of bytes consumed */
#define FD_TEMPL_DEF_STRUCT_END(NAME)                                    \
  };

#include "fd_quic_dft.h"

