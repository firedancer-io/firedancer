#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                \
  void fd_quic_dump_struct_##NAME( fd_quic_##NAME##_t const * data ) { \
    (void)data;

#define FD_QUIC_FMT_uchar  "u"
#define FD_QUIC_FMT_ushort "u"
#define FD_QUIC_FMT_uint   "u"
#define FD_QUIC_FMT_ulong  "lu"

#define FD_QUIC_HEX_FMT_uchar  "x"
#define FD_QUIC_HEX_FMT_ushort "x"
#define FD_QUIC_HEX_FMT_uint   "x"
#define FD_QUIC_HEX_FMT_ulong  "lx"

#define FD_TEMPL_MBR_FRAME_TYPE(TYPE,ID_LO,ID_HI) \
    if( ID_LO == ID_HI ) { \
      printf( "  " "frame_type : %x\n", (unsigned)(ID_LO) ); \
    } else { \
      printf( "  " "frame_type : %x - %x\n", (unsigned)(ID_LO), (unsigned)(ID_HI) ); \
    }

#define FD_TEMPL_MBR_ELEM(NAME,TYPE) \
    printf( "  " #NAME ": %" FD_QUIC_FMT_##TYPE " 0x%" FD_QUIC_HEX_FMT_##TYPE "\n", data->NAME, data->NAME );

#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE) \
    printf( "  " #NAME ": %" FD_QUIC_FMT_##TYPE " 0x%" FD_QUIC_HEX_FMT_##TYPE "\n", data->NAME, data->NAME );

#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE) \
    printf( "  " #NAME " offset: %u\n", data->NAME##_pnoff );

#define FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS) \
    printf( "  " #NAME ": %" FD_QUIC_FMT_##TYPE " 0x%" FD_QUIC_HEX_FMT_##TYPE "\n", data->NAME, data->NAME );

#define FD_TEMPL_MBR_ELEM_BITS_TYPE(NAME,TYPE,BITS,CODE) \
          FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)

#define FD_TEMPL_MBR_ELEM_VAR(NAME,BITS_MIN,BITS_MAX,LEN_NAME) \
    do { \
      printf( "  " #NAME ": " ); \
      ulong tmp_len = data->LEN_NAME; \
      if( tmp_len * 8 > BITS_MAX ) tmp_len = ( BITS_MAX + 7 ) / 8; \
      for( ulong j = 0; j < tmp_len; ++j ) { \
        printf( " %2.2x", data->NAME[j] ); \
      } \
      printf( "\n" ); \
    } while(0);

#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,BITS_MIN,BITS_MAX,LEN_NAME) \
    do { \
      printf( "  " #NAME ": " ); \
      ulong tmp_len = data->LEN_NAME; \
      if( tmp_len * 8 > BITS_MAX ) tmp_len = ( BITS_MAX + 7 ) / 8; \
      for( ulong j = 0; j < tmp_len; ++j ) { \
        printf( " %2.2x", data->NAME[j] ); \
      } \
      printf( "\n" ); \
    } while(0);

#define FD_TEMPL_MBR_ELEM_ARRAY(NAME,TYPE,BYTES_MIN,BYTES_MAX) \
    printf( "  " #NAME " count: %u\n", data->NAME##_len ); \
    do { \
      printf( "  " #NAME ": " ); \
      ulong tmp_len = data->NAME##_len; \
      if( tmp_len > BYTES_MAX ) tmp_len = BYTES_MAX; \
      for( ulong j = 0; j < tmp_len; ++j ) { \
        printf( " %" FD_QUIC_HEX_FMT_##TYPE, data->NAME[j] ); \
      } \
      printf( "\n" ); \
    } while(0);

#define FD_TEMPL_MBR_ELEM_FIXED(NAME,TYPE,BYTES) \
    printf( "  " #NAME " count: %u\n", (uint)(BYTES) ); \
    do { \
      printf( "  " #NAME ": " ); \
      for( ulong j = 0; j < BYTES; ++j ) { \
        printf( " %" FD_QUIC_HEX_FMT_##TYPE, data->NAME[j] ); \
      } \
      printf( "\n" ); \
    } while(0);

#define FD_TEMPL_MBR_OPT(STRUCT,NAME,COND,TEMPL) \
    TEMPL

#define FD_TEMPL_DEF_STRUCT_END(NAME) \
  }

#include "fd_quic_dft.h"

