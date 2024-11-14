/* tracing functionality */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                               \
  static inline                                                       \
  void                                                                \
  fd_quic_trace_struct_##NAME( char **                    out_buf,    \
                               ulong *                    out_buf_sz, \
                               fd_quic_##NAME##_t const * data ) {    \
    (void)data;                                                       \
    char * p = *out_buf; (void)p;                                     \
    char * q = *out_buf + *out_buf_sz; (void)q;

#define trace(...) \
  (__extension__({ \
    int rtn = snprintf( (p), (ulong)((q)-(p)), __VA_ARGS__ ); \
    if( rtn < 0 ) rtn = 0; \
    if( rtn > (int)((q)-(p)) ) rtn = (int)((q)-(p)); \
    p += rtn; \
    (ulong)rtn; }))

#define FD_QUIC_FMT_uchar  "u"
#define FD_QUIC_FMT_ushort "u"
#define FD_QUIC_FMT_uint   "u"
#define FD_QUIC_FMT_ulong  "lu"

#define FD_QUIC_HEX_FMT_uchar  "x"
#define FD_QUIC_HEX_FMT_ushort "x"
#define FD_QUIC_HEX_FMT_uint   "x"
#define FD_QUIC_HEX_FMT_ulong  "lx"

#define FD_TEMPL_MBR_ELEM(NAME,TYPE) \
    trace( "\"" #NAME "\":" "%" FD_QUIC_FMT_##TYPE ", ", data->NAME );

#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE) \
    trace( "\"" #NAME "\": %" FD_QUIC_FMT_##TYPE ", ", data->NAME );

#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE) \
    trace( "\"" #NAME "\": %" FD_QUIC_FMT_##TYPE ", ", data->NAME );


#define FD_TEMPL_MBR_ELEM_VAR(NAME,BITS_MIN,BITS_MAX,LEN_NAME) \
    do { \
      trace( "\"" #NAME "\": [ " ); \
      ulong tmp_len = data->LEN_NAME; \
      if( tmp_len * 8 > BITS_MAX ) tmp_len = ( BITS_MAX + 7 ) / 8; \
      for( ulong j = 0; j < tmp_len; ++j ) { \
        trace( "0x%2.2x, ", data->NAME[j] ); \
      } \
      trace( " ], " ); \
    } while(0);

#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,BITS_MIN,BITS_MAX,LEN_NAME) \
    do { \
      trace( "\"" #NAME "\": [ " ); \
      ulong tmp_len = data->LEN_NAME; \
      if( tmp_len * 8 > BITS_MAX ) tmp_len = ( BITS_MAX + 7 ) / 8; \
      for( ulong j = 0; j < tmp_len; ++j ) { \
        trace( "0x%2.2x, ", data->NAME[j] ); \
      } \
      trace( " ], " ); \
    } while(0);

#define FD_TEMPL_MBR_ELEM_ARRAY(NAME,TYPE,BYTES_MIN,BYTES_MAX) \
    do { \
      trace( "\"" #NAME "\": [ " ); \
      ulong tmp_len = data->NAME##_len; \
      if( tmp_len > BYTES_MAX ) tmp_len = BYTES_MAX; \
      for( ulong j = 0; j < tmp_len; ++j ) { \
        trace( "0x%" FD_QUIC_HEX_FMT_##TYPE ", ", data->NAME[j] ); \
      } \
      trace( " ], " ); \
    } while(0);

#define FD_TEMPL_MBR_ELEM_FIXED(NAME,TYPE,BYTES) \
    do { \
      trace( "\"" #NAME "\" : [ " ); \
      for( ulong j = 0; j < BYTES; ++j ) { \
        trace( "0x%" FD_QUIC_HEX_FMT_##TYPE ", ", data->NAME[j] ); \
      } \
      trace( " ], " ); \
    } while(0);

#define FD_TEMPL_MBR_OPT(TYPE_NAME,NAME,MASK,...)   \
    do {                                            \
      _Bool cond = data->TYPE_NAME & (MASK);        \
      if( cond ) {                                  \
        __VA_ARGS__                                 \
      }                                             \
    } while(0);

#define FD_TEMPL_DEF_STRUCT_END(NAME) \
    *out_buf    = p; \
    *out_buf_sz = (ulong)(q - p); \
  }

#include "fd_quic_dft.h"

