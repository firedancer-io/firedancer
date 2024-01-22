#include "../fd_quic_common.h"

#include "fd_quic_transport_params.h"
#include "fd_quic_parse_util.h"

#include <stdio.h>

void
fd_quic_dump_transport_param_desc( FILE * out ) {
  fprintf( out, "Transport parameter descriptions:\n" );

#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  fprintf( out, #ID " " #TYPE " " #NAME "\n" DESC "\n\n" );

  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __
}


#define FD_QUIC_PARSE_TP_VARINT(NAME) \
  do {                                                 \
    if( FD_UNLIKELY( sz==0    ) ) return -2;           \
    uint width = 1u << ( (unsigned)buf[0] >> 6u );     \
    if( FD_UNLIKELY( sz<width ) ) return -3;           \
    ulong value = (ulong)( buf[0] & 0x3f );            \
    for( ulong j=1; j<width; ++j ) {                   \
      value= ( value<<8u ) + (ulong)buf[j];            \
    }                                                  \
    params->NAME = value;                              \
    params->NAME##_present = 1;                        \
  } while(0)

#define FD_QUIC_PARSE_TP_CONN_ID(NAME)                      \
  do {                                                      \
    if( FD_UNLIKELY( sz>sizeof(params->NAME) ) ) return -1; \
    fd_memcpy( params->NAME, buf, sz );                     \
    params->NAME##_len = (uchar)sz;                         \
    params->NAME##_present = 1;                             \
  } while(0)

#define FD_QUIC_PARSE_TP_ZERO_LENGTH(NAME) \
  params->NAME = 1u;                       \
  params->NAME##_present = 1;

#define FD_QUIC_PARSE_TP_TOKEN(NAME)                        \
  do {                                                      \
    if( FD_UNLIKELY( sz>sizeof(params->NAME) ) ) return -1; \
    fd_memcpy( params->NAME, buf, sz );                     \
    params->NAME##_len = (uchar)sz;                         \
    params->NAME##_present = 1;                             \
  } while(0)

#define FD_QUIC_PARSE_TP_PREFERRED_ADDRESS(NAME)            \
  do {                                                      \
    if( FD_UNLIKELY( sz>sizeof(params->NAME) ) ) return -1; \
    fd_memcpy( params->NAME, buf, sz );                     \
    params->NAME##_len = (uchar)sz;                         \
    params->NAME##_present = 1;                             \
  } while(0)


int
fd_quic_decode_transport_param( fd_quic_transport_params_t * params,
                                uint                         id,
                                uchar const *                buf,
                                ulong                        sz ) {
  // This compiles into a jump table, which is reasonably fast
  switch( id ) {
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  case ID: { \
      FD_QUIC_PARSE_TP_##TYPE(NAME); \
      return (int)id; \
    } \

  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __

  }

  return -1; // parameter with value id not known
}

int
fd_quic_decode_transport_params( fd_quic_transport_params_t * params,
                                 uchar const *                buf,
                                 ulong                        buf_sz ) {
  while( buf_sz > 0 ) {
    /* upon success, this function adjusts buf and sz by bytes consumed */
    ulong param_id = fd_quic_tp_parse_varint( &buf, &buf_sz );
    /* TODO use a named constant/macro for return value */
    if( FD_UNLIKELY( param_id > ~(uint)0   ) ) return -1; /* parse failure */

    ulong param_sz = fd_quic_tp_parse_varint( &buf, &buf_sz );
    if( FD_UNLIKELY( param_sz == ~(ulong)0 ) ) return -1; /* parse failure */
    if( FD_UNLIKELY( param_sz >  buf_sz    ) ) return -1; /* length OOB */

    int consumed = fd_quic_decode_transport_param( params, (uint)param_id, buf, param_sz );
    /* -1 is parameter not understood, which is simply ignored by spec */
    if( FD_UNLIKELY( consumed < -1 ) ) return -1; /* parse failure */

    /* update buf and buf_sz */
    buf    += param_sz;
    buf_sz -= param_sz;
  }

  return 0; /* success */
}

#define FD_QUIC_DUMP_TP_VARINT(NAME) \
  fprintf( out, "%lu", (ulong)params->NAME )
#define FD_QUIC_DUMP_TP_CONN_ID(NAME) \
  do { \
    ulong sz = params->NAME##_len; \
    fprintf( out, "len(%d) ", (int)sz ); \
    for( ulong j = 0; j < sz; ++j ) { \
      fprintf( out, "%2.2x ", (unsigned)params->NAME[j] ); \
    } \
  } while(0)
#define FD_QUIC_DUMP_TP_ZERO_LENGTH(NAME) \
  fprintf( out, "%u", (unsigned)params->NAME )
#define FD_QUIC_DUMP_TP_TOKEN(NAME) FD_QUIC_DUMP_TP_CONN_ID(NAME)
#define FD_QUIC_DUMP_TP_PREFERRED_ADDRESS(NAME) FD_QUIC_DUMP_TP_CONN_ID(NAME)

void
fd_quic_dump_transport_params( fd_quic_transport_params_t const * params, FILE * out ) {
  fprintf( out, "Transport params:\n" );
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  fprintf( out, "  %-50s: %s ", #NAME " (" #ID ")", params->NAME##_present ? "*" : " " ); \
  FD_QUIC_DUMP_TP_##TYPE(NAME); \
  fprintf( out, "\n" );
  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __
}


#define FD_QUIC_ENCODE_TP_VARINT(NAME,ID)                              \
  do {                                                                 \
    ulong val_len = FD_QUIC_ENCODE_VARINT_LEN( params->NAME );         \
    if( val_len == FD_QUIC_ENCODE_FAIL ) return FD_QUIC_ENCODE_FAIL;   \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, ID );                          \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, val_len );                     \
    FD_QUIC_ENCODE_VARINT(buf,buf_sz,params->NAME);                    \
  } while(0)

#define FD_QUIC_ENCODE_TP_CONN_ID(NAME,ID)                             \
  do {                                                                 \
    ulong val_len = params->NAME##_len;                                \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, ID );                          \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, val_len );                     \
    if( val_len + 1 > buf_sz ) return FD_QUIC_ENCODE_FAIL;             \
    for( ulong j = 0; j < val_len; ++j ) {                             \
      buf[j] = params->NAME[j];                                        \
    }                                                                  \
    buf += val_len; buf_sz -= val_len;                                 \
  } while(0);

#define FD_QUIC_ENCODE_TP_ZERO_LENGTH(NAME,ID)                         \
  do {                                                                 \
    if( params->NAME ) {                                               \
      FD_QUIC_ENCODE_VARINT( buf, buf_sz, ID );                        \
      FD_QUIC_ENCODE_VARINT( buf, buf_sz, 0 );                         \
    }                                                                  \
  } while(0)

#define FD_QUIC_ENCODE_TP_TOKEN(NAME,ID) \
  FD_QUIC_ENCODE_TP_CONN_ID(NAME,ID)

#define FD_QUIC_ENCODE_TP_PREFERRED_ADDRESS(NAME,ID) \
  FD_QUIC_ENCODE_TP_CONN_ID(NAME,ID)


/* determine footprint of each type */

#define FD_QUIC_FOOTPRINT_FAIL ((ulong)1 << (ulong)62)

/* we need the length of the ID + the length of the length of the parameter value
   plus the length of the parameter value */
#define FD_QUIC_FOOTPRINT_TP_VARINT(NAME,ID)                           \
  (                                                                    \
    FD_QUIC_ENCODE_VARINT_LEN( ID ) +                                  \
    FD_QUIC_ENCODE_VARINT_LEN( FD_QUIC_ENCODE_VARINT_LEN( params->NAME ) ) + \
    FD_QUIC_ENCODE_VARINT_LEN( params->NAME )                          \
  )

/* the length of a connection id is specified by *_len */
#define FD_QUIC_FOOTPRINT_TP_CONN_ID(NAME,ID)                          \
  (                                                                    \
    FD_QUIC_ENCODE_VARINT_LEN( ID ) +                                  \
    FD_QUIC_ENCODE_VARINT_LEN( params->NAME##_len ) +                  \
    params->NAME##_len                                                 \
  )

#define FD_QUIC_FOOTPRINT_TP_ZERO_LENGTH(NAME,ID)                      \
  (                                                                    \
    FD_QUIC_ENCODE_VARINT_LEN( ID ) +                                  \
    FD_QUIC_ENCODE_VARINT_LEN( 0 )                                     \
  )

#define FD_QUIC_FOOTPRINT_TP_TOKEN(NAME,ID) \
  FD_QUIC_FOOTPRINT_TP_CONN_ID(NAME,ID)

#define FD_QUIC_FOOTPRINT_TP_PREFERRED_ADDRESS(NAME,ID) \
  FD_QUIC_FOOTPRINT_TP_CONN_ID(NAME,ID)


/* validate TP_VARINT */
#define FD_QUIC_VALIDATE_TP_VARINT(NAME,ID)                          \
  (                                                                  \
  FD_QUIC_VALIDATE_VARINT( ID ) |                                    \
  FD_QUIC_VALIDATE_VARINT( params->NAME )                            \
  )

/* validate TP_CONN_ID */
#define FD_QUIC_VALIDATE_TP_CONN_ID(NAME,ID)                       \
  (                                                                \
  FD_QUIC_VALIDATE_VARINT( ID ) |                                  \
  FD_QUIC_VALIDATE_VARINT( params->NAME##_len )                    \
  )

#define FD_QUIC_VALIDATE_TP_ZERO_LENGTH(NAME,ID)                   \
  FD_QUIC_VALIDATE_VARINT( ID )

#define FD_QUIC_VALIDATE_TP_TOKEN(NAME,ID) \
  FD_QUIC_VALIDATE_TP_CONN_ID(NAME,ID)

#define FD_QUIC_VALIDATE_TP_PREFERRED_ADDRESS(NAME,ID) \
  FD_QUIC_VALIDATE_TP_CONN_ID(NAME,ID)


// encode transport parameters into a buffer
// returns the number of bytes written
ulong
fd_quic_encode_transport_params( uchar *                            buf,
                                 ulong                             buf_sz,
                                 fd_quic_transport_params_t const * params ) {
  ulong orig_buf_sz = buf_sz;
#define __( NAME, ID, TYPE, DFT, DESC, ... )                           \
  if( params->NAME##_present ) {                                       \
    FD_QUIC_ENCODE_TP_##TYPE(NAME,ID);                                 \
  }
  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __

  return orig_buf_sz - buf_sz;
}


ulong
fd_quic_transport_params_footprint( fd_quic_transport_params_t const * params ) {
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  + ( ( params->NAME##_present ) ?  FD_QUIC_FOOTPRINT_TP_##TYPE(NAME,ID) : 0 )
  return  FD_QUIC_TRANSPORT_PARAMS( __, _ );
#undef __
}


int
fd_quic_transport_params_validate( fd_quic_transport_params_t const * params ) {
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  & ( (!params->NAME##_present) | FD_QUIC_VALIDATE_TP_##TYPE(NAME,ID) )
  return 1 FD_QUIC_TRANSPORT_PARAMS( __, _ );
#undef __
}

