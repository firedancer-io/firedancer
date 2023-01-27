#include "../fd_quic_common.h"

#include "fd_quic_transport_params.h"
#include "fd_quic_parse_util.h"

#include <stdio.h>


/* parses the varint at *buf (capacity *buf_sz)
   advances the *buf and reduces *buf_sz by the number of bytes
   consumed */
static inline
uint64_t
fd_quic_tp_parse_varint( uchar const ** buf, size_t * buf_sz ) {
  if( *buf_sz == 0 ) return ~(uint64_t)0;
  unsigned width = 1u << ( (unsigned)(*buf)[0] >> 6u ); 
  if( *buf_sz < width ) return ~(uint64_t)0;
  uint64_t value = (uint64_t)( (*buf)[0] & 0x3f ); 
  for( size_t j = 1; j < width; ++j ) { 
    value  = ( value << 8u ) + (uint64_t)(*buf)[j]; 
  } 
  *buf    += width;
  *buf_sz -= width;
  return value;
}


void
fd_quic_dump_transport_param_desc( FILE * out ) {
  fprintf( out, "Transport parameter descriptions:\n" );

#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  fprintf( out, #ID " " #TYPE " " #NAME "\n" DESC "\n\n" );

  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __
}


#define FD_QUIC_PARSE_TP_VARINT(NAME) \
  do { \
    if( sz == 0 ) return -2; \
    unsigned width = 1u << ( (unsigned)buf[0] >> 6u ); \
    if( sz < width ) return -3; \
    uint64_t value = (uint64_t)( buf[0] & 0x3f ); \
    for( size_t j = 1; j < width; ++j ) { \
      value  = ( value << 8u ) + (uint64_t)buf[j]; \
    } \
    params->NAME = value; \
    params->NAME##_present = 1; \
  } while(0)

#define FD_QUIC_PARSE_TP_CONN_ID(NAME) \
  for( size_t j = 0; j < sz; ++j ) { \
    params->NAME[j] = buf[j]; \
  } \
  params->NAME##_len = (uint8_t)sz; \
  params->NAME##_present = 1;

#define FD_QUIC_PARSE_TP_ZERO_LENGTH(NAME) \
  params->NAME = 1u; \
  params->NAME##_present = 1;

#define FD_QUIC_PARSE_TP_TOKEN(NAME) \
  for( size_t j = 0; j < sz; ++j ) { \
    params->NAME[j] = buf[j]; \
  } \
  params->NAME##_len = (uint8_t)sz; \
  params->NAME##_present = 1;

#define FD_QUIC_PARSE_TP_PREFERRED_ADDRESS(NAME) \
  for( size_t j = 0; j < sz; ++j ) { \
    params->NAME[j] = buf[j]; \
  } \
  params->NAME##_len = (uint8_t)sz; \
  params->NAME##_present = 1;


int
fd_quic_decode_transport_param( fd_quic_transport_params_t * params,
                                uint32_t                     id,
                                uchar const *                buf,
                                size_t                       sz ) {
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
                                 size_t                       buf_sz ) {
  while( buf_sz > 0 ) {
    /* upon success, this function adjusts buf and sz by bytes consumed */
    uint64_t param_id = fd_quic_tp_parse_varint( &buf, &buf_sz );
    /* TODO use a named constant/macro for return value */
    if( param_id > ~(uint32_t)0 ) return -1; /* parse failure */
    uint64_t param_sz = fd_quic_tp_parse_varint( &buf, &buf_sz );
    if( param_sz == ~(uint64_t)0 ) return -1; /* parse failure */
    int consumed = fd_quic_decode_transport_param( params, (uint32_t)param_id, buf, buf_sz );
    /* -1 is parameter not understood, which is simply ignored by spec */
    if( consumed < -1 ) return -1; /* parse failure */

    /* update buf and buf_sz */
    buf    += param_sz;
    buf_sz -= param_sz;
  }

  return 0; /* success */
}

#define FD_QUIC_DUMP_TP_VARINT(NAME) \
  fprintf( out, "%lu", (unsigned long)params->NAME )
#define FD_QUIC_DUMP_TP_CONN_ID(NAME) \
  do { \
    size_t sz = params->NAME##_len; \
    fprintf( out, "len(%d) ", (int)sz ); \
    for( size_t j = 0; j < sz; ++j ) { \
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


#define FD_QUIC_ENCODE_TP_VARINT(NAME,ID) \
  do { \
    size_t val_len = FD_QUIC_ENCODE_VARINT_LEN( params->NAME ); \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, ID ); \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, val_len ); \
    FD_QUIC_ENCODE_VARINT(buf,buf_sz,params->NAME); \
  } while(0)

#define FD_QUIC_ENCODE_TP_CONN_ID(NAME,ID) \
  do { \
    size_t val_len = params->NAME##_len; \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, ID ); \
    FD_QUIC_ENCODE_VARINT( buf, buf_sz, val_len ); \
    if( val_len + 1 > buf_sz ) return FD_QUIC_ENCODE_FAIL; \
    for( size_t j = 0; j < val_len; ++j ) { \
      buf[j] = params->NAME[j]; \
    } \
    buf += val_len; buf_sz -= val_len; \
  } while(0);

#define FD_QUIC_ENCODE_TP_ZERO_LENGTH(NAME,ID) \
  do { \
    if( params->NAME ) { \
      FD_QUIC_ENCODE_VARINT( buf, buf_sz, ID ); \
      FD_QUIC_ENCODE_VARINT( buf, buf_sz, 0 ); \
    } \
  } while(0)

#define FD_QUIC_ENCODE_TP_TOKEN(NAME,ID) \
  FD_QUIC_ENCODE_TP_CONN_ID(NAME,ID)

#define FD_QUIC_ENCODE_TP_PREFERRED_ADDRESS(NAME,ID) \
  FD_QUIC_ENCODE_TP_CONN_ID(NAME,ID)


/* determine footprint of each type */

#define FD_QUIC_FOOTPRINT_FAIL ((uint64_t)1 << (uint64_t)62)

/* we need the length of the ID + the length of the length of the parameter value
   plus the length of the parameter value */
#define FD_QUIC_FOOTPRINT_TP_VARINT(NAME,ID) \
  ( \
    FD_QUIC_ENCODE_VARINT_LEN( ID ) + \
    FD_QUIC_ENCODE_VARINT_LEN( FD_QUIC_ENCODE_VARINT_LEN( params->NAME ) ) + \
    FD_QUIC_ENCODE_VARINT_LEN( params->NAME ) \
  )

/* the length of a connection id is specified by *_len */
#define FD_QUIC_FOOTPRINT_TP_CONN_ID(NAME,ID) \
  ( \
    FD_QUIC_ENCODE_VARINT_LEN( ID ) + \
    FD_QUIC_ENCODE_VARINT_LEN( params->NAME##_len ) + \
    params->NAME##_len \
  )

#define FD_QUIC_FOOTPRINT_TP_ZERO_LENGTH(NAME,ID) \
  ( \
    FD_QUIC_ENCODE_VARINT_LEN( ID ) + \
    FD_QUIC_ENCODE_VARINT_LEN( 0 ) \
  )

#define FD_QUIC_FOOTPRINT_TP_TOKEN(NAME,ID) \
  FD_QUIC_FOOTPRINT_TP_CONN_ID(NAME,ID)

#define FD_QUIC_FOOTPRINT_TP_PREFERRED_ADDRESS(NAME,ID) \
  FD_QUIC_FOOTPRINT_TP_CONN_ID(NAME,ID)


// encode transport parameters into a buffer
// returns the number of bytes written
size_t
fd_quic_encode_transport_params( uchar *                            buf,
                                 size_t                             buf_sz,
                                 fd_quic_transport_params_t const * params ) {
  size_t orig_buf_sz = buf_sz;
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  if( params->NAME##_present ) { \
    FD_QUIC_ENCODE_TP_##TYPE(NAME,ID); \
  }
  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __

  return orig_buf_sz - buf_sz;
}


size_t
fd_quic_transport_params_footprint( fd_quic_transport_params_t const * params ) {
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  + ( ( params->NAME##_present ) ?  FD_QUIC_FOOTPRINT_TP_##TYPE(NAME,ID) : 0 )
  return  FD_QUIC_TRANSPORT_PARAMS( __, _ );
#undef __
}

