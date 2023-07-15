#ifndef HEADER_src_ballet_tls_fd_tls_serde_h
#define HEADER_src_ballet_tls_fd_tls_serde_h

/* fd_tls_serde.h provides branch-minimizing (de-)serializer macros for
   internal use. */

/* FD_TLS_SERDE_{BEGIN,END} create and terminate a bounds checking
   context.  Internally, creates a new do/while(0) scope. */

#include "fd_tls_proto.h"
#define FD_TLS_SERDE_BEGIN do { \
  int valid = 1;                \

#define FD_TLS_SERDE_END } while(0);

/* FD_TLS_SERDE_LOCATE defines a local variable pointing to the would-
   be position of the field to be decoded, which may be out-of-bounds.
   Also extends the "valid" expression to include a bounds check for
   this field.  Both the "valid" expression and this local can be fully
   constant-propagated if sz is constant. */

#define FD_TLS_SERDE_LOCATE( IDX, FIELD, FIELD_TYPE, FIELD_CNT )             \
  ulong        _field_##IDX##_laddr = wire_laddr;                            \
  ulong const  _field_##IDX##_cnt   = (FIELD_CNT);                           \
  ulong const  _field_##IDX##_sz    = sizeof(FIELD_TYPE)*_field_##IDX##_cnt; \
  valid &= (wire_sz    >= _field_##IDX##_sz);                                \
            wire_sz    -= _field_##IDX##_sz;                                 \
            wire_laddr += _field_##IDX##_sz;

/* FD_TLS_SERDE_CHECK performs tbe bounds checks queued by prior
   FD_TLS_SERDE_LOCATE ops. */

#define FD_TLS_SERDE_CHECK \
  if( FD_UNLIKELY( !valid ) ) return -(long)FD_TLS_ALERT_DECODE_ERROR;

/* FD_TLS_SERDE_DECODE generates a non-overlapping memory copy for the
   given field.  Field should be bounds checked at this point.

   Note: We use __extension__ here because ISO C forbids casting a
         non-scalar type to itself.  (as is the case with tls_u24). */

#define FD_TLS_SERDE_DECODE( IDX, FIELD, FIELD_TYPE, FIELD_CNT ) \
  do {                                                           \
    memcpy( (FIELD), (void const *)_field_##IDX##_laddr, _field_##IDX##_sz ); \
    FIELD_TYPE * _field_##IDX##_ptr = (FIELD);                   \
    for( ulong i=0; i < (FIELD_CNT); i++ ) {                     \
      *((_field_##IDX##_ptr)++) = __extension__                  \
        (FIELD_TYPE)fd_##FIELD_TYPE##_bswap( (FIELD)[i] );       \
    }                                                            \
  } while(0);

#define FD_TLS_SERDE_ENCODE( IDX, FIELD, FIELD_TYPE, FIELD_CNT ) \
  do {                                                           \
    FIELD_TYPE * _field_##IDX##_ptr = (FIELD);                   \
    for( ulong i=0; i < (FIELD_CNT); i++ ) {                     \
      *((_field_##IDX##_ptr)++) = __extension__                  \
        (FIELD_TYPE)fd_##FIELD_TYPE##_bswap( (FIELD)[i] );       \
    }                                                            \
    memcpy( (void *)_field_##IDX##_laddr, (FIELD), _field_##IDX##_sz ); \
  } while(0);

/* FD_TLS_DECODE_FIELD is a convenience macro for decoding a single
   field with known size. */

#define FD_TLS_DECODE_FIELD( FIELD, FIELD_TYPE )  \
  FD_TLS_SERDE_BEGIN                              \
  FD_TLS_SERDE_LOCATE( _, FIELD, FIELD_TYPE, 1 )  \
  FD_TLS_SERDE_CHECK                              \
  FD_TLS_SERDE_DECODE(  _, FIELD, FIELD_TYPE, 1 ) \
  FD_TLS_SERDE_END

#define FD_TLS_ENCODE_FIELD( FIELD, FIELD_TYPE )  \
  FD_TLS_SERDE_BEGIN                              \
  FD_TLS_SERDE_LOCATE( _, FIELD, FIELD_TYPE, 1 )  \
  FD_TLS_SERDE_CHECK                              \
  FD_TLS_SERDE_ENCODE(  _, FIELD, FIELD_TYPE, 1 ) \
  FD_TLS_SERDE_END

/* FD_TLS_DECODE_STATIC_BATCH is a convenience macro for decoding a
   batch of static sized fields in a new decode context. */

#define FD_TLS_DECODE_STATIC_BATCH( fields ) \
  FD_TLS_SERDE_BEGIN                         \
  fields( FD_TLS_SERDE_LOCATE )              \
  FD_TLS_SERDE_CHECK                         \
  fields( FD_TLS_SERDE_DECODE )              \
  FD_TLS_SERDE_END

#define FD_TLS_ENCODE_STATIC_BATCH( fields ) \
  FD_TLS_SERDE_BEGIN                         \
  fields( FD_TLS_SERDE_LOCATE )              \
  FD_TLS_SERDE_CHECK                         \
  fields( FD_TLS_SERDE_ENCODE )              \
  FD_TLS_SERDE_END

#define FD_TLS_DECODE_LIST_BEGIN( LIST_SZ_TYPE, ALIGN )           \
  do {                                                            \
    LIST_SZ_TYPE list_sz;                                         \
    FD_TLS_DECODE_FIELD( &list_sz, LIST_SZ_TYPE );                \
    if( FD_UNLIKELY( !fd_ulong_is_aligned( list_sz, (ALIGN) ) ) ) \
      return -(long)FD_TLS_ALERT_DECODE_ERROR;                    \
    ulong list_start = wire_laddr;                                \
    ulong list_stop  = list_start + list_sz;                      \
    while( wire_laddr < list_stop )                               \

#define FD_TLS_DECODE_LIST_END                     \
    if( FD_UNLIKELY( wire_laddr != list_stop ) )   \
      return -(long)FD_TLS_ALERT_DECODE_ERROR;     \
  } while(0);                                      \

#define FD_TLS_SKIP_FIELD( FIELD_TYPE ) (__extension__({ \
    int valid = 1;                                       \
    FD_TLS_SERDE_LOCATE( , , FIELD_TYPE, 1   )           \
    FD_TLS_SERDE_CHECK                                   \
    (FIELD_TYPE *)_field__laddr;                         \
  }))

#define FD_TLS_SKIP_FIELDS( FIELD_TYPE, CNT ) (__extension__({ \
    int valid = 1;                                             \
    FD_TLS_SERDE_LOCATE( , , FIELD_TYPE, (CNT)   )             \
    FD_TLS_SERDE_CHECK                                         \
    (FIELD_TYPE *)_field__laddr;                               \
  }))

#define FD_TLS_DECODE_SUB( FUNC, OUT ) do {                      \
    long res = FUNC( (OUT), (void const *)wire_laddr, wire_sz ); \
    if( FD_UNLIKELY( res<0L ) ) return res;                      \
    wire_laddr += (ulong)res;                                    \
    wire_sz    -= (ulong)res;                                    \
  } while(0)

#define FD_TLS_ENCODE_SUB( FUNC, IN ) (__extension__({    \
    long res = FUNC( (IN), (void *)wire_laddr, wire_sz ); \
    if( FD_UNLIKELY( res<0L ) ) return res;               \
    wire_laddr += (ulong)res;                             \
    wire_sz    -= (ulong)res;                             \
    (ulong)res;                                           \
  }))

#endif /* HEADER_src_ballet_tls_fd_tls_serde_h */
