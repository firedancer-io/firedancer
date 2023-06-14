#ifndef HEADER_src_ballet_tls_fd_tls_serde_h
#define HEADER_src_ballet_tls_fd_tls_serde_h

/* fd_tls_serde.h provides branch-minimizing (de-)serializer macros for
   internal use. */

/* FD_TLS_DECODE_{BEGIN,END} create and terminate a decode context.
   Internally, creates a new do/while(0) scope. */

#define FD_TLS_DECODE_BEGIN do { \
  int valid = 1;                 \

#define FD_TLS_DECODE_END } while(0);

/* FD_TLS_DECODE_PREPARE defines a local variable pointing to the would-
   be position of the field to be decoded, which may be out-of-bounds.
   Also extends the "valid" expression to include a bounds check for
   this field.  Both the "valid" expression and this local can be fully
   constant-propagated if sz is constant. */

#define FD_TLS_DECODE_PREPARE( IDX, FIELD, FIELD_TYPE, FIELD_CNT )         \
  void const * _field_##IDX       = (void const *)wire;                    \
  ulong const  _field_##IDX##_cnt = (FIELD_CNT);                           \
  ulong const  _field_##IDX##_sz  = sizeof(FIELD_TYPE)*_field_##IDX##_cnt; \
  valid &= (wire_sz >=  _field_##IDX##_sz);            \
            wire_sz -=  _field_##IDX##_sz;             \
            wire     = (void const *)( (ulong)wire + _field_##IDX##_sz );

/* FD_TLS_DECODE_CHECK performs tbe bounds checks queued by prior
   FD_TLS_DECODE_PREPARE ops. */

#define FD_TLS_DECODE_CHECK \
  if( FD_UNLIKELY( !valid ) ) return -(long)FD_TLS_ALERT_DECODE_ERROR;

/* FD_TLS_DECODE_COMMIT generates a non-overlapping memory copy for the
   given field.  Field should be bounds checked at this point. */

#define FD_TLS_DECODE_COMMIT( IDX, FIELD, FIELD_TYPE, FIELD_CNT ) \
  do {                                                            \
    memcpy( (FIELD), _field_##IDX, _field_##IDX##_sz );           \
    FIELD_TYPE * _field_##IDX##_ptr = (FIELD);                    \
    for( ulong i=0; i < (FIELD_CNT); i++ ) {                      \
      *((_field_##IDX##_ptr)++) =                                 \
        (FIELD_TYPE)fd_##FIELD_TYPE##_bswap( (FIELD)[i] );        \
    }                                                             \
  } while(0);

/* FD_TLS_DECODE_FIELD is a convenience macro for decoding a single
   field with known size. */

#define FD_TLS_DECODE_FIELD( FIELD, FIELD_TYPE )   \
  FD_TLS_DECODE_BEGIN                              \
  FD_TLS_DECODE_PREPARE( _, FIELD, FIELD_TYPE, 1 ) \
  FD_TLS_DECODE_CHECK                              \
  FD_TLS_DECODE_COMMIT(  _, FIELD, FIELD_TYPE, 1 ) \
  FD_TLS_DECODE_END

/* FD_TLS_DECODE_STATIC_BATCH is a convenience macro for decoding a
   batch of static sized fields in a new decode context. */

#define FD_TLS_DECODE_STATIC_BATCH( fields ) \
  FD_TLS_DECODE_BEGIN                        \
  fields( FD_TLS_DECODE_PREPARE )            \
  FD_TLS_DECODE_CHECK                        \
  fields( FD_TLS_DECODE_COMMIT )             \
  FD_TLS_DECODE_END

#endif /* HEADER_src_ballet_tls_fd_tls_serde_h */
