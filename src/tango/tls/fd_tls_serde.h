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
   constant-propagated if sz is constant.

   - IDX is an arbitrary identifier for the current field within the
     decode context.
   - FIELD is ignored.
   - FIELD_SZ is an expression specifying the byte size of the field. */

#define FD_TLS_DECODE_PREPARE( IDX, FIELD, FIELD_SZ )  \
  void const * _field_##IDX      = (void const *)wire; \
  ulong const  _field_##IDX##_sz = (FIELD_SZ);         \
  valid &= (wire_sz >=  _field_##IDX##_sz);            \
            wire_sz -=  _field_##IDX##_sz;             \
            wire     = (void const *)( (ulong)wire + _field_##IDX##_sz );

/* FD_TLS_DECODE_CHECK performs tbe bounds checks queued by prior
   FD_TLS_DECODE_PREPARE ops. */

#define FD_TLS_DECODE_CHECK \
  if( FD_UNLIKELY( !valid ) ) return -(long)FD_TLS_ALERT_DECODE_ERROR;

/* FD_TLS_DECODE_COMMIT generates a non-overlapping memory copy for the
   given field.  Field should be bounds checked at this point.

   - IDX is an arbitrary identifier for the current field within the
     decode context.
   - FIELD is an lvalue pointing to the memory that will contain the
     field after decode finishes.
   - FIELD_SZ is ignored. */

#define FD_TLS_DECODE_COMMIT( IDX, FIELD, FIELD_SZ ) \
  memcpy( (FIELD), _field_##IDX, _field_ ##IDX##_sz );

/* FD_TLS_DECODE_STATIC_BATCH is a convenience macro for decoding a
   batch of static sized fields in a new decode context. */

#define FD_TLS_DECODE_STATIC_BATCH( fields ) \
  FD_TLS_DECODE_BEGIN                        \
  fields( FD_TLS_DECODE_PREPARE )            \
  FD_TLS_DECODE_CHECK                        \
  fields( FD_TLS_DECODE_COMMIT )             \
  FD_TLS_DECODE_END

#endif /* HEADER_src_ballet_tls_fd_tls_serde_h */
