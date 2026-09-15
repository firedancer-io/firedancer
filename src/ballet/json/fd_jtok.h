#ifndef HEADER_fd_src_ballet_json_fd_jtok_h
#define HEADER_fd_src_ballet_json_fd_jtok_h

/* fd_jtok is a JSON tokenizer.

   Example:

     fd_jtok_t j[1];
     fd_jtok_init( j, buf, buf_sz );
     fd_jtok_str_t key;
     fd_jtok_obj_enter( j );
     while( fd_jtok_obj_next( j, &key ) ) {
       if(      fd_jtok_str_eq( &key, "commitment"     ) ) fd_jtok_cstr ( j, cfg->commitment, sizeof(cfg->commitment) );
       else if( fd_jtok_str_eq( &key, "minContextSlot" ) ) fd_jtok_ulong( j, &cfg->min_ctx_slot );
     }
     if( fd_jtok_fini( j ) ) reject( fd_jtok_err_off( j ) );

   Errors are sticky.  After the first error every call returns 0.

   obj_next / arr_next leave the cursor on the member's value.  If the
   caller does not read it, the next obj_next / arr_next / fini skips
   it.

   To read a value whose meaning depends on a later sibling (JSON-RPC
   "params" before "method"), capture it with fd_jtok_raw and tokenize
   the slice with a second cursor after the loop.

   Input must be RFC 8259 JSON.  Strings must be valid UTF-8 with no
   raw control characters.  Bytes after the top-level value are an
   error.  If a key repeats, the last one wins. */

#include "../fd_ballet_base.h"

/* FD_JTOK_ERR_* give error codes */

#define FD_JTOK_ERR_SYNTAX (1) /* malformed JSON */
#define FD_JTOK_ERR_TYPE   (2) /* value has the wrong kind */
#define FD_JTOK_ERR_RANGE  (3) /* number or string does not fit */
#define FD_JTOK_ERR_DEPTH  (4) /* skipped value nests deeper than FD_JTOK_SKIP_DEPTH_MAX */
#define FD_JTOK_ERR_TRAIL  (5) /* bytes after the top-level value */
#define FD_JTOK_ERR_USAGE  (6) /* getter with no pending value, or fini inside a container */

/* FD_JTOK_* give value kinds (fd_jtok_peek) */

#define FD_JTOK_OBJ  (1) /* { ... } */
#define FD_JTOK_ARR  (2) /* [ ... ] */
#define FD_JTOK_STR  (3) /* " ... " */
#define FD_JTOK_INT  (4) /* number without fraction or exponent */
#define FD_JTOK_NUM  (5) /* any other number */
#define FD_JTOK_BOOL (6) /* false/true */
#define FD_JTOK_NULL (7) /* null */

/* FD_JTOK_SKIP_DEPTH_MAX is the max nesting of a value consumed by
   skip, raw, or auto-skip. */

#define FD_JTOK_SKIP_DEPTH_MAX (64UL)

/* FD_JTOK_NUM_SZ_MAX is the max length of a number literal accepted by
   fd_jtok_double. */

#define FD_JTOK_NUM_SZ_MAX (64UL)

/* fd_jtok_str_t spans encoded string bytes from the input buffer. */

struct fd_jtok_str {
  char const * ptr;
  ulong        sz;
};

typedef struct fd_jtok_str fd_jtok_str_t;

/* fd_jtok_t is the parser cursor. */

struct fd_jtok {
  char const * beg;
  char const * cur;
  char const * end;
  int          err;
  int          pending;
  int          first;
  ulong        depth;
};

typedef struct fd_jtok fd_jtok_t;

FD_PROTOTYPES_BEGIN

/* fd_jtok_init starts tokenizing the sz bytes at buf.  buf must
   outlive any fd_jtok_str_t taken from it.  Returns j with the
   top-level value pending.  An empty input (sz 0, buf may then be
   NULL) is not valid JSON and starts out with FD_JTOK_ERR_SYNTAX. */

fd_jtok_t *
fd_jtok_init( fd_jtok_t *  j,
              void const * buf,
              ulong        sz );

/* fd_jtok_fini skips the top-level value if still pending and checks
   that only whitespace remains.  Returns the error code, 0 on
   success.  Call it at top level, after the last obj_next / arr_next
   returned 0. */

int
fd_jtok_fini( fd_jtok_t * j );

FD_FN_PURE static inline int
fd_jtok_err( fd_jtok_t const * j ) {
  return j->err;
}

/* fd_jtok_err_off returns the input offset at which the error was
   detected. */

FD_FN_PURE static inline ulong
fd_jtok_err_off( fd_jtok_t const * j ) {
  return (ulong)( j->cur - j->beg );
}

/* fd_jtok_peek returns the FD_JTOK_* kind of the pending value, 0 on
   error.  The value stays pending. */

int
fd_jtok_peek( fd_jtok_t * j );

/* fd_jtok_obj_enter consumes the opening brace of the pending object.
   FD_JTOK_ERR_TYPE if it is not an object. */

void
fd_jtok_obj_enter( fd_jtok_t * j );

/* fd_jtok_obj_next advances to the next member of the innermost
   object, skipping the previous value if it was not read.  Returns 1
   with *key set and the value pending, or 0 after the closing brace
   (or on error). */

int
fd_jtok_obj_next( fd_jtok_t *     j,
                  fd_jtok_str_t * key );

/* Array equivalents of obj_enter / obj_next. */

void
fd_jtok_arr_enter( fd_jtok_t * j );

int
fd_jtok_arr_next( fd_jtok_t * j );

/* Scalar getters consume the pending value into *out.  Wrong kind is
   FD_JTOK_ERR_TYPE, out of range is FD_JTOK_ERR_RANGE.  *out is
   written on success only.  ulong and long require an INT.  double
   accepts INT or NUM up to FD_JTOK_NUM_SZ_MAX chars and fails with
   FD_JTOK_ERR_RANGE if the literal overflows or underflows a finite
   double (e.g. 1e999, 1e-999).  bool stores 0 or 1. */

void fd_jtok_ulong ( fd_jtok_t * j, ulong  * out );
void fd_jtok_long  ( fd_jtok_t * j, long   * out );
void fd_jtok_double( fd_jtok_t * j, double * out );
void fd_jtok_bool  ( fd_jtok_t * j, int    * out );
void fd_jtok_null  ( fd_jtok_t * j );

/* fd_jtok_cstr consumes the pending string, decodes escapes to UTF-8
   and writes it NUL-terminated to the out_sz bytes at out.
   FD_JTOK_ERR_RANGE if it does not fit or contains an escaped NUL.
   On failure out[0] is '\0' (if out_sz>0). */

void
fd_jtok_cstr( fd_jtok_t * j,
              char *      out,
              ulong       out_sz );

/* fd_jtok_str consumes the pending string as a zero-copy view. */

void
fd_jtok_str( fd_jtok_t *     j,
             fd_jtok_str_t * out );

/* fd_jtok_skip consumes the pending value. */

void
fd_jtok_skip( fd_jtok_t * j );

/* fd_jtok_raw consumes the pending value and returns the input bytes
   from its first to its last character. */

void
fd_jtok_raw( fd_jtok_t *   j,
             char const ** ptr,
             ulong *       sz );

/* fd_jtok_str_decode decodes the escapes in s to UTF-8 and writes the
   result NUL-terminated to the out_sz bytes at out.  Returns the
   decoded length excluding the terminator, or -1 if it does not fit or
   s contains an escaped NUL (out[0] is then '\0' if out_sz>0). */

long
fd_jtok_str_decode( fd_jtok_str_t const * s,
                    char *                out,
                    ulong                 out_sz );

/* fd_jtok_str_eq returns 1 if s decodes to exactly lit.  Escapes in s
   are decoded before comparing. */

FD_FN_PURE int
fd_jtok_str_eq( fd_jtok_str_t const * s,
                char const *          lit );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_json_fd_jtok_h */
