#ifndef HEADER_fd_src_ballet_toml_fd_toml_h
#define HEADER_fd_src_ballet_toml_fd_toml_h

/* fd_toml.h provides APIs for parsing TOML config files.

   Grammar: https://github.com/toml-lang/toml/blob/1.0.0/toml.abnf */

#include "../../util/pod/fd_pod.h"

/* Error codes */

#define FD_TOML_SUCCESS     ( 0)  /* ok */
#define FD_TOML_ERR_POD     (-1)  /* ran out of output space */
#define FD_TOML_ERR_SCRATCH (-2)  /* ran out of scratch space */
#define FD_TOML_ERR_KEY     (-3)  /* oversz key */
#define FD_TOML_ERR_DUP     (-4)  /* duplicate key */
#define FD_TOML_ERR_RANGE   (-5)  /* overflow */
#define FD_TOML_ERR_PARSE   (-6)  /* parse fail */

/* FD_TOML_PATH_MAX is the max supported pod path length. */

#define FD_TOML_PATH_MAX (512UL)

/* fd_toml_err_info_t contains information about a TOML parse failure.  */

struct fd_toml_err_info {
  ulong line; /* 1-indexed line number */
  /* ... add more info here ... */
};

typedef struct fd_toml_err_info fd_toml_err_info_t;

FD_PROTOTYPES_BEGIN

/* fd_toml_parse deserializes a TOML document and inserts the document's
   object tree into an fd_pod.  toml points to the first byte of the
   TOML.  toml_sz is the byte length of the TOML.  If toml_sz==0 then
   the toml pointer is ignored (may be invalid).  pod is a local join to
   an fd_pod_t.  [scratch,scratch+scratch_sz) is arbitrary unaligned
   scratch memory used during deserialization.  scratch_sz>=4kB
   recommended.  If scratch_sz is too small, may fail to deserialize
   long strings and sub tables.  On success, returns FD_TOML_SUCCESS.
   On parse failure returns FD_TOML_ERR_*.  If opt_err!=NULL,
   initializes *opt_err with error information (even if the return code
   was success).

   Note that toml is not interpreted as a cstr -- No terminating zero is
   fine and so are stray zeros in the middle of the file.

   fd_toml_parse is not hardened against untrusted input. fd_toml_parse
   is not optimized for performance.

   Mapping:

    TOML type      | Example     | fd_pod type
    ---------------|-------------|--------------------------------------
     table         | [key]       | subpod
     array table   | [[key]]     | subpod (keys %d formatted cstrs)
     inline table  | x={a=1,b=2} | subpod
     inline array  | x=[1,2]     | subpod (keys %d formatted cstrs)
     bool          | true        | int
     integer       | -3          | long
     float         | 3e-3        | float
     string        | 'hello'     | cstr
     datetime      | 2022-08-16  | ulong (ns since unix epoch)

   Despite the name, TOML is neither "obvious" nor "minimal".  fd_toml
   thus only supports a subset of the 'spec' and ignores some horrors.
   Known errata:

   - fd_toml allows duplicate tables and arrays whereas TOML has various
     complicated rules that forbid such.  For example, the following
     is not allowed in toml:

       fruit = []
       [[fruit]]  # inline arrays are immutable

   - fd_toml allows mixing tables and arrays which is forbidden in TOML

       a = [1]
       a.b = 1

   - Missing validation for out-of-bounds Unicode escapes

   - Missing support for CRLF

   - Missing support for subtables of array tables.
     The following gets deserialized as {a={b={c={d="val0"}}}} instead
     of {a=[{b=[{c={d="val0"}}]}]}

       [[a]]
         [[a.b]]
           [a.b.c]
             d = "val0"

   - Missing support for dot-escapes.
     The tables ["a.b"] and [a.b] are the same in fd_toml.

   - Keys with embedded NUL characters are truncated whereas they are
     legal in TOML.

   - Infinite and NaN floats are rejected. */

int
fd_toml_parse( void const *         toml,
               ulong                toml_sz,
               uchar *              pod,
               uchar *              scratch,
               ulong                scratch_sz,
               fd_toml_err_info_t * opt_err );

/* fd_toml_strerror returns a human-readable error string with static
   storage describing the given FD_TOML_ERR_* code.  Works for negative
   return values in fd_toml_parse. */

FD_FN_CONST char const *
fd_toml_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_toml_fd_toml_h */
