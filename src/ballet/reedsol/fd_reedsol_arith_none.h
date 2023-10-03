#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_none_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_none_h

#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_private_h
#error "Do not include this file directly; use fd_reedsol_private.h"
#endif

typedef ulong gf_t; /* One byte stored in a ulong */

#define GF_WIDTH 1UL
#define W_ATTR

FD_PROTOTYPES_BEGIN

static inline gf_t gf_ldu( uchar const * addr ) { return (ulong)(*addr); }
static inline void gf_stu( uchar * addr, gf_t v ) { *addr = (uchar)v; }

#define gf_zero() (0UL)

#define GF_ADD( a, b ) ((a)^(b))

#define GF_OR(  a, b ) ((a)|(b))

/* Exposing log_tbl at compile time would let the compiler remove a
   branch, but we don't care too much about performance in this case. */

#define GF_MUL( a, c ) (__extension__({                                                                                 \
    ulong _a = (a);                                                                                                     \
    int   _c = (c);                                                                                                     \
    /* c is known at compile time, so this is not a runtime branch. */                                                  \
    ((_c==0) ? 0UL : ( (_c==1) ? _a : (ulong)gf_arith_invlog_tbl[ gf_arith_log_tbl[ _a ] + gf_arith_log_tbl[ _c ] ] )); \
  }))

#define GF_MUL_VAR( a, c ) ((ulong)gf_arith_invlog_tbl[ gf_arith_log_tbl[ (a) ] + gf_arith_log_tbl[ (c) ] ] )

#define GF_ANY( x ) (!!(x))

extern uchar const fd_reedsol_arith_consts_generic_mul[]  __attribute__((aligned(128)));

FD_FN_UNUSED static short const * gf_arith_log_tbl    = (short const *)fd_reedsol_arith_consts_generic_mul; /* Indexed [0,256) */
FD_FN_UNUSED static uchar const * gf_arith_invlog_tbl =
  fd_reedsol_arith_consts_generic_mul + 256UL*sizeof(short) + 512UL*sizeof(uchar); /* Indexed [-512,512) */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_none_h */
