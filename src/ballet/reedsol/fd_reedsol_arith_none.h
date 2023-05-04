#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_none_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_none_h
#include "../../util/fd_util_base.h"

#define FD_REEDSOL_GF_ARITH_DEFINED 1

typedef ulong gf_t; /* One byte stored in a ulong */
#define GF_WIDTH 1UL
#define W_ATTR

static inline gf_t gf_ldu( uchar const * addr ) { return (ulong)(*addr); }
static inline void gf_stu( uchar * addr, gf_t v ) { *addr = (uchar)v; }
#define gf_zero() (0UL)

#ifdef INCLUDE_CONSTANTS
FD_IMPORT_BINARY( fd_reedsol_arith_consts_generic_mul, "src/ballet/reedsol/constants/generic_constants.bin" );
#undef INCLUDE_CONSTANTS
#else
extern uchar const fd_reedsol_arith_consts_generic_mul[]  __attribute__((aligned(128)));
#endif
static FD_FN_UNUSED short const * gf_arith_log_tbl     = (short const *)fd_reedsol_arith_consts_generic_mul; /* Indexed [0, 256) */
static FD_FN_UNUSED uchar const * gf_arith_invlog_tbl  = fd_reedsol_arith_consts_generic_mul + 256UL*sizeof(short) + 512UL*sizeof(uchar); /* Indexed [-512, 512) */

#define GF_ADD( a, b ) ((a)^(b))
#define GF_OR(  a, b ) ((a)|(b))

/* c is known at compile time, so this is not a runtime branch.
   Exposing log_tbl at compile time would let the compiler remove a
   branch, but we don't care too much about performance in this case. */
#define GF_MUL( a, c ) ((c==0) ? 0UL : ( (c==1) ? (a) : (ulong)gf_arith_invlog_tbl[ gf_arith_log_tbl[ a ] + gf_arith_log_tbl[ c ] ] ))

#define GF_MUL_VAR( a, c ) ((ulong)gf_arith_invlog_tbl[ gf_arith_log_tbl[ a ] + gf_arith_log_tbl[ c ] ] )

#define GF_ANY( x ) (!!(x))


#endif /*HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_none_h */
