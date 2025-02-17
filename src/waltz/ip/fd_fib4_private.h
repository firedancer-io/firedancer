#ifndef HEADER_fd_src_waltz_route_fd_fib4_private_h
#define HEADER_fd_src_waltz_route_fd_fib4_private_h

#include "fd_fib4.h"

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4_key {
  /* FIXME optimize this to 8 bytes? */
  uint addr; /* prefix bits, little endian (low bits outside of mask are undefined) */
  uint mask; /* bit pattern */
  uint prio; /* lower is higher */
};

typedef struct fd_fib4_key fd_fib4_key_t;

struct __attribute__((aligned(FD_FIB4_ALIGN))) fd_fib4 {
  ulong generation;
  ulong cnt;
  ulong max;
  ulong hop_off;
  /* fd_fib4_key_t[] follows */
  /* fd_fib4_hop_t[] follows */
};

FD_FN_CONST ulong
fd_fib4_key_tbl_laddr( fd_fib4_t const * fib ) {
  return (ulong)fib + sizeof(fd_fib4_t);
}

FD_FN_PURE ulong
fd_fib4_hop_tbl_laddr( fd_fib4_t const * fib ) {
  return (ulong)fib + fib->hop_off;
}

FD_FN_CONST static inline fd_fib4_key_t const * fd_fib4_key_tbl_const( fd_fib4_t const * fib ) { return (fd_fib4_key_t const *)fd_fib4_key_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_key_t *       fd_fib4_key_tbl      ( fd_fib4_t *       fib ) { return (fd_fib4_key_t *)      fd_fib4_key_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_hop_t const * fd_fib4_hop_tbl_const( fd_fib4_t const * fib ) { return (fd_fib4_hop_t const *)fd_fib4_hop_tbl_laddr( fib ); }
FD_FN_CONST static inline fd_fib4_hop_t *       fd_fib4_hop_tbl      ( fd_fib4_t *       fib ) { return (fd_fib4_hop_t *)      fd_fib4_hop_tbl_laddr( fib ); }

#endif /* HEADER_fd_src_waltz_route_fd_fib4_private_h */
