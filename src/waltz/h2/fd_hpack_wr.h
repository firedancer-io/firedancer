#ifndef HEADER_fd_src_waltz_h2_fd_hpack_wr_h
#define HEADER_fd_src_waltz_h2_fd_hpack_wr_h

/* fd_hpack_wr.h provides simple APIs to generate HPACK header entries.
   Generates somewhat wasteful serializations, but is quite simple. */

#include "fd_h2_base.h"
#include "fd_h2_rbuf.h"

#define FD_HPACK_INDEXED_SHORT( val ) ((uchar)( 0x80|(val) ))

#if FD_HAS_X86
#include <immintrin.h>
#endif

FD_PROTOTYPES_BEGIN

static inline ulong
fd_hpack_wr_varint(
    uchar code[9],
    uint  prefix,
    uint  addend,
    ulong number /* in [0,2^56) */
) {
  ulong sz;
  if( number<addend ) {
    code[0] = (uchar)( prefix|number );
    sz = 1UL;
  } else {
    code[0] = (uchar)( prefix|addend );
    ulong tail = number-addend;
#if FD_HAS_X86 && defined(__BMI2__)
    ulong enc = _pdep_u64( tail, 0x7f7f7f7f7f7f7f7fUL );
#else
    ulong enc =
      ( ( tail<<0 )&0x000000000000007fUL ) |
      ( ( tail<<1 )&0x0000000000007f00UL ) |
      ( ( tail<<2 )&0x00000000007f0000UL ) |
      ( ( tail<<3 )&0x000000007f000000UL ) |
      ( ( tail<<4 )&0x0000007f00000000UL ) |
      ( ( tail<<5 )&0x00007f0000000000UL ) |
      ( ( tail<<6 )&0x007f000000000000UL ) |
      ( ( tail<<7 )&0x7f00000000000000UL );
#endif
    int   msb   = fd_ulong_find_msb_w_default( enc, 0 );
    int   shift = 64-(msb&0x38);
    ulong mask  = shift==64 ? 0UL : 0x8080808080808080UL>>shift;
    FD_STORE( ulong, code+1, enc|mask );
    sz = 2 + (ulong)( msb>>3 );
  }
  return sz;
}

static inline int
fd_hpack_wr_private_indexed( fd_h2_rbuf_t * rbuf_tx,
                             ulong          idx ) {
  if( FD_UNLIKELY( !fd_h2_rbuf_free_sz( rbuf_tx ) ) ) return 0;
  uchar code[1] = { FD_HPACK_INDEXED_SHORT( idx ) };
  fd_h2_rbuf_push( rbuf_tx, code, 1 );
  return 1;
}

static inline int
fd_hpack_wr_private_name_indexed_0(
    fd_h2_rbuf_t * rbuf_tx,
    ulong          key,
    ulong          value_len  /* in [0,128) */
) {
  uchar prefix[10] = { (uchar)key };
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < sizeof(prefix)+value_len ) ) return 0;
  ulong prefix_len = 1+fd_hpack_wr_varint( prefix+1, 0x00, 0x7f, value_len );
  fd_h2_rbuf_push( rbuf_tx, prefix, prefix_len );
  return 1;
}

static inline int
fd_hpack_wr_method_post( fd_h2_rbuf_t * rbuf_tx ) {
  return fd_hpack_wr_private_indexed( rbuf_tx, 0x03 );
}

static inline int
fd_hpack_wr_scheme( fd_h2_rbuf_t * rbuf_tx,
                    int            is_https ) {
  if( is_https ) {
    return fd_hpack_wr_private_indexed( rbuf_tx, 0x07 );
  } else {
    return fd_hpack_wr_private_indexed( rbuf_tx, 0x06 );
  }
}

/* fd_hpack_wr_path writes a ':path: ...' header.  path_len must be in
   [0,128). */

static inline int
fd_hpack_wr_path( fd_h2_rbuf_t * rbuf_tx,
                  char const *   path,
                  ulong          path_len ) {
  if( FD_UNLIKELY( !fd_hpack_wr_private_name_indexed_0( rbuf_tx, 0x04, path_len ) ) ) return 0;
  fd_h2_rbuf_push( rbuf_tx, path, path_len );
  return 1;
}

/* fd_hpack_wr_trailers writes the 'te: trailers' header. */

static inline int
fd_hpack_wr_trailers( fd_h2_rbuf_t * rbuf_tx ) {
  static char const code[] =
    "\x00"
    "\x02" "te"
    "\x08" "trailers";
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx )<sizeof(code)-1 ) ) return 0;
  fd_h2_rbuf_push( rbuf_tx, code, sizeof(code)-1 );
  return 1;
}

/* fd_hpack_wr_user_agent writes a 'user-agent' header.
   user_agent_len is in [0,128). */

static inline int
fd_hpack_wr_user_agent( fd_h2_rbuf_t * rbuf_tx,
                        ulong          user_agent_len ) {
  return fd_hpack_wr_private_name_indexed_0( rbuf_tx, 0x7a, user_agent_len );
}

/* fd_hpack_wr_auth_bearer writes an 'authorization: Bearer xxx' header.
   Uses a never-indexed literal to prevent compression attacks. */

static inline int
fd_hpack_wr_auth_bearer( fd_h2_rbuf_t * rbuf_tx,
                         char const *   auth_token,
                         ulong          auth_token_len ) {
  uchar prefix[11] = { 0x1f, 0x08 };
  ulong value_len = 7UL+auth_token_len;
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < sizeof(prefix)+value_len ) ) return 0;
  ulong prefix_len = 2+fd_hpack_wr_varint( prefix+2, 0x00, 0x7f, value_len );
  fd_h2_rbuf_push( rbuf_tx, prefix,     prefix_len     );
  fd_h2_rbuf_push( rbuf_tx, "Bearer ",  7              );
  fd_h2_rbuf_push( rbuf_tx, auth_token, auth_token_len );
  return 1;
}

/* fd_hpack_wr_authority writes an ':authority: host[:port]' header.
   Port is only specified if it is non-zero. */

static inline int
fd_hpack_wr_authority( fd_h2_rbuf_t * rbuf_tx,
                       char const *   host,
                       ulong          host_len,
                       ushort         port ) {
  char suffix_cstr[ 7 ];
  ulong port_cstr_len = fd_ushort_base10_dig_cnt( port );
  char * p = fd_cstr_init( suffix_cstr );
  p = fd_cstr_append_char( p, ':' );
  p = fd_cstr_append_ushort_as_text( p, 0, 0, port, port_cstr_len );
  ulong suffix_len = (ulong)p - (ulong)suffix_cstr;
  fd_cstr_fini( p );

  //if( !port ) suffix_len = 0;
  ulong value_len  = host_len+suffix_len;

  uchar prefix[10] = { (uchar)0x01 };
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < sizeof(prefix)+value_len ) ) return 0;
  ulong prefix_len = 1+fd_hpack_wr_varint( prefix+1, 0x00, 0x7f, value_len );
  fd_h2_rbuf_push( rbuf_tx, prefix,      prefix_len );
  fd_h2_rbuf_push( rbuf_tx, host,        host_len   );
  fd_h2_rbuf_push( rbuf_tx, suffix_cstr, suffix_len );
  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_wr_h */
