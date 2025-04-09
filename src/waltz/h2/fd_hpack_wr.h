#ifndef HEADER_fd_src_waltz_h2_fd_hpack_wr_h
#define HEADER_fd_src_waltz_h2_fd_hpack_wr_h

/* fd_hpack_wr.h provides simple APIs to generate HPACK header entries.
   Generates somewhat wasteful serializations, but is quite simple. */

#include "fd_h2_base.h"
#include "fd_h2_rbuf.h"

#define FD_HPACK_INDEXED_SHORT( val ) ((uchar)( 0x80|(val) ))

FD_PROTOTYPES_BEGIN

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
    void const *   value,
    ulong          value_len  /* in [0,128) */
) {
  uchar const prefix[2] = { (uchar)key, (uchar)value_len };
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < sizeof(prefix)+value_len ) ) return 0;
  fd_h2_rbuf_push( rbuf_tx, prefix, sizeof(prefix) );
  fd_h2_rbuf_push( rbuf_tx, value,  value_len      );
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
  return fd_hpack_wr_private_name_indexed_0( rbuf_tx, 0x04, path, path_len );
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
                        char const *   user_agent,
                        ulong          user_agent_len ) {
  return fd_hpack_wr_private_name_indexed_0( rbuf_tx, 0x7a, user_agent, user_agent_len );
}

/* fd_hpack_wr_auth_bearer writes an 'authorization: Bearer xxx' header.
   Uses a never-indexed literal to prevent compression attacks. */

static inline int
fd_hpack_wr_auth_bearer( fd_h2_rbuf_t * rbuf_tx,
                         char const *   auth_token,
                         ulong          auth_token_len ) {
  uchar const prefix[3] = { 0x1f, 0x08, (uchar)( 7+auth_token_len ) };
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx ) < sizeof(prefix)+7+auth_token_len ) ) return 0;
  fd_h2_rbuf_push( rbuf_tx, prefix,     sizeof(prefix) );
  fd_h2_rbuf_push( rbuf_tx, "Bearer ",  7              );
  fd_h2_rbuf_push( rbuf_tx, auth_token, auth_token_len );
  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_wr_h */
