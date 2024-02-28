#ifndef HEADER_fd_src_disco_tiles_sign_fd_sign_tile_h
#define HEADER_fd_src_disco_tiles_sign_fd_sign_tile_h

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#include "../../keyguard/fd_keyguard.h"

#define FD_SIGN_TILE_ALIGN (128UL)

#define FD_SIGN_TILE_MAX_IN (32UL)

struct fd_sign_tile_args {
  char const * identity_key_path;
};

typedef struct fd_sign_tile_args fd_sign_tile_args_t;

struct fd_sign_tile_topo {
  ulong       link_cnt;

  ulong       link_in_kind[ FD_SIGN_TILE_MAX_IN ];
  fd_wksp_t * link_in_wksp[ FD_SIGN_TILE_MAX_IN ];
  void *      link_in_dcache[ FD_SIGN_TILE_MAX_IN ];
  ulong       link_in_mtu[ FD_SIGN_TILE_MAX_IN ];

  fd_frag_meta_t * link_out_mcache[ FD_SIGN_TILE_MAX_IN ];
  void *           link_out_dcache[ FD_SIGN_TILE_MAX_IN ];
  ulong            link_out_mtu[ FD_SIGN_TILE_MAX_IN ];
};

typedef struct fd_sign_tile_topo fd_sign_tile_topo_t;

struct fd_sign_tile_out {
  ulong            seq;
  fd_frag_meta_t * mcache;
  uchar *          data;
};

typedef struct fd_sign_tile_out fd_sign_tile_out_t;

struct __attribute__((aligned(FD_SIGN_TILE_ALIGN))) fd_sign_tile_private {
  uchar              _data[ FD_KEYGUARD_SIGN_REQ_MTU ];

  ulong              in_kind[ FD_SIGN_TILE_MAX_IN ];
  uchar *            in_data[ FD_SIGN_TILE_MAX_IN ];

  fd_sign_tile_out_t out[ FD_SIGN_TILE_MAX_IN ];

  fd_sha512_t        sha512 [ 1 ];

  uchar const *      public_key;
  uchar const *      private_key;
};

typedef struct fd_sign_tile_private fd_sign_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sign_tile_align( void );

FD_FN_PURE ulong
fd_sign_tile_footprint( fd_sign_tile_args_t const * args );

ulong
fd_sign_tile_seccomp_policy( void *               shsign,
                             struct sock_filter * out,
                             ulong                out_cnt );

ulong
fd_sign_tile_allowed_fds( void * shsign,
                          int *  out,
                          ulong  out_cnt );

void
fd_sign_tile_join_privileged( void *                      shsign,
                              fd_sign_tile_args_t const * args );

fd_sign_tile_t *
fd_sign_tile_join( void *                      shsign,
                   fd_sign_tile_args_t const * args,
                   fd_sign_tile_topo_t const * topo );

void
fd_sign_tile_run( fd_sign_tile_t *        sign,
                  fd_cnc_t *              cnc,
                  ulong                   in_cnt,
                  fd_frag_meta_t const ** in_mcache,
                  ulong **                in_fseq,
                  fd_frag_meta_t *        mcache,
                  ulong                   out_cnt,
                  ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_sign_fd_sign_tile_h */
