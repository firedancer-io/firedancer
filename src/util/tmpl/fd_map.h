#ifndef HEADER_fd_src_util_tmpl_fd_map_h
#define HEADER_fd_src_util_tmpl_fd_map_h

#include "../fd_util_base.h"

/* Common map error codes (FIXME: probably should get around to making
   unified error codes, error strings and/or flags across util at least
   so we don't have to do this in the generator itself) */

#define FD_MAP_SUCCESS     (0)
#define FD_MAP_ERR_INVAL   (-1)
#define FD_MAP_ERR_AGAIN   (-2)
#define FD_MAP_ERR_CORRUPT (-3)
//#define FD_MAP_ERR_EMPTY   (-4)
#define FD_MAP_ERR_FULL    (-5)
#define FD_MAP_ERR_KEY     (-6)

/* common map flags */

#define FD_MAP_FLAG_BLOCKING      (1<<0)

/* map_slot_para flags */

//#define FD_MAP_FLAG_BLOCKING      (1<<0)
#define FD_MAP_FLAG_USE_HINT      (1<<2)
#define FD_MAP_FLAG_PREFETCH_NONE (0<<3)
#define FD_MAP_FLAG_PREFETCH_META (1<<3)
#define FD_MAP_FLAG_PREFETCH_DATA (2<<3)
#define FD_MAP_FLAG_PREFETCH      (3<<3)
#define FD_MAP_FLAG_RDONLY        (1<<5)

/* map_chain_para flags */

//#define FD_MAP_FLAG_BLOCKING      (1)
#define FD_MAP_FLAG_ADAPTIVE      (2)

struct fd_map_chain_iter {
  ulong chain_rem;
  ulong ele_idx;
};

FD_PROTOTYPES_BEGIN

FD_FN_CONST char const *
fd_map_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_tmpl_fd_map_h */
