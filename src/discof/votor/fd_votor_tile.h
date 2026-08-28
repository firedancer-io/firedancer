#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

#include "fd_votor_rooted.h"
#include "../../disco/topo/fd_topo.h"

#define FD_VOTOR_SIG_FINAL          (0)
#define FD_VOTOR_SIG_FAST_FINAL     (1)
#define FD_VOTOR_SIG_NOTAR          (2)
#define FD_VOTOR_SIG_NOTAR_FALLBACK (3)
#define FD_VOTOR_SIG_SKIP           (4)
// #define FD_VOTOR_SIG_ROOTED      (5)  /* defined in fd_votor_rooted.h */
#define FD_VOTOR_SIG_REPAIR         (6)
#define FD_VOTOR_SIG_LEADER         (7)

typedef fd_votor_rooted_t fd_votor_repair_t;

struct fd_votor_notar {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_notar fd_votor_notar_t;

struct fd_votor_notar_fallback {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_notar_fallback fd_votor_notar_fallback_t;

struct fd_votor_skip {
  ulong slot;
};
typedef struct fd_votor_skip fd_votor_skip_t;

struct fd_votor_final {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_final fd_votor_final_t;

struct fd_votor_fast_final {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_fast_final fd_votor_fast_final_t;

struct fd_votor_leader {
  ulong     start_slot;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
};
typedef struct fd_votor_leader fd_votor_leader_t;

union fd_votor_msg {
  fd_votor_final_t          final;
  fd_votor_fast_final_t     fast_final;
  fd_votor_notar_t          notar;
  fd_votor_notar_fallback_t notar_fallback;
  fd_votor_skip_t           skip;
  fd_votor_rooted_t         rooted;
  fd_votor_repair_t         repair;
  fd_votor_leader_t         leader;
};
typedef union fd_votor_msg fd_votor_msg_t;

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
