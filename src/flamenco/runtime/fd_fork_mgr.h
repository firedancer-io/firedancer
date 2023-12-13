#ifndef HEADER_fd_src_flamenco_runtime_fd_fork_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_fork_mgr_h

#include "../../util/valloc/fd_valloc.h"

#include "../types/fd_types.h"

#include "context/fd_exec_slot_ctx.h"
#include "info/fd_block_info.h"

/* Fork status constants */
#define FD_FORK_STATUS_UNKNOWN    (0)
#define FD_FORK_STATUS_COMPLETE   (1)
#define FD_FORK_STATUS_INPROGRESS (2)

typedef int fd_fork_status_t;

struct __attribute__((aligned(8UL))) fd_active_block {
  fd_pubkey_t key;
  fd_pubkey_t parent_key;
  fd_fork_status_t status;

  // TODO: make microblock_infos a linked list or something
  fd_microblock_info_t const * microblock_infos[1024];
  ulong microblock_infos_cnt;
  
  fd_exec_slot_ctx_t slot_ctx[1];

  // TODO: make this a linked list or something
  fd_pubkey_t child_keys[16];
  ulong child_keys_cnt;
};
typedef struct fd_active_block fd_active_block_t;

struct __attribute__((aligned(16UL))) fd_active_block_t_mapnode {
  fd_active_block_t elem;
  ulong redblack_parent;
  ulong redblack_left;
  ulong redblack_right;
  int redblack_color;
};
typedef struct fd_active_block_t_mapnode fd_active_block_t_mapnode_t;

#define REDBLK_T fd_active_block_t_mapnode_t
#define REDBLK_NAME fd_active_block_t_map
#define REDBLK_IMPL_STYLE 1
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME

struct fd_fork_mgr {
  fd_funk_t * funk;
  fd_pubkey_t root_key;

  fd_active_block_t_mapnode_t * active_block_pool;
  fd_active_block_t_mapnode_t * active_block_root;

  fd_valloc_t valloc;
  fd_rng_t rng[1];
};
typedef struct fd_fork_mgr fd_fork_mgr_t;

int
fd_fork_mgr_init( fd_fork_mgr_t * fork_mgr );

int
fd_fork_mgr_add_new_block( fd_fork_mgr_t * fork_mgr,
                           fd_block_info_t const * block_info );

int
fd_fork_mgr_add_new_microblock_batch( fd_fork_mgr_t * fork_mgr,
                                      fd_microblock_batch_info_t const * mircoblock_batch_info );

int
fd_fork_mgr_add_new_microblock( fd_fork_mgr_t * fork_mgr,
                                fd_microblock_info_t const * mircoblock_info );

int
fd_fork_mgr_set_root_block( void );

int
fd_fork_mgr_get_heads( fd_fork_mgr_t const * fork_mgr,
                       fd_pubkey_t * out_heads,
                       ulong out_heads_capacity,
                       ulong * out_heads_sz );

int
fd_fork_mgr_get_dead_forks( void );

int
fd_fork_mgr_mark_block_completed( fd_fork_mgr_t * fork_mgr,
                                  fd_hash_t const * block_hash );

#endif /* HEADER_fd_src_flamenco_runtime_fd_fork_mgr_h */
