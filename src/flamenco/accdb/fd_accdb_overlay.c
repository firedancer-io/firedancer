#include "fd_accdb_overlay.h"

struct acc_map {
  fd_pubkey_t key;
  uint        hash;
};

typedef struct acc_map acc_map_t;

static ulong acc_map_seed;

#define MAP_NAME              acc_map
#define MAP_KEY_T             fd_pubkey_t
#define MAP_T                 acc_map_t
#define MAP_LG_SLOT_CNT       FD_ACCDB_OVERLAY_LG_SLOT_MAX
#define MAP_KEY_NULL          (fd_pubkey_t){0}
#define MAP_KEY_INVAL(k)      fd_pubkey_check_zero( &(k) )
#define MAP_KEY_EQUAL(a,b)    fd_pubkey_eq( &(a), &(b) )
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k)       (uint)fd_funk_rec_key_hash1( (k).uc, acc_map_seed )
#include "../../util/tmpl/fd_map.c"

fd_accdb_overlay_t *
fd_accdb_overlay_init( fd_accdb_overlay_t * overlay,
                       fd_accdb_user_t *    src,
                       fd_acc_pool_t *      acc_pool ) {
  FD_LOG_CRIT(( "TODO" ));
}

void *
fd_accdb_overlay_fini( fd_accdb_overlay_t * overlay ) {
  FD_LOG_CRIT(( "TODO" ));
}

fd_accdb_user_t *
fd_accdb_overlay_user( fd_accdb_overlay_t * overlay ) {
  FD_LOG_CRIT(( "TODO" ));
}

fd_accdb_user_vt_t const fd_accdb_overlay_vt = {
  "TODO"
};

void
fd_accdb_overlay_commit( fd_accdb_overlay_t * overlay ) {
  FD_LOG_CRIT(( "TODO" ));
}
