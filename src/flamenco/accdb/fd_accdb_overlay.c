#include "fd_accdb_overlay.h"

static ulong acc_map_seed;
__attribute__((constructor)) static void
acc_map_seed_init( void ) {
  acc_map_seed = fd_ulong_hash( (ulong)fd_tickcount() );
}

#define MAP_NAME              acc_map
#define MAP_KEY_T             fd_pubkey_t
#define MAP_T                 fd_accdb_overlay_rec_t
#define MAP_LG_SLOT_CNT       FD_ACCDB_OVERLAY_LG_SLOT_MAX
#define MAP_KEY_NULL          (fd_pubkey_t){0}
#define MAP_KEY_INVAL(k)      fd_pubkey_check_zero( &(k) )
#define MAP_KEY_EQUAL(a,b)    fd_pubkey_eq( &(a), &(b) )
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(k)       (uint)fd_funk_rec_key_hash1( (k).uc, acc_map_seed )
#include "../../util/tmpl/fd_map.c"

fd_accdb_overlay_t *
fd_accdb_overlay_init( fd_accdb_overlay_t * overlay ) {
  if( FD_UNLIKELY( !overlay ) ) {
    FD_LOG_WARNING(( "NULL overlay" ));
    return NULL;
  }
  overlay->cnt = 0;
  acc_map_new( overlay->map );
  return overlay;
}

void
fd_accdb_overlay_fini( fd_accdb_overlay_t * overlay ) {
  FD_CRIT( overlay->cnt==0, "overlay not clean" );
}
