#include "fd_racesan.h"
#include "fd_racesan_target.h"
#include "../../util/log/fd_log.h"

#define MAP_NAME        hook_map
#define MAP_T           fd_racesan_hook_map_t
#define MAP_LG_SLOT_CNT FD_RACESAN_HOOKS_LG_MAX
#define MAP_KEY         name_hash
#define MAP_MEMOIZE     0
#define MAP_KEY_HASH(k) (uint)(k)
#include "../../util/tmpl/fd_map.c"

FD_TL fd_racesan_t * fd_racesan_g = NULL;

fd_racesan_t *
fd_racesan_new( fd_racesan_t * racesan,
                void *         ctx ) {
  if( FD_UNLIKELY( !racesan ) ) {
    FD_LOG_WARNING(( "NULL racesan" ));
    return NULL;
  }
  racesan->hook_ctx     = ctx;
  racesan->default_hook = NULL;
  hook_map_new( racesan->hook_map );
  return racesan;
}

void *
fd_racesan_delete( fd_racesan_t * racesan ) {
  (void)racesan;
  return racesan;
}

void
fd_racesan_inject( fd_racesan_t *         racesan,
                   char const *           name,
                   fd_racesan_hook_fn_t * fn ) {
  ulong name_len  = strlen( name );
  ulong name_hash = fd_racesan_strhash( name, name_len );
  fd_racesan_hook_map_t * entry = hook_map_insert( racesan->hook_map, name_hash );
  if( FD_UNLIKELY( !entry ) ) FD_LOG_ERR(( "fd_racesan_inject failed: hook for %s already exists", name ));
  entry->hook = fn;
}

void
fd_racesan_inject_default( fd_racesan_t *      racesan,
                           fd_racesan_hook_fn_t * callback ) {
  racesan->default_hook = callback;
}

void
fd_racesan_enter( fd_racesan_t * racesan ) {
  if( FD_UNLIKELY( fd_racesan_g ) ) {
    FD_LOG_CRIT(( "Failed to enter racesan context: already activated" ));
  }
  fd_racesan_g = racesan;
}

void
fd_racesan_exit( void ) {
  fd_racesan_g = NULL;
}

void
fd_racesan_hook_private( ulong        name_hash,
                         char const * file,
                         int          line ) {
  fd_racesan_t * racesan = fd_racesan_g;
  if( FD_UNLIKELY( !racesan ) ) return;

  fd_racesan_hook_map_t const * entry = hook_map_query_const( racesan->hook_map, name_hash, NULL );
  if( entry ) {
    entry->hook( racesan->hook_ctx, name_hash );
  }

  if( racesan->default_hook ) {
    racesan->default_hook( racesan->hook_ctx, name_hash );
  }

  (void)file; (void)line;
}
