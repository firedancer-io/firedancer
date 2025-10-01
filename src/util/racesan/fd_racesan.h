#ifndef HEADER_fd_src_flamenco_racesan_fd_racesan_h
#define HEADER_fd_src_flamenco_racesan_fd_racesan_h

/* fd_racesan.h provides test utils for deterministically simulating
   data races.  Practically just a mechanism to inject callbacks into
   instrumented production code (with appropriate compiler hacks to
   invalidate registers/locals).

   See README.md for usage. */

#include "fd_racesan_base.h"

/* FD_RACESAN_HOOKS_MAX is the max number of active racesan hooks */

#define FD_RACESAN_HOOKS_LG_MAX (7)
#define FD_RACESAN_HOOKS_MAX    (1UL<<FD_RACESAN_HOOKS_LG_MAX) /* 128 */

typedef void
fd_racesan_hook_fn_t( void * ctx,
                      ulong  name_hash );

struct fd_racesan_hook_map {
  ulong                  name_hash;
  fd_racesan_hook_fn_t * hook;
};

typedef struct fd_racesan_hook_map fd_racesan_hook_map_t;

struct fd_racesan {
  void * hook_ctx;

  fd_racesan_hook_fn_t * default_hook;
  fd_racesan_hook_map_t  hook_map[ FD_RACESAN_HOOKS_MAX ];
};

typedef struct fd_racesan fd_racesan_t;

FD_PROTOTYPES_BEGIN

fd_racesan_t *
fd_racesan_new( fd_racesan_t * obj,
                void *         ctx );

void *
fd_racesan_delete( fd_racesan_t * obj );

/* fd_racesan_inject injects a callback into an fd_racesan_hook trace
   point.  Useful for fault injection. */

void
fd_racesan_inject( fd_racesan_t *      obj,
                   char const *        hook,
                   fd_racesan_hook_fn_t * callback );

/* fd_racesan_inject_default injects a default callback that's called
   by any fd_racesan_hook trace points. */

void
fd_racesan_inject_default( fd_racesan_t *      obj,
                           fd_racesan_hook_fn_t * callback );

void
fd_racesan_enter( fd_racesan_t * racesan );

void
fd_racesan_exit( void );

FD_PROTOTYPES_END

static inline void
fd_racesan_private_cleanup( int * unused ) {
  (void)unused;
  fd_racesan_exit();
}

#define FD_RACESAN_INJECT_BEGIN( _rs )        \
  do {                                        \
    fd_racesan_t * __rs = (_rs);              \
    fd_racesan_enter( __rs );                 \
    __attribute__((cleanup(fd_racesan_private_cleanup))) int __dummy; \
    do {                                      \

#define FD_RACESAN_INJECT_END \
    } while(0); \
  } while(0)

#endif /* HEADER_fd_src_flamenco_racesan_fd_racesan_h */
