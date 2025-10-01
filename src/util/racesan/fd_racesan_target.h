#ifndef HEADER_fd_src_flamenco_racesan_fd_racesan_target_h
#define HEADER_fd_src_flamenco_racesan_fd_racesan_target_h

/* fd_racesan_target.h provides macros to instrument a shared memory
   concurrent algorithm with racesan.  These are zero cost if racesan
   is disabled (default in production). */

#include "fd_racesan_base.h"

#if FD_HAS_RACESAN

/* To instrument an algorithm with racesan, call fd_racesan_hook at
   critical sections.  For example:

     fd_racesan_hook( "load_pre" );
     ulong x = FD_VOLATILE_CONST( *p );
     fd_racesan_hook( "load_post" );
     x++;
     FD_VOLATILE_CONST( *p ) = x;
     fd_racesan_hook( "store_post" ); */

void
fd_racesan_hook_private( ulong        name_hash,
                         char const * file,
                         int          line );

#define fd_racesan_hook( name ) fd_racesan_hook_private( fd_racesan_strhash( (name), sizeof( name )-1UL ), __FILE__, __LINE__ )

#else

#define fd_racesan_hook( ... )

#endif /* FD_HAS_RACESAN */

FD_PROTOTYPES_BEGIN

/* racesan instrumentation is set up per thread. */
extern FD_TL fd_racesan_t * fd_racesan_g;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_racesan_fd_racesan_target_h */
