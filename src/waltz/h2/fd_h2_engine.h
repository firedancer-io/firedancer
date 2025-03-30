#ifndef HEADER_fd_src_waltz_h2_fd_h2_engine_h
#define HEADER_fd_src_waltz_h2_fd_h2_engine_h

/* fd_h2_engine.h provides a high-level APIs for driving HTTP/2 streams
   over multiple conns.  Flexibly supports client and server conns.
   Supports both short request-reply style streams and long lived flows
   like WebSockets.

   There is no single 'engine object'.  Instead, the engine is composed
   of multiple objects:

   - Connection pool
   - Stream pool
   - Timer heap
   - Application callback interface
   - Message buffer (hcache) */

#include "../../util/fd_util_base.h"

/* Declare a stream pool */

FD_PROTOTYPES_BEGIN


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_engine_h */
