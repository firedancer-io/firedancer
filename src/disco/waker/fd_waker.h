#ifndef HEADER_fd_src_disco_waker_fd_waker_h
#define HEADER_fd_src_disco_waker_fd_waker_h

/* The waker tile sleeps in epoll_wait(2) on behalf of every tile
   that owns kernel fds, so those tiles do not poll speculatively.

   At boot the launcher creates one "outer" epoll fd for the waker
   plus one "inner" epoll fd per client, at fixed inherited numbers.
   Inner fds sit in the outer set with EPOLLIN|EPOLLONESHOT.  Clients
   register sockets in their inner set (level-triggered) and touch
   the outer set only to rearm their own entry.  A ready inner fd
   wakes the outer epoll_wait.

   Wake protocol, per client: one fseq word, 0 idle / 1 ready.

     waker:   for each outer event: fd_fseq_update( word, 1UL );
              (EPOLLONESHOT: a slow client cannot wake-storm)

     client:  if fd_fseq_query( word )==1:
                fd_fseq_update( word, 0UL );   clear FIRST
                while( service_fds() );        drain to empty
                fd_waker_client_rearm( idx );  rearm LAST
              the rearm MOD re-polls, so readiness that raced the
              drain re-fires: no lost-wake window.

   Inner entries must be level-triggered and drained to empty, or
   data can strand with no outer readiness. */

#include "../../util/fd_util_base.h"

#define FD_WAKER_OUTER_FD        (123500)
#define FD_WAKER_INNER_FD( idx ) (123501+(int)(idx))

#define FD_WAKER_CLIENT_MAX (16UL)

FD_PROTOTYPES_BEGIN

/* fd_waker_install creates the outer and client_cnt inner epoll fds
   at their fixed numbers and registers the inners in the outer set.
   Self-tests the kernel's nested-epoll wakeups first (broken on
   unpatched v5.5-v5.12; rejected at boot rather than losing wakes).
   Logs error and aborts on failure. */

void
fd_waker_install( ulong client_cnt );

/* fd_waker_client_rearm rearms the caller's entry in the outer
   epoll set after a drain (see wake protocol).  Logs err on
   failure. */

void
fd_waker_client_rearm( ulong idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_waker_fd_waker_h */
