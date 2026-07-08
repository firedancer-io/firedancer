#ifndef HEADER_fd_src_disco_waker_fd_waker_h
#define HEADER_fd_src_disco_waker_fd_waker_h

/* The waker tile sleeps in epoll_wait(2) on behalf of every tile that
   owns kernel file descriptors, so those tiles do not need to poll
   their fds speculatively.

   Mechanism: at boot, before any tile is forked, the launcher creates
   one "outer" epoll instance for the waker plus one "inner" epoll
   instance per waker client tile, at fixed fd numbers (the same
   inheritance scheme as FD_ACCDB_FD_* and the XDP fds: dup2 to a
   known number, toggle FD_CLOEXEC per fork so only entitled tiles
   inherit each fd).  Each inner epfd is registered in the outer set
   with EPOLLIN|EPOLLONESHOT.  Client tiles register their own
   sockets in their inner set (level-triggered EPOLLIN; EPOLLOUT only
   armed while a send is blocked on EAGAIN) and never touch the outer
   set except to rearm their own entry.  Nested epoll readiness is
   level-triggered from the outer view: the inner epfd polls readable
   while its set has a genuinely ready entry (the kernel re-polls
   inner items on outer poll), and every new event propagates a
   wakeup up the nesting chain, so there is no window where a client
   has a ready fd but the waker was never signaled.  Requires the
   nested-epoll wakeup fixes present in kernels >=5.13 (and in the
   5.4/5.10 stable series backports).

   Wake protocol, per client: one fseq word (waker RW, client RW),
   value 0 idle / 1 ready.

     waker:   n = epoll_wait( outer, evs, max, timeout );
              for each ev: fd_fseq_update( word[ ev.data ], 1UL );
              (the outer entry is now disarmed by EPOLLONESHOT, so a
              slow client cannot wake-storm the waker)

     client:  each loop iteration, if fd_fseq_query( word )!=1 skip
              fd servicing entirely (one cache read).  Otherwise:
                fd_fseq_update( word, 0UL );            clear FIRST
                while( service_fds() );                 drain to empty
                epoll_ctl( FD_WAKER_OUTER_FD, EPOLL_CTL_MOD,
                           my_inner_fd, ... EPOLLONESHOT ... );
                                                        rearm LAST
              EPOLL_CTL_MOD re-polls the target immediately, so
              readiness that raced the drain re-fires the outer:
              there is no lost-wake window.

   The client must use level-triggered entries in its inner set and
   drain to empty: an edge-triggered inner entry whose event was
   consumed from the inner rdllist but whose data was not fully read
   stops contributing to outer readiness and can strand data. */

#include "../../util/fd_util_base.h"

/* Fixed fd numbers inherited from the launcher (see the accdb/XDP fd
   passing pattern in fd_topo_run/run.c).  The outer epfd is inherited
   by the waker tile (to wait on) and by every client tile (to rearm
   its own entry; clients are seccomp-restricted to epoll_ctl on it).
   FD_WAKER_INNER_FD( idx ) is the inner epfd of the client with
   waker_client_idx idx, inherited by that client and by the waker. */

#define FD_WAKER_OUTER_FD        (123500)
#define FD_WAKER_INNER_FD( idx ) (123501+(int)(idx))

/* Max waker clients supported.  Bounded by the fixed fd range
   [123501, 123501+FD_WAKER_CLIENT_MAX). */

#define FD_WAKER_CLIENT_MAX (16UL)

FD_PROTOTYPES_BEGIN

/* fd_waker_tile_is_client returns 1 if the named tile implementation
   has been converted to waker-gated fd servicing, 0 otherwise.  Only
   converted tiles may be listed: enrollment makes the boot process
   inherit epoll fds into the tile, which the tile must account for in
   its allowed fds and seccomp policy, and the tile must drain/rearm
   per the wake protocol above. */

int
fd_waker_tile_is_client( char const * name );

/* fd_waker_install creates the outer epoll fd and client_cnt inner
   epoll fds at their fixed fd numbers, and registers each inner fd in
   the outer set with EPOLLIN|EPOLLONESHOT and event data idx.  If
   client_cnt is nonzero, first runs a self test (forks a scratch
   child) proving the running kernel wakes a blocked nested epoll_wait
   and re-fires pending readiness on EPOLL_CTL_MOD rearm; kernels
   missing the nested-epoll wakeup fixes (unpatched v5.5-v5.12) would
   silently lose wakes and are rejected at boot instead.  Must be
   called by the launcher before any tile is forked, at most once.
   Logs err and exits on failure. */

void
fd_waker_install( ulong client_cnt );

/* fd_waker_client_rearm rearms this client's entry in the outer epoll
   set.  Must be called by a client tile after fully draining its
   inner set (see wake protocol above).  idx is the caller's
   waker_client_idx.  Logs err and exits on failure. */

void
fd_waker_client_rearm( ulong idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_waker_fd_waker_h */
