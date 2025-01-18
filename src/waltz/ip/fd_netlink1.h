#ifndef HEADER_fd_src_waltz_ip_fd_netlink_h
#define HEADER_fd_src_waltz_ip_fd_netlink_h

#if defined(__linux__)

#include "../../util/fd_util_base.h"

struct fd_netlink {
  int   fd;   /* netlink socket */
  uint  seq;  /* netlink sequence number */
};

typedef struct fd_netlink fd_netlink_t;

/* FIXME this should be a 'buffered reader' style API not an iterator since
   iterators are infallible by definition in Firedancer style. */

struct fd_netlink_iter {
  uchar * buf;
  ulong   buf_sz;
  uchar * msg0;
  uchar * msg1;
  int     err;
};

typedef struct fd_netlink_iter fd_netlink_iter_t;

FD_PROTOTYPES_BEGIN

/* fd_netlink_enobufs_cnt counts the number of ENOBUFS error occurrences. */

extern FD_TL ulong fd_netlink_enobufs_cnt;

/* fd_netlink_init creates a new netlink session.  Creates a new netlink
   socket with explicit ACKs.  seq0 is the initial sequence number. */

fd_netlink_t *
fd_netlink_init( fd_netlink_t * netlink,
                 uint           seq0 );

/* fd_netlink_fini closes the netlink socket. */

void *
fd_netlink_fini( fd_netlink_t * netlink );

/* fd_netlink_read_socket wraps recvfrom(fd,buf,buf_sz,0,0,0) but
   automatically skips EINTR and ENOBUFS errors. */

long
fd_netlink_read_socket( int     fd,
                        uchar * buf,
                        ulong   buf_sz );

/* fd_netlink_iter_init prepares iteration over a sequence of incoming
   netlink multipart messages. */

fd_netlink_iter_t *
fd_netlink_iter_init( fd_netlink_iter_t * iter,
                      fd_netlink_t *      netlink,
                      uchar *             buf,
                      ulong               buf_sz );

/* fd_netlink_iter_done returns 0 if there are more netlink messages to
   iterate over or 1 if not. */

int
fd_netlink_iter_done( fd_netlink_iter_t const * iter );

/* fd_netlink_iter_next advances the iterator to the next netlink message
   (if any).  Assumes !fd_netlink_iter_done(iter).  Invalidates pointers
   previously returned by fd_netlink_iter_msg(iter). */

fd_netlink_iter_t *
fd_netlink_iter_next( fd_netlink_iter_t * iter,
                      fd_netlink_t *      netlink );

/* fd_netlink_iter_msg returns a pointer to the current netlink message
   header.  Assumes !fd_netlink_iter_done(iter). */

static inline struct nlmsghdr const *
fd_netlink_iter_msg( fd_netlink_iter_t const * iter ) {
  return fd_type_pun_const( iter->msg0 );
}

static FD_FN_UNUSED ulong
fd_netlink_iter_drain( fd_netlink_iter_t * iter,
                       fd_netlink_t *      netlink ) {
  ulong cnt;
  for( cnt=0UL; !fd_netlink_iter_done( iter ); cnt++ ) {
    fd_netlink_iter_next( iter, netlink );
  }
  return cnt;
}

/* Debug utils */

char const *
fd_netlink_rtm_type_str( int rtm_type );

char const *
fd_netlink_rtattr_str( int rta_type );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_ip_fd_netlink_h */
