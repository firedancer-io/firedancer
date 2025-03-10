#if !defined(__linux__)
#error "fd_xdp_redirect_user requires Linux operating system with XDP support"
#endif

#define _DEFAULT_SOURCE
#include "fd_xdp_redirect_user.h"
#include "../ebpf/fd_linux_bpf.h"
#include <errno.h>

fd_xsk_t *
fd_xsk_activate( fd_xsk_t * xsk,
                 int        xsk_map_fd ) {

  uint key   = xsk->if_queue_id;
  int  value = xsk->xsk_fd;
  if( FD_UNLIKELY( 0!=fd_bpf_map_update_elem( xsk_map_fd, &key, &value, BPF_ANY ) ) ) {
    FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%u,value=%#x,flags=%#x) failed (%i-%s)",
                     xsk_map_fd, key, (uint)value, (uint)BPF_ANY, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  FD_LOG_INFO(( "Attached to XDP on interface %u queue %u",
                xsk->if_idx, xsk->if_queue_id ));
  return xsk;
}

fd_xsk_t *
fd_xsk_deactivate( fd_xsk_t * xsk,
                   int        xsk_map_fd ) {

  uint key   = xsk->if_queue_id;
  if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( xsk_map_fd, &key ) ) ) {
    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%u) failed (%i-%s)", xsk_map_fd, key, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  FD_LOG_INFO(( "Detached from XDP on interface %u queue %u",
                xsk->if_idx, xsk->if_queue_id ));
  return xsk;
}
