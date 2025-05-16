#include "fd_contact_info.h"
#include "../../util/fd_util.h"

fd_ip4_port_t
fd_contact_info_get_socket( fd_contact_info_t const * ci,
                            uchar                     socket_tag ){
  if( FD_UNLIKELY( !ci || socket_tag>=FD_CONTACT_INFO_SOCKET_MAX ) ) {
    FD_LOG_ERR(( "Invalid arguments to fd_contact_info_get_socket" ));
  }
  return ci->sockets[ socket_tag ];
}

fd_ip4_port_t
fd_contact_info_gossip_socket( fd_contact_info_t const * ci ){
  return ci->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
}

struct socket_ctx {
  fd_ip4_port_t socket;
  uchar         socket_tag;
};

typedef struct socket_ctx socket_ctx_t;

#define SORT_NAME           sort_socket_port
#define SORT_KEY_T          socket_ctx_t
#define SORT_BEFORE( a, b ) ( (a).socket.port<(b).socket.port )

#include "../../util/tmpl/fd_sort.c"


int
fd_contact_info_convert_sockets( fd_contact_info_t const *             contact_info,
                                 fd_gossip_contact_info_socket_entry_t out_sockets_entries[static FD_CONTACT_INFO_SOCKET_MAX],
                                 uchar *                               out_socket_entries_cnt,
                                 uint                                  out_addrs[static FD_CONTACT_INFO_SOCKET_MAX],
                                 uchar *                               out_addrs_cnt ) {
  if( FD_UNLIKELY( !contact_info || !out_sockets_entries || !out_socket_entries_cnt ||
                   !out_addrs || !out_addrs_cnt ) ) {
    FD_LOG_ERR(( "Invalid arguments to fd_contact_info_convert_sockets" ));
    return -1;
  }

  socket_ctx_t filled_up[ FD_CONTACT_INFO_SOCKET_MAX ];
  ulong filled_up_cnt = 0UL;
  for( ulong j=0; j<FD_CONTACT_INFO_SOCKET_MAX; j++ ) {
    if( contact_info->sockets[j].l != FD_CONTACT_INFO_NULL_SOCKET ){
      filled_up[filled_up_cnt].socket = contact_info->sockets[j];
      /* Convert port to host order. Needed for sorting and because port info
         is encoded in host order in ContactInfo */
      filled_up[filled_up_cnt].socket.port = fd_ushort_bswap( filled_up[filled_up_cnt].socket.port );
      filled_up[filled_up_cnt].socket_tag = (uchar)j;
      filled_up_cnt++;
    }
  }

  socket_ctx_t scratch[ FD_CONTACT_INFO_SOCKET_MAX ];
  socket_ctx_t * sorted = sort_socket_port_stable_fast( filled_up, filled_up_cnt, scratch );

  uchar addrs_cnt = 0UL;
  uchar socket_entries_cnt = 0UL;

  /* fill in first entry */
  out_addrs[addrs_cnt++]                              = sorted[0].socket.addr;
  out_sockets_entries[socket_entries_cnt].port_offset = sorted[0].socket.port;
  out_sockets_entries[socket_entries_cnt].addr_index  = 0U;
  out_sockets_entries[socket_entries_cnt++].tag       = sorted[0].socket_tag;

  for( ulong j=1; j<filled_up_cnt; j++ ) {
    socket_ctx_t const * socket = &sorted[j];

    uchar addr_found = 0U;
    for( ulong k=0UL; k<addrs_cnt; k++ ) {
      if( out_addrs[k]==socket->socket.addr ) {
        /* Already have this address, set index */
        out_sockets_entries[socket_entries_cnt].addr_index = (uchar)k;
        addr_found                                         = 1U;
        break;
      }
    }
    if( !addr_found ) {
      /* New address, add it */
      out_addrs[addrs_cnt++]                              = socket->socket.addr;
      out_sockets_entries[socket_entries_cnt].addr_index  = (uchar)(addrs_cnt-1);
    }

    out_sockets_entries[socket_entries_cnt].port_offset   = (socket->socket.port-sorted[j-1].socket.port);
    out_sockets_entries[socket_entries_cnt++].tag         = socket->socket_tag;
  }

  *out_addrs_cnt              = addrs_cnt;
  *out_socket_entries_cnt     = socket_entries_cnt;
  return 0;
}
