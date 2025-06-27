#include "../fd_contact_info.h"
#include "../fd_gossip_private.h"

struct fd_crds_contact_info_entry {
  fd_contact_info_t contact_info[1];
  struct{
    ulong next;
  } pool;
  /* TODO: Stake-ordered treap/pq ? */
};

typedef struct fd_crds_contact_info_entry fd_crds_contact_info_entry_t;

#define POOL_NAME  crds_contact_info_pool
#define POOL_T     fd_crds_contact_info_entry_t
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

int
fd_crds_contact_info_populate( fd_gossip_view_crds_value_t const * view,
                               uchar const *                       payload,
                               fd_contact_info_t *                 ci ) {
  FD_TEST( view->tag == 11 /* Contact Info */ );
  fd_gossip_view_contact_info_t const * ci_view = view->contact_info;

  ci->instance_creation_wallclock_nanos = ci_view->instance_creation_wallclock_nanos;
  ci->wallclock_nanos                   = view->wallclock_nanos;
  ci->shred_version                     = ci_view->shred_version;
  fd_memcpy( ci->pubkey, payload + view->pubkey_off, 32UL );

  ci->version.major       = ci_view->version->major;
  ci->version.minor       = ci_view->version->minor;
  ci->version.patch       = ci_view->version->patch;
  ci->version.commit      = ci_view->version->commit;
  ci->version.feature_set = ci_view->version->feature_set;

  /* We only want to save the first instance in the event of duplicate socket
     tag entries

     TODO: Check if we might want to keep last-seen instead? */
  uchar  tag_set[ FD_CONTACT_INFO_SOCKET_MAX ] = {0};
  ushort cur_port = 0U;
  for( ulong i = 0UL; i < ci_view->sockets_len; i++ ) {
   fd_gossip_view_socket_t const * socket_view = &ci_view->sockets[ i ];
    ushort socket_tag = socket_view->key;
    if( FD_UNLIKELY( socket_tag >= FD_CONTACT_INFO_SOCKET_MAX ) ) {
        /* FIXME: We should treat this a corrupted packet, but we
           see a bunch of contact infos in testnet that enter this
           branch. Should investigate before making this a return
           instead of continue. */
      continue;
    }
    if( FD_UNLIKELY( tag_set[ socket_tag ] ) ) {
      /* already seen this socket tag, skip */
      continue;
    }
    if( FD_UNLIKELY( socket_view->index >= ci_view->addrs_len ) ) {
      FD_LOG_WARNING(( "socket index %u out of bounds for addrs_len %u", socket_view->index, ci_view->addrs_len ));
      continue; /* FIXME: Return instead? This is likely a corrupted packet */
    }

    fd_gossip_view_ipaddr_t const * addr_view = &ci_view->addrs[ socket_view->index ];
    if( FD_UNLIKELY( addr_view->is_ip6 ) ) {
      continue; /* IPv6 not supported */
    }

    tag_set[ socket_tag ] = 1;
    cur_port += socket_view->offset;

    ci->sockets[ socket_tag ].addr = addr_view->ip4_addr;
    ci->sockets[ socket_tag ].port = fd_ushort_bswap( cur_port );
  }
  return 0;
}
