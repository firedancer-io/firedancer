#include "../fd_gossip_types.h"
#include "../fd_gossip_private.h"

struct fd_crds_contact_info_entry {
  fd_contact_info_t contact_info[1];
  struct{
    ulong next;
  } pool;
};

typedef struct fd_crds_contact_info_entry fd_crds_contact_info_entry_t;

#define POOL_NAME  crds_contact_info_pool
#define POOL_T     fd_crds_contact_info_entry_t
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

void
fd_crds_contact_info_init( fd_gossip_view_crds_value_t const * view,
                           uchar const *                       payload,
                           fd_contact_info_t *                 ci,
                           fd_crds_metrics_t *                 metrics ) {
  FD_TEST( view->tag==FD_GOSSIP_VALUE_CONTACT_INFO );
  fd_gossip_view_contact_info_t const * ci_view = view->contact_info;

  ci->instance_creation_wallclock_nanos = ci_view->instance_creation_wallclock_nanos;
  ci->wallclock_nanos                   = view->wallclock_nanos;
  ci->shred_version                     = ci_view->shred_version;
  fd_memcpy( ci->pubkey.uc, payload + view->pubkey_off, 32UL );

  ci->version.major       = ci_view->version->major;
  ci->version.minor       = ci_view->version->minor;
  ci->version.patch       = ci_view->version->patch;
  ci->version.commit      = ci_view->version->commit;
  ci->version.feature_set = ci_view->version->feature_set;

  ushort cur_port = 0U;
  for( ulong i = 0UL; i < ci_view->sockets_len; i++ ) {
    fd_gossip_view_socket_t const * socket_view = &ci_view->sockets[ i ];
    cur_port = (ushort)(cur_port + socket_view->offset);

    ushort socket_tag = socket_view->key;
    if( FD_UNLIKELY( socket_tag>FD_CONTACT_INFO_SOCKET_LAST ) ) {
      /* https://github.com/anza-xyz/agave/blob/bff4df9cf6f41520a26c9838ee3d4d8c024a96a1/gossip/src/contact_info.rs#L572-L574 */
      metrics->ci_insert_events.unrecognized_socket_tag++;
      continue;
    }
    /* Should be caught by parser. */
    FD_TEST( socket_view->index < ci_view->addrs_len );

    fd_gossip_view_ipaddr_t const * addr_view = &ci_view->addrs[ socket_view->index ];
    if( FD_UNLIKELY( addr_view->is_ip6 ) ) {
      metrics->ci_insert_events.ipv6_address++;
      continue;
    }

    /* We only want to save the last instance in the event of duplicate
     socket tag entries. This tracks Agave's behavior when populating
     its ContactInfo cache, where setting a socket value overrides
     an existing entry instead of appending.
     https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/contact_info.rs#L557-L570
     */
    ci->sockets[ socket_tag ].addr = addr_view->ip4;
    ci->sockets[ socket_tag ].port = fd_ushort_bswap( cur_port );
  }
  return;
}
