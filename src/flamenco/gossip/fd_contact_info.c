#include "fd_contact_info.h"
#include "../../util/net/fd_net_headers.h"
#include <string.h>

static void
reset_socket_tag_idx( ushort * socket_tag_idx ) {
  for( ulong i = 0UL; i<FD_GOSSIP_SOCKET_TAG_MAX; i++ ) {
    socket_tag_idx[ i ] = USHORT_MAX;
  }
}

static void
refresh_metadata( fd_contact_info_t * ci_int ) {
  ushort cur_port = 0U;
  reset_socket_tag_idx( ci_int->socket_tag_idx );
  for( ushort i = 0UL; i<ci_int->ci_crd.sockets_len; i++ ) {
    cur_port = (ushort)( cur_port + ci_int->sockets[ i ].offset );

    ci_int->socket_tag_idx[ ci_int->sockets[ i ].key ] = i;
    ci_int->ports[ i ] = cur_port;
  }
}

ushort
fd_contact_info_get_shred_version( fd_contact_info_t const * contact_info ) {
  return contact_info->ci_crd.shred_version;
}

void
fd_contact_info_set_shred_version( fd_contact_info_t * contact_info,
                                   ushort              shred_version ) {
  contact_info->ci_crd.shred_version = shred_version;
}


void
fd_contact_info_init( fd_contact_info_t * contact_info ) {
  memset( contact_info, 0, sizeof(fd_contact_info_t) );

  contact_info->ci_crd.addrs    = contact_info->addrs;
  contact_info->ci_crd.sockets  = contact_info->sockets;

  reset_socket_tag_idx( contact_info->socket_tag_idx );
}

void
fd_contact_info_from_ci_v2( fd_gossip_contact_info_v2_t const * ci_v2,
                            fd_contact_info_t *                 contact_info ) {
  fd_gossip_contact_info_v2_t * ci_int = &contact_info->ci_crd;
  *ci_int = *ci_v2;

  ci_int->addrs           = contact_info->addrs;
  ci_int->addrs_len       = 0U;
  ci_int->sockets         = contact_info->sockets;
  ci_int->sockets_len     = 0U;
  ci_int->extensions      = NULL; /* unsupported */
  ci_int->extensions_len  = 0U;   /* unsupported */

  reset_socket_tag_idx( contact_info->socket_tag_idx );


  /* For sockets, validate individual entries and keep track of offsets */
  ushort cur_offset = 0U;
  ushort cur_port   = 0U;
  for( ulong i = 0UL; i<ci_v2->sockets_len; i++ ) {
    fd_gossip_socket_entry_t const * socket_entry = &ci_v2->sockets[ i ];
    cur_offset = (ushort)( cur_offset + socket_entry->offset );
    cur_port   = (ushort)( cur_port   + socket_entry->offset );

    if( FD_UNLIKELY( socket_entry->key >= FD_GOSSIP_SOCKET_TAG_MAX ) ){
      /* We seem to receive quite a few of these in testnet, so commented out logging
         TODO: Check with Anza about why this is the case */
      // FD_LOG_WARNING(( "Invalid socket entry key %u", socket_entry->key ));
      continue;
    }

    if( FD_UNLIKELY( contact_info->socket_tag_idx[ socket_entry->key ]!=USHORT_MAX ) ){
      FD_LOG_WARNING(( "Duplicate socket tag %u", socket_entry->key ));
      continue;
    }

    /* Find addr index
       TODO: can avoid nested for loop with a simple mapping of (ci_v2 addr_idx, ci_int addr_idx) */
    uchar addr_index = UCHAR_MAX;
    for( ulong j = 0UL; j < ci_int->addrs_len; j++ ) {
      if( FD_LIKELY( memcmp(&ci_int->addrs[j], &ci_v2->addrs[socket_entry->index], sizeof(fd_gossip_ip_addr_t)) == 0 ) ) {
        addr_index = (uchar)j;
        break;
      }
    }

    /* Add entry to end of addrs if does not exist */
    if( FD_UNLIKELY( addr_index == UCHAR_MAX ) ) {
      if( FD_UNLIKELY( socket_entry->index >= ci_v2->addrs_len ) ) {
        FD_LOG_WARNING(( "addr index %u out of bounds for addrs_len %u", socket_entry->index, ci_v2->addrs_len ));
        continue;
      }
      if( FD_UNLIKELY( ci_int->addrs_len >= FD_GOSSIP_SOCKET_TAG_MAX ) ) {
        FD_LOG_ERR(( "Too many unique addresses (%u) in contact info, possible broken implementation of fd_contact_info_from_ci_v2", ci_int->addrs_len ));
        continue;
      }
      ci_int->addrs[ ci_int->addrs_len ] = ci_v2->addrs[ socket_entry->index ];
      addr_index = (uchar)ci_int->addrs_len;
      ci_int->addrs_len++;
    }

    ci_int->sockets[ ci_int->sockets_len ].index            = addr_index;
    ci_int->sockets[ ci_int->sockets_len ].key              = socket_entry->key;
    ci_int->sockets[ ci_int->sockets_len ].offset           = cur_offset;

    /* Metadata updates */
    contact_info->socket_tag_idx[ socket_entry->key ]       = ci_int->sockets_len;
    contact_info->ports[ ci_int->sockets_len ]              = cur_port;

    ci_int->sockets_len++;
    cur_offset = 0U;
  }

  if( FD_UNLIKELY( ci_int->sockets_len > FD_GOSSIP_SOCKET_TAG_MAX ) ){
    FD_LOG_ERR(( "Too many sockets (%u) in contact info, possible broken implementation of fd_contact_info_from_ci_v2", ci_int->sockets_len ));
  }
}

void
fd_contact_info_to_ci_v2( fd_contact_info_t const *     ci_int,
                          fd_gossip_contact_info_v2_t * ci_v2 ){
  *ci_v2 = ci_int->ci_crd;
}

void
fd_contact_info_to_update_msg( fd_contact_info_t const * contact_info,
                               fd_gossip_update_msg_t *  update ) {
  fd_gossip_contact_info_v2_t const * ci_v2 = &contact_info->ci_crd;
  fd_memcpy( update->pubkey, &ci_v2->from, sizeof(fd_pubkey_t) );

  update->wallclock           = ci_v2->wallclock;
  update->shred_version       = ci_v2->shred_version;
  update->version_major       = ci_v2->version.major;
  update->version_minor       = ci_v2->version.minor;
  update->version_patch       = ci_v2->version.patch;
  update->version_commit      = ci_v2->version.commit;
  update->version_feature_set = ci_v2->version.feature_set;

  /* TODO: missing version_commit_type and version_type */
  update->version_commit_type = 0U;
  update->version_type        = 0U;

  ushort cur_port = 0U;
  for( ulong i = 0UL; i<FD_GOSSIP_SOCKET_TAG_MAX; i++ ) {
    fd_gossip_socket_entry_t const * socket_entry = &ci_v2->sockets[ i ];
    cur_port = (ushort)( cur_port + socket_entry->offset );
    ushort socket_tag = socket_entry->key;

    /* NOTE: We use FD_GOSSIP_UPDATE_MSG_NUM_SOCKETS instead of FD_GOSSIP_SOCKET_TAG_MAX
       since they aren't strictly the same. At this moment
       FD_GOSSIP_UPDATE_MSG is missing the TVU_QUIC */

    if( FD_UNLIKELY( socket_tag >= FD_GOSSIP_UPDATE_MSG_NUM_SOCKETS ) ){
      FD_LOG_DEBUG(( "Unsupported socket tag in update msg %u", socket_tag ));
      continue;
    }
    if( FD_UNLIKELY( !fd_gossip_ip_addr_is_ip4( &ci_v2->addrs[ socket_entry->index ] ))){
      /* Skip non IPv4 entries */
      continue;
    }

    update->addrs[ socket_tag ].ip   = ci_v2->addrs[ socket_entry->index ].inner.ip4;
    update->addrs[ socket_tag ].port = cur_port ;
  }
}

int
fd_contact_info_get_socket_addr( fd_contact_info_t const *  ci_int,
                                 uchar                      socket_tag,
                                 fd_gossip_socket_addr_t *  out_addr ) {
  if( FD_UNLIKELY( socket_tag >= FD_GOSSIP_SOCKET_TAG_MAX ) ) {
    FD_LOG_ERR(( "Invalid socket tag %u", socket_tag ));
    return -1;
  }
  if( FD_UNLIKELY( ci_int->socket_tag_idx[ socket_tag ]==USHORT_MAX ) ) {
    FD_LOG_WARNING(( "Socket tag %u not found in contact info", socket_tag ));
    return -1;
  }
  ushort socket_idx = ci_int->socket_tag_idx[ socket_tag ];
  fd_gossip_socket_entry_t const * socket_entry = &ci_int->ci_crd.sockets[ socket_idx ];
  fd_gossip_ip_addr_t const * addr = &ci_int->ci_crd.addrs[ socket_entry->index ];
  ushort port = fd_ushort_bswap( ci_int->ports[ socket_idx ] );

  if( FD_LIKELY( fd_gossip_ip_addr_is_ip4( addr ) ) ) {
    fd_gossip_socket_addr_new_disc( out_addr, fd_gossip_socket_addr_enum_ip4 );
    out_addr->inner.ip4.port = port;
    out_addr->inner.ip4.addr = addr->inner.ip4;
  } else {
    fd_gossip_socket_addr_new_disc( out_addr, fd_gossip_socket_addr_enum_ip6 );
    out_addr->inner.ip6.port = port;
    out_addr->inner.ip6.addr = addr->inner.ip6;
  }

  return 0;

}

static int
fd_contact_info_remove_socket( fd_contact_info_t *      ci_int,
                               ushort                   socket_tag ) {
  if( FD_UNLIKELY( socket_tag >= FD_GOSSIP_SOCKET_TAG_MAX ) ){
    FD_LOG_ERR(( "Invalid socket tag %u", socket_tag ));
  }

  if( FD_UNLIKELY( ci_int->socket_tag_idx[ socket_tag ]==USHORT_MAX ) ) {
    FD_LOG_WARNING(( "Socket tag %u not found in contact info", socket_tag ));
    return -1;
  }

  ushort socket_idx = ci_int->socket_tag_idx[ socket_tag ];
  ushort addr_idx = ci_int->ci_crd.sockets[ socket_idx ].index;
  memmove( &ci_int->ci_crd.sockets[ socket_idx ],
           &ci_int->ci_crd.sockets[ socket_idx+1 ],
           sizeof(fd_gossip_socket_entry_t)*(ulong)( ci_int->ci_crd.sockets_len - socket_idx - 1 ) );
  ci_int->ci_crd.sockets_len--;

  /* Remove addr idx if no longer in any socket entry */
  int addr_found = 0;
  for( ulong i = 0UL; i<ci_int->ci_crd.sockets_len; i++ ) {
    if( ci_int->ci_crd.sockets[ i ].index == addr_idx ){
      addr_found = 1;
      break;
    }
  }

  if( !addr_found ){
    memmove( &ci_int->ci_crd.addrs[ addr_idx ],
             &ci_int->ci_crd.addrs[ addr_idx+1 ],
             sizeof(fd_gossip_ip_addr_t)*(ulong)( ci_int->ci_crd.addrs_len - addr_idx - 1 ) );
    ci_int->ci_crd.addrs_len--;
  }

  refresh_metadata( ci_int );

  return 0;
}

int
fd_contact_info_insert_socket( fd_contact_info_t *            ci_int,
                               fd_gossip_peer_addr_t const *  peer,
                               uchar                          socket_tag ) {
  if( FD_UNLIKELY( socket_tag >= FD_GOSSIP_SOCKET_TAG_MAX ) ) {
    FD_LOG_ERR(( "Invalid socket tag %u", socket_tag ));
  }

  if( FD_UNLIKELY( ci_int->socket_tag_idx[ socket_tag ]!=FD_CONTACT_INFO_SOCKET_TAG_NULL ) ) {
    FD_LOG_NOTICE(( "Overwriting socket tag %u", socket_tag ));
    fd_contact_info_remove_socket( ci_int, socket_tag );
  }

  ushort new_port = peer->port; /* host order */
  fd_gossip_socket_entry_t new_socket_entry;
  new_socket_entry.key = socket_tag;

  /* Find idx to insert in */
  ushort insert_idx = 0;
  ushort cur_port = 0U;
  for( ; insert_idx<ci_int->ci_crd.sockets_len; insert_idx++ ) {
    fd_gossip_socket_entry_t const * socket_entry = &ci_int->sockets[ insert_idx ];
    if( FD_LIKELY( cur_port + socket_entry->offset > new_port ) ) {
      break;
    }
    cur_port = (ushort)( cur_port + socket_entry->offset );
  }

  new_socket_entry.offset = (ushort)( new_port - cur_port );

  /* Update the offset for the entry currently in insert_idx */
  ci_int->sockets[ insert_idx ].offset = (ushort)( ci_int->sockets[ insert_idx ].offset - new_socket_entry.offset );

  /* Shift all entries starting from insert_idx down */
  memmove( &ci_int->sockets[ insert_idx+1 ],
           &ci_int->sockets[ insert_idx ],
           sizeof(fd_gossip_socket_entry_t)*(ulong)( ci_int->ci_crd.sockets_len - insert_idx ) );
  ci_int->ci_crd.sockets_len++;

  /* Find addr idx */
  uchar addr_idx = 0U;
  for( ; addr_idx<ci_int->ci_crd.addrs_len; addr_idx++ ) {
    if( FD_LIKELY( ci_int->ci_crd.addrs[ addr_idx ].inner.ip4==peer->addr ) ) {
      break;
    }
  }

  if(  FD_UNLIKELY( addr_idx==ci_int->ci_crd.addrs_len ) ) {
    FD_LOG_INFO(( "Adding new addr %u", peer->addr ) );
    fd_gossip_ip_addr_new_disc( &ci_int->ci_crd.addrs[ addr_idx ], fd_gossip_ip_addr_enum_ip4 );
    ci_int->ci_crd.addrs[ addr_idx ].inner.ip4 = peer->addr;
    ci_int->ci_crd.addrs_len++;
  }

  new_socket_entry.index = addr_idx;
  ci_int->ci_crd.sockets[ insert_idx ] = new_socket_entry;

  /* Refresh metadata */
  refresh_metadata( ci_int );
  return 0;
}

int
fd_gossip_contact_info_v2_find_proto_ident( fd_gossip_contact_info_v2_t const * contact_info,
                                            uchar                               proto_ident,
                                            fd_gossip_socket_addr_t *           out_addr ) {
  ushort port = 0;
  for( ulong i = 0UL; i<contact_info->sockets_len; i++ ) {
    fd_gossip_socket_entry_t const * socket_entry = &contact_info->sockets[ i ];
    port = (ushort)( port + socket_entry->offset );
    if( socket_entry->key==proto_ident ) {
      if( socket_entry->index>=contact_info->addrs_len) {
        continue;
      }

      /* fd_gossip_socket_addr->inner and fd_gossip_ip_addr
         are slightly different, so we can't just
         out_addr->ip = contact_info->addrs[ idx ] */
      fd_gossip_ip_addr_t * tmp = &contact_info->addrs[ socket_entry->index ];
      if( FD_LIKELY( tmp->discriminant == fd_gossip_ip_addr_enum_ip4 ) ) {
        out_addr->discriminant = fd_gossip_socket_addr_enum_ip4;
        out_addr->inner.ip4.addr = tmp->inner.ip4;
        out_addr->inner.ip4.port = port;
      } else {
        out_addr->discriminant = fd_gossip_socket_addr_enum_ip6;
        out_addr->inner.ip6.addr = tmp->inner.ip6;
        out_addr->inner.ip6.port = port;
      }
      return 1;
    }
  }

  return 0;
}
