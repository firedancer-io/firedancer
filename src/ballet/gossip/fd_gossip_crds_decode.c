#include "fd_gossip_crds.h"
#include "fd_gossip_vector_utils.h"
#include "fd_gossip_validation.h"

/* Logic for parsing CRDS objects received over the network */

int
fd_gossip_parse_crds_obj( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      ) {

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_header_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_header_t * header = (fd_gossip_crds_header_t *)out_buf;

  if( !fd_bin_parse_read_blob_of_size( ctx, 64, &(header->signature) ) ) {
    FD_LOG_WARNING(( "unable to parse `signature`" ));
    return 0;
  }

  uint crds_type = 0;
  if( !fd_bin_parse_read_u32( ctx, &crds_type ) ) {
    FD_LOG_WARNING(( "unable to parse `crds_type`" ));
    return 0;
  }

  int parse_status = 0;

  switch( crds_type ) {
  case FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO:
    parse_status = fd_gossip_parse_crds_legacy_contact_info( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_VOTE:
    parse_status = fd_gossip_parse_crds_vote( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_LOWEST_SLOT:
    parse_status = fd_gossip_parse_crds_lowest_slot( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES:
    parse_status = fd_gossip_parse_crds_snapshot_hashes( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_ACCOUNT_HASHES:
    parse_status = fd_gossip_parse_crds_account_hashes( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_EPOCH_SLOTS:
    parse_status = fd_gossip_parse_crds_epoch_slots( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_LEGACY_VERSION:
    parse_status = fd_gossip_parse_crds_legacy_version( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_VERSION:
    parse_status = fd_gossip_parse_crds_version( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_NODE_INSTANCE:
    parse_status = fd_gossip_parse_crds_node_instance( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED:
    parse_status = fd_gossip_parse_crds_duplicate_shred( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES:
    parse_status = fd_gossip_parse_crds_incremental_snapshot_hashes( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  case FD_GOSSIP_CRDS_ID_CONTACT_INFO:
    parse_status = fd_gossip_parse_crds_contact_info( ctx, out_buf, out_buf_sz, obj_sz );
    break;

  default:
    FD_LOG_WARNING(( "invalid crds type found " ));
  }

  return parse_status;
}

int
fd_gossip_read_socketaddr( fd_bin_parse_ctx_t * ctx,
                           fd_socketaddr_t    * socketaddr ) {

  uint addr_type = 0;
  if( !fd_bin_parse_read_u32( ctx, &addr_type) ) {
    FD_LOG_WARNING(( "unable to read `variant_index`" ));
    return 0;
  }

  switch( addr_type ) {
  case FD_SOCKETADDR_IPV4: {
    socketaddr->fam = FD_SOCKETADDR_IPV4;
    if( !fd_bin_parse_read_blob_of_size( ctx, 4, &(socketaddr->addr.ipv4_sin_addr.s_addr) ) ) {
        FD_LOG_WARNING(( "error parsing ipv4 addr" ));
        return 0;
    }
    break;
  }

  case FD_SOCKETADDR_IPV6:  {
    socketaddr->fam = FD_SOCKETADDR_IPV6;
    if( !fd_bin_parse_read_blob_of_size( ctx, 16, &(socketaddr->addr.ipv6_sin_addr.__in6_u) ) ) {
        FD_LOG_WARNING(( "error parsing ipv6 addr" ));
        return 0;
    }
    break;
  }

  default:
    FD_LOG_WARNING(( "invalid address type (neither ipv4 nor ipv6)" ));
    return 0;
  }

  if( !fd_bin_parse_read_u16( ctx, &(socketaddr->port) ) ) {
    FD_LOG_WARNING(( "error reading port number" ));
    return 0;
  }

  return 1;
}

int
fd_bin_parse_decode_socket_entry_vector( fd_bin_parse_ctx_t * ctx,
                                         void       * out_buf,
                                         ulong        out_buf_sz,
                                         ulong      * nelems        ) {
  ushort vector_sz_short_tmp = 0;

  /* vec<SocketEntry> in ContactInfo is encoded as a short_vec, hence this length value is
     encoded as a varint with max value USHORT_MAX. */
  if( !fd_bin_parse_read_varint_u16( ctx, &vector_sz_short_tmp ) ) {
    FD_LOG_WARNING(( "failed to read u64 as vector size" ));
    return 0;
  }

  ulong vector_sz = (ulong)vector_sz_short_tmp;

  /* check for enough space in the destination for the number of `fd_gossip_socketentry_t` to be decoded */
  if( FD_UNLIKELY( (vector_sz*sizeof( fd_gossip_socketentry_t ) )>out_buf_sz ) ) {
    FD_LOG_WARNING(( "dst size exceeded" ));
    return 0;
  }

  /* check for integer overflow wrap and bail out if so */
  if( FD_UNLIKELY( (vector_sz*sizeof( fd_gossip_socketentry_t ))<vector_sz ) ) {
    FD_LOG_WARNING(( "overflow in int overflow protection arithmetic" ));
    return 0;
  }

  uchar * ptr = (uchar *)out_buf;

  /* we now attempt to read `vector_sz` number of elements from the slice,
     each of length `type_sz`. we already bounds checked vs. size of dest buffer above. */
  fd_gossip_socketentry_t * socket_entry = NULL;
  for( ulong i = 0; i<vector_sz; i++ ) {
    socket_entry = (fd_gossip_socketentry_t *)DST_CUR;
    if( !fd_bin_parse_read_u8( ctx, &(socket_entry->key) ) ) {
      FD_LOG_WARNING(( "failed to read u8 as socket_entry `key`" ));
      return 0;
    }

    if( !fd_bin_parse_read_u8( ctx, &(socket_entry->index) ) ) {
      FD_LOG_WARNING(( "failed to read u8 as socket_entry `index`" ));
      return 0;
    }

    if( !fd_bin_parse_read_varint_u16( ctx, &(socket_entry->offset) ) ) {
      FD_LOG_WARNING(( "failed to read varint as socket_entry `offset`" ));
      return 0;
    }
    ADVANCE_DST_PTR( sizeof( fd_gossip_socketentry_t ) );
  }

  *nelems = vector_sz;
  return 1;
}

int
fd_bin_parse_decode_ipaddr_entry_vector( fd_bin_parse_ctx_t * ctx,
                                         void       * out_buf,
                                         ulong        out_buf_sz,
                                         ulong      * nelems       ) {
  ushort vector_sz_short_tmp = 0;

  /* vec<IpAddr> in ContactInfo is encoded as a short_vec, hence the vector length is
   * a varint, max USHORT_MAX. */
  if( !fd_bin_parse_read_varint_u16( ctx, &vector_sz_short_tmp ) ) {
    FD_LOG_WARNING(( "failed to read u64 as vector size" ));
    return 0;
  }

  ulong vector_sz = (ulong)vector_sz_short_tmp;

  /* check for enough space in the destination for the number of `fd_gossip_socketentry_t` to be decoded */
  if( FD_UNLIKELY( (vector_sz*sizeof( fd_ipaddr_t ) )>out_buf_sz ) ) {
    FD_LOG_WARNING(( "dst size exceeded: %lu", vector_sz ));
    return 0;
  }

  /* check for integer overflow wrap and bail out if so */
  if( FD_UNLIKELY( (vector_sz*sizeof( fd_ipaddr_t ))<vector_sz ) ) {
    FD_LOG_WARNING(( "overflow in int overflow protection arithmetic" ));
    return 0;
  }

  uchar * ptr = (uchar *)out_buf;

  fd_ipaddr_t * ipaddr = NULL;
  for( ulong i = 0; i<vector_sz; i++ ) {
    ipaddr = (fd_ipaddr_t *)DST_CUR;
    uint addr_type = 0;
    if( !fd_bin_parse_read_u32( ctx, &addr_type) ) {
      FD_LOG_WARNING(( "unable to read `addr_type`" ));
      return 0;
    }

    switch( addr_type ) {
    case FD_SOCKETADDR_IPV4: {
      ipaddr->fam = FD_SOCKETADDR_IPV4;
      if( !fd_bin_parse_read_blob_of_size( ctx, 4, &(ipaddr->addr.ipv4_sin_addr.s_addr) ) ) {
        FD_LOG_WARNING(( "error parsing ipv4 addr" ));
        return 0;
      }
      break;
    }

    case FD_SOCKETADDR_IPV6:  {
      ipaddr->fam = FD_SOCKETADDR_IPV6;
      if( !fd_bin_parse_read_blob_of_size( ctx, 16, &(ipaddr->addr.ipv6_sin_addr.__in6_u) ) ) {
        FD_LOG_WARNING(( "error parsing ipv6 addr" ));
        return 0;
      }
      break;
    }

    default:
      FD_LOG_WARNING(( "invalid address type (neither ipv4 nor ipv6)" ));
      return 0;
  } 

  ADVANCE_DST_PTR( sizeof( fd_ipaddr_t ) );
  }

  *nelems = vector_sz;
  return 1;
}

int
fd_bin_parse_decode_slot_hash_vector( fd_bin_parse_ctx_t * ctx,
                                      void       * out_buf,
                                      ulong        out_buf_sz,
                                      ulong      * nelems        ) {
  ulong vector_sz = 0;
  if( !fd_bin_parse_read_u64( ctx, &vector_sz ) ) {
    FD_LOG_WARNING(( "failed to read u64 as vector size" ));
    return 0;
  }

  /* check for enough space in the destination for the number of `fd_gossip_socketentry_t` to be decoded */
  if( FD_UNLIKELY( (vector_sz*sizeof( fd_gossip_crds_slot_hash_t ) )>out_buf_sz ) ) {
    FD_LOG_WARNING(( "dst size exceeded" ));
    return 0;
  }

  /* check for integer overflow wrap and bail out if so */
  if( FD_UNLIKELY( (vector_sz*sizeof( fd_gossip_crds_slot_hash_t ))<vector_sz ) ) {
    FD_LOG_WARNING(( "overflow in int overflow protection arithmetic" ));
    return 0;
  }

  uchar * ptr = (uchar *)out_buf;

  /* we now attempt to read `vector_sz` number of elements from the slice,
     each of length `type_sz`. we already bounds checked vs. size of dest buffer above. */
  fd_gossip_crds_slot_hash_t * slot_hash = NULL;
  for( ulong i = 0; i<vector_sz; i++ ) {
    slot_hash = (fd_gossip_crds_slot_hash_t *)DST_CUR;
    if( !fd_bin_parse_read_u64( ctx, &(slot_hash->slot) ) ) {
      FD_LOG_WARNING(( "unable to parse `SlotHash.Slot`" ));
      return 0;
    }

    CHECK_SLOT( slot_hash->slot );

    if( !fd_bin_parse_read_blob_of_size( ctx, 32, &(slot_hash->hash) ) ) {
      FD_LOG_WARNING(( "unable to parse `SlotHash.Hash`" ));
      return 0;
    }
    ADVANCE_DST_PTR( sizeof( fd_gossip_crds_slot_hash_t ) );
  }

  *nelems = vector_sz;
  return 1;
}

int
fd_gossip_parse_crds_legacy_contact_info( fd_bin_parse_ctx_t * ctx,
                                          void               * out_buf,
                                          ulong                out_buf_sz,
                                          ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing LegacyContactInfo" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_legacy_contact_info_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_legacy_contact_info_t * contact_info = (fd_gossip_crds_value_legacy_contact_info_t *)out_buf;
  contact_info->hdr.crds_id = FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO;

  if( !fd_bin_parse_read_pubkey( ctx, &(contact_info->data.id) ) ) {
    FD_LOG_WARNING(( "unable to parse pubkey" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.gossip) ) ) {
    FD_LOG_WARNING(( "unable to parse `gossip` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.tvu) ) ) {
    FD_LOG_WARNING(( "unable to parse `tvu` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.tvu_fwd) ) ) {
    FD_LOG_WARNING(( "unable to parse `tvu_fwd` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.repair) ) ) {
    FD_LOG_WARNING(( "unable to parse `repair` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.tpu) ) ) {
    FD_LOG_WARNING(( "unable to parse `tpu` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.tpu_fwd) ) ) {
    FD_LOG_WARNING(( "unable to parse `tpu_fwd` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.tpu_vote) ) ) {
    FD_LOG_WARNING(( "unable to parse `tpu_vote` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.rpc) ) ) {
    FD_LOG_WARNING(( "unable to parse `rpc` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.rpc_pub_sub) ) ) {
    FD_LOG_WARNING(( "unable to parse `rpc_pub_sub` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_read_socketaddr( ctx, &(contact_info->data.serve_repair) ) ) {
    FD_LOG_WARNING(( "unable to parse `serve_repair` socketaddr" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(contact_info->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( contact_info->data.wallclock );

  if( !fd_bin_parse_read_u16( ctx, &(contact_info->data.shred_version) ) ) {
    FD_LOG_WARNING(( "unable to parse `shred_version`" ));
    return 0;
  }

  *obj_sz = contact_info->hdr.obj_sz = sizeof( fd_gossip_crds_value_legacy_contact_info_t );
  return 1;
}

int
fd_gossip_parse_crds_legacy_version( fd_bin_parse_ctx_t * ctx,
                                     void               * out_buf,
                                     ulong                out_buf_sz,
                                     ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing LegacyVersion" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_legacy_version_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_legacy_version_t * legacy_version = (fd_gossip_crds_value_legacy_version_t *)out_buf;
  legacy_version->hdr.crds_id = FD_GOSSIP_CRDS_ID_LEGACY_VERSION;

  if( !fd_bin_parse_read_pubkey( ctx, &(legacy_version->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(legacy_version->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( legacy_version->data.wallclock );

  if( !fd_bin_parse_read_u16( ctx, &(legacy_version->data.major) ) ) {
    FD_LOG_WARNING(( "unable to parse `major`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u16( ctx, &(legacy_version->data.minor) ) ) {
    FD_LOG_WARNING(( "unable to parse `minor`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u16( ctx, &(legacy_version->data.patch) ) ) {
    FD_LOG_WARNING(( "unable to parse `patch`" ));
    return 0;
  }

  if( !fd_bin_parse_read_option_u32( ctx, (uint *)&(legacy_version->data.commit) ) ) {
    FD_LOG_WARNING(( "unable to parse `commit`" ));
    return 0;
  }

  *obj_sz = legacy_version->hdr.obj_sz = sizeof( fd_gossip_crds_value_legacy_version_t );
  return 1;
}

int
fd_gossip_parse_crds_version( fd_bin_parse_ctx_t * ctx,
                              void               * out_buf,
                              ulong                out_buf_sz,
                              ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing Version" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_version_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_version_t * version = (fd_gossip_crds_value_version_t *)out_buf;
  version->hdr.crds_id = FD_GOSSIP_CRDS_ID_VERSION;

  if( !fd_bin_parse_read_pubkey( ctx, &(version->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(version->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( version->data.wallclock );

  if( !fd_bin_parse_read_u16( ctx, &(version->data.major) ) ) {
    FD_LOG_WARNING(( "unable to parse `major`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u16( ctx, &(version->data.minor) ) ) {
    FD_LOG_WARNING(( "unable to parse `minor`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u16( ctx, &(version->data.patch) ) ) {
    FD_LOG_WARNING(( "unable to parse `patch`" ));
    return 0;
  }

  if( !fd_bin_parse_read_option_u32( ctx, (uint *)&(version->data.commit) ) ) {
    FD_LOG_WARNING(( "unable to parse `commit`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u32( ctx, &(version->data.features) ) ) {
    FD_LOG_WARNING(( "unable to parse `features`" ));
    return 0;
  }

  *obj_sz = version->hdr.obj_sz = sizeof( fd_gossip_crds_value_version_t );
  return 1;
}

int
fd_gossip_parse_crds_node_instance( fd_bin_parse_ctx_t * ctx,
                                    void               * out_buf,
                                    ulong                out_buf_sz,
                                    ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing NodeInstance" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_node_instance_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_node_instance_t * node_instance = (fd_gossip_crds_value_node_instance_t *)out_buf;
  node_instance->hdr.crds_id = FD_GOSSIP_CRDS_ID_NODE_INSTANCE;

  if( !fd_bin_parse_read_pubkey( ctx, &(node_instance->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(node_instance->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( node_instance->data.wallclock );

  if( !fd_bin_parse_read_u64( ctx, &(node_instance->data.timestamp) ) ) {
    FD_LOG_WARNING(( "unable to parse `timestamp`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(node_instance->data.token) ) ) {
    FD_LOG_WARNING(( "unable to parse `token`" ));
    return 0;
  }

  *obj_sz = node_instance->hdr.obj_sz = sizeof( fd_gossip_crds_value_node_instance_t );
  return 1;
}

int
fd_gossip_parse_crds_incremental_snapshot_hashes( fd_bin_parse_ctx_t * ctx,
                                                  void               * out_buf,
                                                  ulong                out_buf_sz,
                                                  ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing IncrementalSnapshotHashes" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_incremental_snapshot_hashes_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_incremental_snapshot_hashes_t * incr_snapshot_hashes = (fd_gossip_crds_value_incremental_snapshot_hashes_t *)out_buf;
  incr_snapshot_hashes->hdr.crds_id = FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES;

  if( !fd_bin_parse_read_pubkey( ctx, &(incr_snapshot_hashes->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(incr_snapshot_hashes->data.base.slot) ) ) {
    FD_LOG_WARNING(( "unable to parse `SlotHash.Slot`" ));
    return 0;
  }

  CHECK_SLOT( incr_snapshot_hashes->data.base.slot );

  if( !fd_bin_parse_read_blob_of_size( ctx, 32, &(incr_snapshot_hashes->data.base.hash) ) ) {
    FD_LOG_WARNING(( "unable to parse `SlotHash.Hash`" ));
    return 0;
  }

  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_crds_value_incremental_snapshot_hashes_t );
  ulong nelems;

  if( !fd_bin_parse_decode_slot_hash_vector( ctx, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error parsing SlotHash vector `hashes`" ));
    return 0;
  }

  /* setup vector struct for this data */
  incr_snapshot_hashes->data.hashes.num_objs = nelems;
  incr_snapshot_hashes->data.hashes.offset = CUR_DATA_OFFSET;
  ADVANCE_DST_PTR( nelems*sizeof( fd_gossip_crds_slot_hash_t ) );

  if( !fd_bin_parse_read_u64( ctx, &(incr_snapshot_hashes->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( incr_snapshot_hashes->data.wallclock );

  *obj_sz = incr_snapshot_hashes->hdr.obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_crds_duplicate_shred( fd_bin_parse_ctx_t * ctx,
                                      void               * out_buf,
                                      ulong                out_buf_sz,
                                      ulong              * obj_sz      ) {
  FD_LOG_NOTICE(( "parsing DuplicateShred" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_duplicate_shred_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_duplicate_shred_t * duplicate_shred = (fd_gossip_crds_value_duplicate_shred_t *)out_buf;
  duplicate_shred->hdr.crds_id = FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED;

  if( !fd_bin_parse_read_u16( ctx, &(duplicate_shred->data.index) ) ) {
    FD_LOG_WARNING(( "unable to parse `index`" ));
    return 0;
  }

  CHECK_DUPLICATE_SHRED_INDEX( duplicate_shred->data.index );

  if( !fd_bin_parse_read_pubkey( ctx, &(duplicate_shred->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(duplicate_shred->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( duplicate_shred->data.wallclock );

  if( !fd_bin_parse_read_u64( ctx, &(duplicate_shred->data.slot) ) ) {
    FD_LOG_WARNING(( "unable to parse `slot`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u32( ctx, &(duplicate_shred->data.shred_index) ) ) {
    FD_LOG_WARNING(( "unable to parse `shred_index`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u8( ctx, &(duplicate_shred->data.shred_type) ) ) {
    FD_LOG_WARNING(( "unable to parse `shred_type`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u8( ctx, &(duplicate_shred->data.num_chunks) ) ) {
    FD_LOG_WARNING(( "unable to parse `num_chunks`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u8( ctx, &(duplicate_shred->data.chunk_index) ) ) {
    FD_LOG_WARNING(( "unable to parse `chunk_index`" ));
    return 0;
  }

  if( duplicate_shred->data.chunk_index>=duplicate_shred->data.num_chunks ) {
    FD_LOG_WARNING(( "invalid `chunk_index` value" ));
    return 0;
  }

  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_crds_value_duplicate_shred_t );
  ulong nelems;

  if( !fd_bin_parse_decode_vector( ctx, 1, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error parsing u8 vector `chunk`" ));
    return 0;
  }

  /* setup vector struct for this data */
  duplicate_shred->data.chunk.num_objs = nelems;
  duplicate_shred->data.chunk.offset = CUR_DATA_OFFSET;
  ADVANCE_DST_PTR( nelems*1 );

  *obj_sz = duplicate_shred->hdr.obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_crds_lowest_slot( fd_bin_parse_ctx_t * ctx,
                                  void               * out_buf,
                                  ulong                out_buf_sz,
                                  ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing LowestSlot" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_lowest_slot_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_lowest_slot_t * lowest_slot = (fd_gossip_crds_value_lowest_slot_t *)out_buf;
  lowest_slot->hdr.crds_id = FD_GOSSIP_CRDS_ID_LOWEST_SLOT;

  if( !fd_bin_parse_read_u8( ctx, &(lowest_slot->data.index) ) ) {
    FD_LOG_WARNING(( "unable to parse `index`" ));
    return 0;
  }

  CHECK_LOWEST_SLOT_INDEX( lowest_slot->data.index );

  if( !fd_bin_parse_read_pubkey( ctx, &(lowest_slot->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(lowest_slot->data.root) ) ) {
    FD_LOG_WARNING(( "unable to parse `root`" ));
    return 0;
  }

  if( lowest_slot->data.root ) {
    FD_LOG_WARNING(( "invalid `root` value" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(lowest_slot->data.lowest) ) ) {
    FD_LOG_WARNING(( "unable to parse `lowest`" ));
    return 0;
  }

  CHECK_SLOT( lowest_slot->data.lowest );
  
  /* the `slots` and `stash` vectors are deprecated and fail validation in the Rust
     validator implementation if they are non-empty, so we don't even bother decoding
     these vectors, and instead just fail if their size field is non-zero. */
  ulong nelems = 0;
  if( !fd_bin_parse_read_u64( ctx, &nelems ) ) {
    FD_LOG_WARNING(( "unable to parse size for `slots` vector" ));
    return 0;
  }

  if( nelems ) {
    FD_LOG_WARNING(( "`slots` vector is deprecated and must be empty" ));
    return 0;
  }

  /* stash vector. this is deprecated and appears to be unused */
  if( !fd_bin_parse_read_u64( ctx, &nelems ) ) {
    FD_LOG_WARNING(( "unable to parse `stash` u64 length" ));
    return 0;
  }

  if( nelems ) {
    FD_LOG_WARNING(( "`stash` vector is deprecated and must be empty" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(lowest_slot->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( lowest_slot->data.wallclock );

  *obj_sz = lowest_slot->hdr.obj_sz = sizeof( fd_gossip_crds_value_lowest_slot_t );
  return 1;                      
}

int
fd_gossip_parse_crds_snapshot_hashes( fd_bin_parse_ctx_t * ctx,
                                      void               * out_buf,
                                      ulong                out_buf_sz,
                                      ulong              * obj_sz      ) {
  FD_LOG_NOTICE(( "parsing SnapshotHashes" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_snapshot_hashes_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_snapshot_hashes_t * snapshot_hashes = (fd_gossip_crds_value_snapshot_hashes_t *)out_buf;
  snapshot_hashes->hdr.crds_id = FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES;

  if( !fd_bin_parse_read_pubkey( ctx, &(snapshot_hashes->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  /* deserialize `hashes` ( slot_hash[] )*/
  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_crds_value_snapshot_hashes_t );
  ulong nelems;

  /* parse vector of SlotHash's */
  if( !fd_bin_parse_decode_slot_hash_vector( ctx, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error parsing SlotHash vector `hashes`" ));
    return 0;
  }

  /* setup vector struct for this data */
  snapshot_hashes->data.hashes.num_objs = nelems;
  snapshot_hashes->data.hashes.offset = CUR_DATA_OFFSET;

  ADVANCE_DST_PTR( nelems*sizeof( fd_gossip_crds_slot_hash_t ) );

  /* wallclock */
  if( !fd_bin_parse_read_u64( ctx, &(snapshot_hashes->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( snapshot_hashes->data.wallclock );

  *obj_sz = snapshot_hashes->hdr.obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_crds_account_hashes( fd_bin_parse_ctx_t * ctx,
                                     void               * out_buf,
                                     ulong                out_buf_sz,
                                     ulong              * obj_sz      ) {
  return fd_gossip_parse_crds_snapshot_hashes( ctx, out_buf, out_buf_sz, obj_sz );
}

int
fd_gossip_parse_crds_vote( fd_bin_parse_ctx_t * ctx,
                           void               * out_buf,
                           ulong                out_buf_sz,
                           ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing Vote" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_vote_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_vote_t * vote = (fd_gossip_crds_value_vote_t *)out_buf;
  vote->hdr.crds_id = FD_GOSSIP_CRDS_ID_VOTE;

  if( !fd_bin_parse_read_u8( ctx, &(vote->data.index) ) ) {
    FD_LOG_WARNING(( "unable to parse `index`" ));
    return 0;
  }

  CHECK_VOTE_INDEX( vote->data.index );

  if( !fd_bin_parse_read_pubkey( ctx, &(vote->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  ulong num_raw_txn_bytes_consumed = 0;
  uchar * ptr = (uchar *)out_buf + sizeof ( fd_gossip_crds_value_vote_t );

  /* parse transaction */
  ulong txn_sz = fd_txn_parse( (uchar const *)fd_bin_parse_get_cur_src( ctx ), fd_bin_parse_src_size_remaining( ctx ), DST_CUR, NULL, &num_raw_txn_bytes_consumed );
  if( !txn_sz ) {
    FD_LOG_WARNING(( "error parsing transaction. bytes consumed: %lu", num_raw_txn_bytes_consumed ));
    return 0;
  }

  /* transaction is valid. set the data up as a vector descriptor in the form [fd_txn_t struct][raw_txn_payload] */
  vote->data.transaction.offset = CUR_DATA_OFFSET;
  ADVANCE_DST_PTR( txn_sz );
  if( DST_BYTES_REMAINING < num_raw_txn_bytes_consumed ) {
    FD_LOG_WARNING(( "not enough room left in destination for raw tx payload" ));
    return 0;
  }
  fd_memcpy( DST_CUR, fd_bin_parse_get_cur_src( ctx ), num_raw_txn_bytes_consumed );
  vote->data.transaction.num_objs = txn_sz + num_raw_txn_bytes_consumed;
  ADVANCE_DST_PTR( num_raw_txn_bytes_consumed );

  /* move the src cursor beyond the transaction blob */
  fd_slice_increment_slice( &(ctx->src), num_raw_txn_bytes_consumed );

  if( !fd_bin_parse_read_u64( ctx, &(vote->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( vote->data.wallclock );
  
  /* This optional 'slot' field appears to be gone now */
  /*if( !fd_bin_parse_read_option_u64( ctx, (ulong *)&(vote->data.slot) ) ) {
    FD_LOG_WARNING(( "unable to parse optional `slot`" ));
    return 0;
  }*/

  *obj_sz = vote->hdr.obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_crds_compressed_slots( fd_bin_parse_ctx_t * ctx,
                                       void               * out_buf,
                                       ulong                out_buf_sz,
                                       ulong              * obj_sz      ) {

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_compressed_slots_t ) ) ) {
    FD_LOG_WARNING(( "dest buffer too small for compressed slots" ));
    return 0;
  }

  fd_gossip_crds_compressed_slots_t * compressed_slots = (fd_gossip_crds_compressed_slots_t *)out_buf;

  uint variant_type = 0;
  if( !fd_bin_parse_read_u32( ctx, &variant_type ) ) {
    FD_LOG_WARNING(( "unable to read variant_type" ));
    return 0;
  }

  if ( !fd_bin_parse_read_u64( ctx, &(compressed_slots->first_slot) ) ) {
    FD_LOG_WARNING(( "error reading `first_slot`" ));
    return 0;
  }

  CHECK_SLOT( compressed_slots->first_slot );

  if ( !fd_bin_parse_read_u64( ctx, &(compressed_slots->num) ) ) {
    FD_LOG_WARNING(( "error reading `num`" ));
    return 0;
  }

  if( compressed_slots->num>=FD_GOSSIP_CRDS_MAX_SLOTS_PER_ENTRY ) {
    FD_LOG_WARNING(( "invalid `num` value" ));
    return 0;
  }

  ulong nelems = 0;
  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_crds_compressed_slots_t );

  switch( variant_type ) {

  case FD_GOSSIP_COMPRESSION_TYPE_FLATE2:  {
    compressed_slots->type = FD_GOSSIP_COMPRESSION_TYPE_FLATE2;
    if( !fd_bin_parse_decode_vector( ctx, 1, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
      FD_LOG_WARNING(( "error parsing compressed u8 vector" ));
      return 0;
    }
    compressed_slots->compressed.num_objs = nelems;
    compressed_slots->compressed.offset = CUR_DATA_OFFSET;
    ADVANCE_DST_PTR( nelems*1 );
    break;
  }

  case FD_GOSSIP_COMPRESSION_TYPE_UNCOMPRESSED: {
    compressed_slots->type = FD_GOSSIP_COMPRESSION_TYPE_UNCOMPRESSED;
    
    /* deserialize bitvec */
    if( !fd_bin_parse_decode_option_vector( ctx, 1, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
      FD_LOG_WARNING(( "error decoding option vector for bitvec64" ));
      return 0;
    }

    /* this is an optional vector; no data in this case. */
    if( nelems==0 ) {
      compressed_slots->slots.bits.num_objs = 0;
      compressed_slots->slots.bits.offset = 0;
    } else {
    /* setup vector struct for this data */
      compressed_slots->slots.bits.num_objs = nelems;
      compressed_slots->slots.bits.offset = CUR_DATA_OFFSET;
      ADVANCE_DST_PTR( nelems*1 );
    }

    if( !fd_bin_parse_read_u64( ctx, &(compressed_slots->slots.len) ) ) {
      FD_LOG_WARNING(( "error parsing bloom bitvec `Len`" ));
      return 0;
    }
    break;
  }

  default:
    FD_LOG_WARNING(( "invalid compression type" ));
    return 0;
  }
  
  *obj_sz = compressed_slots->obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_crds_epoch_slots( fd_bin_parse_ctx_t * ctx,
                                  void               * out_buf,
                                  ulong                out_buf_sz,
                                  ulong              * obj_sz      ) {
  FD_LOG_NOTICE(( "parsing EpochSlots" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_epoch_slots_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_epoch_slots_t * epoch_slots = (fd_gossip_crds_value_epoch_slots_t *)out_buf;
  epoch_slots->hdr.crds_id = FD_GOSSIP_CRDS_ID_EPOCH_SLOTS;

  if( !fd_bin_parse_read_u8( ctx, &(epoch_slots->data.index) ) ) {
    FD_LOG_WARNING(( "unable to parse `index`" ));
    return 0;
  }

  CHECK_EPOCH_SLOTS_INDEX( epoch_slots->data.index );

  if( !fd_bin_parse_read_pubkey( ctx, &(epoch_slots->data.from) ) ) {
    FD_LOG_WARNING(( "unable to parse `from`" ));
    return 0;
  }

  /* deserialize vector of CompressedSlot, i.e. vec<CompressedSlot> */
  /* get size of vector */
  ulong nelems = 0;
  if( !fd_bin_parse_read_u64(ctx, &nelems ) ) {
    FD_LOG_WARNING(( "error reading len of CompressedSlot vector "));
    return 0;
  }

  /* TODO(smcio): although the boundedness of the logic below ultimately kicks out
     overly large `nelems` u64 vector sizes, it might still be worth logging such an 
     anomalous case explicitly in the interests of completeness/debugging purposes/audit. 
     If so, determine an upper limit upon which to trigger a log event. */

  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_crds_value_epoch_slots_t );
  epoch_slots->data.compressed_slots.num_objs = 0;
  ulong compressed_slots_obj_sz = 0;

  for( ulong count=0; count<nelems; count++ ) {
    if( !fd_gossip_parse_crds_compressed_slots( ctx, DST_CUR, DST_BYTES_REMAINING, &compressed_slots_obj_sz ) ) {
      FD_LOG_WARNING(( "error decoding CompressedSlots object" ));
      return 0;
    }

    if( count==0 ) {
      epoch_slots->data.compressed_slots.offset = CUR_DATA_OFFSET;
    }

    epoch_slots->data.compressed_slots.num_objs++;
    ADVANCE_DST_PTR( compressed_slots_obj_sz );
  }

  if( !fd_bin_parse_read_u64( ctx, &(epoch_slots->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( epoch_slots->data.wallclock );

  *obj_sz = epoch_slots->hdr.obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_crds_contact_info( fd_bin_parse_ctx_t * ctx,
                                   void               * out_buf,
                                   ulong                out_buf_sz,
                                   ulong              * obj_sz      ) {

  FD_LOG_NOTICE(( "parsing ContactInfo" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_crds_value_contact_info_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_value_contact_info_t * contact_info = (fd_gossip_crds_value_contact_info_t *)out_buf;
  contact_info->hdr.crds_id = FD_GOSSIP_CRDS_ID_CONTACT_INFO;

  if( !fd_bin_parse_read_pubkey( ctx, &(contact_info->data.pubkey) ) ) {
    FD_LOG_WARNING(( "unable to parse pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_read_varint_u64( ctx, &(contact_info->data.wallclock) ) ) {
    FD_LOG_WARNING(( "unable to parse varint `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( contact_info->data.wallclock );

  if( !fd_bin_parse_read_u64( ctx, &(contact_info->data.outset) ) ) {
    FD_LOG_WARNING(( "unable to parse `outset`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u16( ctx, &(contact_info->data.shred_version) ) ) {
    FD_LOG_WARNING(( "unable to parse `shred_version`" ));
    return 0;
  }

  /* deserialize `Version` object embedded in this ContactInfo object.
     some fields are varint encoded. */
  if( !fd_bin_parse_read_varint_u16( ctx, &(contact_info->data.version.major) ) ) {
    FD_LOG_WARNING(( "unable to parse varint `version.major`" ));
    return 0;
  }

  if( !fd_bin_parse_read_varint_u16( ctx, &(contact_info->data.version.minor) ) ) {
    FD_LOG_WARNING(( "unable to parse varint `version.minor`" ));
    return 0;
  }

  if( !fd_bin_parse_read_varint_u16( ctx, &(contact_info->data.version.patch) ) ) {
    FD_LOG_WARNING(( "unable to parse varint `version.patch`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u32( ctx, &(contact_info->data.version.commit) ) ) {
    FD_LOG_WARNING(( "unable to parse `version.commit`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u32( ctx, &(contact_info->data.version.feature_set) ) ) {
    FD_LOG_WARNING(( "unable to parse `version.feature_set`" ));
    return 0;
  }

  if( !fd_bin_parse_read_varint_u16( ctx, &(contact_info->data.version.client) ) ) {
    FD_LOG_WARNING(( "unable to parse varint `version.client`" ));
    return 0;
  }

  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_crds_value_contact_info_t );
  ulong nelems = 0;

  /* decode addrs vector, vec<IpAddr> */
  if ( !fd_bin_parse_decode_ipaddr_entry_vector( ctx, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error decoding ipaddr vector" ));
    return 0;
  }

  contact_info->data.addrs.num_objs = nelems;
  contact_info->data.addrs.offset = CUR_DATA_OFFSET;
  ADVANCE_DST_PTR( nelems*sizeof( fd_ipaddr_t ) );

  /* decode `sockets`, i.e. vec<SocketEntry> */
  if( !fd_bin_parse_decode_socket_entry_vector( ctx, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error decoding SocketEntry vector" ));
    return 0;
  }

  contact_info->data.sockets.num_objs = nelems;
  contact_info->data.sockets.offset = CUR_DATA_OFFSET;
  ADVANCE_DST_PTR( nelems*sizeof( fd_gossip_socketentry_t ) );

  *obj_sz = contact_info->hdr.obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}
