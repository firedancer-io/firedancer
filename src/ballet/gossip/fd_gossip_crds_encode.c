#include "fd_gossip_crds.h"
#include "fd_gossip_vector_utils.h"
#include "fd_gossip_validation.h"

/* Logic for encoding CRDS structs into on-the-wire format for transmission across the network */

int
fd_gossip_encode_crds_obj( fd_bin_parse_ctx_t * ctx,
                           void               * in_buf,
                           ulong                in_buf_sz,
                           ulong              * bytes_consumed      ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_header_t ) ) ) {
    return 0;
  }

  fd_gossip_crds_header_t * header = (fd_gossip_crds_header_t *)in_buf;
  int encode_status = 0;

  switch( header->crds_id ) {
  case FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO:
    encode_status = fd_gossip_encode_crds_legacy_contact_info( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_VOTE:
    encode_status = fd_gossip_encode_crds_vote( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_LOWEST_SLOT:
    encode_status = fd_gossip_encode_crds_lowest_slot( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES:
    encode_status = fd_gossip_encode_crds_snapshot_hashes( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_ACCOUNT_HASHES:
    encode_status = fd_gossip_encode_crds_snapshot_hashes( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_EPOCH_SLOTS:
    encode_status = fd_gossip_encode_crds_epoch_slots( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_LEGACY_VERSION:
    encode_status = fd_gossip_encode_crds_legacy_version( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_VERSION:
    encode_status = fd_gossip_encode_crds_version( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_NODE_INSTANCE:
    encode_status = fd_gossip_encode_crds_node_instance( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED:
    encode_status = fd_gossip_encode_crds_duplicate_shred( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES:
    encode_status = fd_gossip_encode_crds_incremental_snapshot_hashes( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  case FD_GOSSIP_CRDS_ID_CONTACT_INFO:
    encode_status = fd_gossip_encode_crds_contact_info( ctx, in_buf, in_buf_sz, bytes_consumed );
    break;

  default:
    FD_LOG_WARNING(( "trying to serialize unimplemented CRDS object type - programming error" ));
    break;
  }

  return encode_status;
}

int
fd_gossip_write_socketaddr( fd_bin_parse_ctx_t * ctx,
                            fd_socketaddr_t    * socketaddr ) {

  /* address family, i.e. IPv4 or IPv6 */
  if( !fd_bin_parse_write_u32( ctx, socketaddr->fam ) ) {
    FD_LOG_WARNING(( "error writing socket addr family to blob" ));
    return 0;
  }

  ulong addr_len = 0;
  if( socketaddr->fam == FD_SOCKETADDR_IPV4 ) {
    addr_len = FD_ADDR_LEN_IPV4;
  } else if( socketaddr->fam == FD_SOCKETADDR_IPV6 ) {
    addr_len = FD_ADDR_LEN_IPV6;
  } else {
    FD_LOG_WARNING(( "address family was neither IPv4 nor IPv6 - programming error." ));
    return 0;
  }

  /* write out address */
  if( !fd_bin_parse_write_blob_of_size( ctx, &(socketaddr->addr), addr_len ) ) {
    FD_LOG_WARNING(( "unable to write socketaddr address to blob" ));
    return 0;
  }

  /* write out port */
  if( !fd_bin_parse_write_u16( ctx, socketaddr->port ) ) {
    FD_LOG_WARNING(( "error writing port out to blob" ));
    return 0;
  }

  return 1;
}

int
fd_gossip_encode_crds_legacy_contact_info( fd_bin_parse_ctx_t * ctx,
                                           void               * in_buf,
                                           ulong                in_buf_sz,
                                           ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_legacy_contact_info_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy contactinfo struct" ));
    return 0;
  }

  fd_gossip_crds_value_legacy_contact_info_t * legacy_contact_info = (fd_gossip_crds_value_legacy_contact_info_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(legacy_contact_info->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey( ctx, &(legacy_contact_info->data.id) ) ) {
    FD_LOG_WARNING(( "unable to write `id` pubkey to blob" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.gossip) ) ) {
    FD_LOG_WARNING(( "unable to write out `gossip` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.tvu) ) ) {
    FD_LOG_WARNING(( "unable to write out `tvu` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.tvu_fwd) ) ) {
    FD_LOG_WARNING(( "unable to write out `tvu_fwd` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.repair) ) ) {
    FD_LOG_WARNING(( "unable to write out `repair` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.tpu) ) ) {
    FD_LOG_WARNING(( "unable to write out `tpu` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.tpu_fwd) ) ) {
    FD_LOG_WARNING(( "unable to write out `tpu_fwd` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.tpu_vote) ) ) {
    FD_LOG_WARNING(( "unable to write out `tpu_vote` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.rpc) ) ) {
    FD_LOG_WARNING(( "unable to write out `rpc` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.rpc_pub_sub) ) ) {
    FD_LOG_WARNING(( "unable to write out `rpc_pub_sub` socketaddr" ));
    return 0;
  }

  if( !fd_gossip_write_socketaddr( ctx, &(legacy_contact_info->data.serve_repair) ) ) {
    FD_LOG_WARNING(( "unable to write out `serve_repair` socketaddr" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, legacy_contact_info->data.wallclock ) ) {
    FD_LOG_WARNING(( "unable to write `wallclock` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, legacy_contact_info->data.shred_version ) ) {
    FD_LOG_WARNING(( "unable to write `shred_version` to blob" ));
    return 0;
  }

  *bytes_consumed = legacy_contact_info->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_vote( fd_bin_parse_ctx_t * ctx,
                            void               * in_buf,
                            ulong                in_buf_sz,
                            ulong              * bytes_consumed ) {
  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_vote_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than vote struct" ));
    return 0;
  }

  fd_gossip_crds_value_vote_t * vote = (fd_gossip_crds_value_vote_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(vote->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_VOTE ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u8( ctx, vote->data.index ) ) {
    FD_LOG_WARNING(( "unable to write `index` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey( ctx, &(vote->data.from ) ) ) {
    FD_LOG_WARNING(( "unable to write `pubkey` out to blob" ));
    return 0;
  }

  /* vote transaction */
  fd_txn_t * txn = (fd_txn_t *)((uchar *)vote + vote->data.transaction.offset);
  ulong txn_struct_sz = fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt );

  uchar * txn_blob_ptr = (uchar *)txn + txn_struct_sz;
  ulong txn_blob_sz = vote->hdr.obj_sz - sizeof( fd_gossip_crds_value_vote_t ) - txn_struct_sz;

  if( !fd_bin_parse_write_blob_of_size( ctx, txn_blob_ptr, txn_blob_sz ) ) {
    FD_LOG_WARNING(( "error writing transaction out to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, vote->data.wallclock ) ) {
    FD_LOG_WARNING(( "error writing `wallclock` to blob" ));
    return 0;
  }

  *bytes_consumed = vote->hdr.obj_sz;
  return 1;   
}

int
fd_gossip_encode_crds_lowest_slot( fd_bin_parse_ctx_t * ctx,
                                   void               * in_buf,
                                   ulong                in_buf_sz,
                                   ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_lowest_slot_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than lowest_slot struct" ));
    return 0;
  }

  fd_gossip_crds_value_lowest_slot_t * lowest_slot = (fd_gossip_crds_value_lowest_slot_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(lowest_slot->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_LOWEST_SLOT ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u8( ctx, lowest_slot->data.index ) ) {
    FD_LOG_WARNING(( "unable to write `index` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey( ctx, &(lowest_slot->data.from) ) ) {
    FD_LOG_WARNING(( "error writing `from` pubkey to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, lowest_slot->data.root ) ) {
    FD_LOG_WARNING(( "unable to write `root` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, lowest_slot->data.lowest ) ) {
    FD_LOG_WARNING(( "unable to write `lowest` to blob" ));
    return 0;
  }

  /* write out `slots` vector length. this field is deprecated and must be zero-length,
     hence we just write out 0x0 and do not follow with any data. */
  if( !fd_bin_parse_write_u64( ctx, 0 ) ) {
    FD_LOG_WARNING(( "unable to write `slots` length to blob" ));
    return 0;
  }

  /* write out `stash` vector length. this field is deprecated and must be zero-length,
     hence as with above, just write out 0x0 as the vector length. */
  if( !fd_bin_parse_write_u64( ctx, 0 ) ) {
    FD_LOG_WARNING(( "unable to write `stash` length to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, lowest_slot->data.wallclock ) ) {
    FD_LOG_WARNING(( "unable to write `wallclock` to blob" ));
    return 0;
  }

  *bytes_consumed = lowest_slot->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_snapshot_hashes( fd_bin_parse_ctx_t * ctx,
                                       void               * in_buf,
                                       ulong                in_buf_sz,
                                       ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_snapshot_hashes_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than snapshot_hashes struct" ));
    return 0;
  }

  fd_gossip_crds_value_snapshot_hashes_t * snapshot_hashes = (fd_gossip_crds_value_snapshot_hashes_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(snapshot_hashes->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, snapshot_hashes->hdr.crds_id ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(snapshot_hashes->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  /* serialize out SlotHash vector */
  if( !fd_bin_parse_write_u64( ctx, snapshot_hashes->data.hashes.num_objs ) ) {
    FD_LOG_WARNING(( "error writing out `hashes` SlotHash vector size" ));
    return 0;
  }

  fd_gossip_crds_slot_hash_t * slot_hash_ptr = (fd_gossip_crds_slot_hash_t *)((uchar *)snapshot_hashes + snapshot_hashes->data.hashes.offset);
  for( ulong count = 0; count < snapshot_hashes->data.hashes.num_objs; count++, slot_hash_ptr++ ) {
    if( !fd_bin_parse_write_u64( ctx, slot_hash_ptr->slot ) ) {
      FD_LOG_WARNING(( "error writing `SlotHash.slot` out to blob" ));
      return 0;
    }

    if( !fd_bin_parse_write_blob_of_size( ctx, &(slot_hash_ptr->hash), 32 ) ) {
      FD_LOG_WARNING(( "error writing `SlotHash.hash` out to blob" ));
      return 0;
    }
  }

  if( !fd_bin_parse_write_u64( ctx, snapshot_hashes->data.wallclock ) ) {
    FD_LOG_WARNING(( "unable to write `wallclock` to blob" ));
    return 0;
  }

  *bytes_consumed = snapshot_hashes->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_legacy_version( fd_bin_parse_ctx_t * ctx,
                                      void               * in_buf,
                                      ulong                in_buf_sz,
                                      ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_legacy_version_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_legacy_version_t * legacy_version = (fd_gossip_crds_value_legacy_version_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(legacy_version->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_LEGACY_VERSION ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(legacy_version->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, legacy_version->data.wallclock ) ) {
    FD_LOG_WARNING(( "error writing out `wallclock` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, legacy_version->data.major ) ) {
    FD_LOG_WARNING(( "error writing out `major` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, legacy_version->data.minor ) ) {
    FD_LOG_WARNING(( "error writing out `minor` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, legacy_version->data.patch ) ) {
    FD_LOG_WARNING(( "error writing out `patch` to blob" ));
    return 0;
  }

  /* optional `commit`
     value is -1 to indicate that the Optional is missing. */
  if( legacy_version->data.commit == -1 ) {
    if( !fd_bin_parse_write_u8( ctx, (uchar)0 ) ) {
      FD_LOG_WARNING(( "unable to write out tag for Optional `commit`" ));
      return 0;
    }
  } else {
    if( !fd_bin_parse_write_u8( ctx, (uchar)1 ) ) {
      FD_LOG_WARNING(( "unable to write out tag for Optional `commit`" ));
      return 0;
    }
    if( !fd_bin_parse_write_u32( ctx, (uint)legacy_version->data.commit ) ) {
      FD_LOG_WARNING(( "unable to write out `commit` to blob" ));
      return 0;
    }
  }

  *bytes_consumed = legacy_version->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_version( fd_bin_parse_ctx_t * ctx,
                                      void               * in_buf,
                                      ulong                in_buf_sz,
                                      ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_version_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_version_t * version = (fd_gossip_crds_value_version_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(version->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_VERSION ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(version->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, version->data.wallclock ) ) {
    FD_LOG_WARNING(( "error writing out `wallclock` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, version->data.major ) ) {
    FD_LOG_WARNING(( "error writing out `major` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, version->data.minor ) ) {
    FD_LOG_WARNING(( "error writing out `minor` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, version->data.patch ) ) {
    FD_LOG_WARNING(( "error writing out `patch` to blob" ));
    return 0;
  }

  /* optional `commit`
     value is -1 to indicate that the Optional is missing. */
  if( version->data.commit == -1 ) {
    if( !fd_bin_parse_write_u8( ctx, (uchar)0 ) ) {
      FD_LOG_WARNING(( "unable to write out tag for Optional `commit`" ));
      return 0;
    }
  } else {
    if( !fd_bin_parse_write_u8( ctx, (uchar)1 ) ) {
      FD_LOG_WARNING(( "unable to write out tag for Optional `commit`" ));
      return 0;
    }
    if( !fd_bin_parse_write_u32( ctx, (uint)version->data.commit ) ) {
      FD_LOG_WARNING(( "unable to write out `commit` to blob" ));
      return 0;
    }
  }
  if( !fd_bin_parse_write_u32( ctx, (uint)version->data.features ) ) {
    FD_LOG_WARNING(( "unable to write out `features` to blob" ));
    return 0;
  }

  *bytes_consumed = version->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_node_instance( fd_bin_parse_ctx_t * ctx,
                                     void               * in_buf,
                                     ulong                in_buf_sz,
                                     ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_node_instance_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_node_instance_t * node_instance = (fd_gossip_crds_value_node_instance_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(node_instance->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_NODE_INSTANCE ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(node_instance->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, node_instance->data.wallclock ) ) {
    FD_LOG_WARNING(( "error writing out `wallclock` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, node_instance->data.timestamp ) ) {
    FD_LOG_WARNING(( "error writing out `timestamp` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, node_instance->data.token ) ) {
    FD_LOG_WARNING(( "error writing out `token` to blob" ));
    return 0;
  }

  *bytes_consumed = node_instance->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_duplicate_shred( fd_bin_parse_ctx_t * ctx,
                                       void               * in_buf,
                                       ulong                in_buf_sz,
                                       ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_duplicate_shred_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_duplicate_shred_t * duplicate_shred = (fd_gossip_crds_value_duplicate_shred_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(duplicate_shred->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, duplicate_shred->data.index ) ) {
    FD_LOG_WARNING(( "error writing out `index` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(duplicate_shred->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, duplicate_shred->data.wallclock ) ) {
    FD_LOG_WARNING(( "error writing out `wallclock` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, duplicate_shred->data.slot ) ) {
    FD_LOG_WARNING(( "error writing out `slot` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, duplicate_shred->data.shred_index ) ) {
    FD_LOG_WARNING(( "error writing out `shred_index` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u8( ctx, duplicate_shred->data.shred_type ) ) {
    FD_LOG_WARNING(( "error writing out `shred_type` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u8( ctx, duplicate_shred->data.num_chunks ) ) {
    FD_LOG_WARNING(( "error writing out `num_chunks` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u8( ctx, duplicate_shred->data.chunk_index ) ) {
    FD_LOG_WARNING(( "error writing out `chunk_index` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, duplicate_shred->data.chunk.num_objs ) ) {
    FD_LOG_WARNING(( "error writing `chunks` vector size to blob" ));
    return 0;
  }

  if( duplicate_shred->data.chunk.num_objs ) {
    void * chunk_data = ((uchar *)duplicate_shred + duplicate_shred->data.chunk.offset);
    if( !fd_bin_parse_write_blob_of_size( ctx, chunk_data, duplicate_shred->data.chunk.num_objs ) ) {
      FD_LOG_WARNING(( "unable to write `chunk` vector to blob" ));
    }
  }

  *bytes_consumed = duplicate_shred->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_incremental_snapshot_hashes( fd_bin_parse_ctx_t * ctx,
                                                   void               * in_buf,
                                                   ulong                in_buf_sz,
                                                   ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_incremental_snapshot_hashes_t) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_incremental_snapshot_hashes_t * incr_snapshot_hashes = (fd_gossip_crds_value_incremental_snapshot_hashes_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(incr_snapshot_hashes->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(incr_snapshot_hashes->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, incr_snapshot_hashes->data.base.slot ) ) {
    FD_LOG_WARNING(( "error writing out `slot` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_blob_of_size( ctx, &(incr_snapshot_hashes->data.base.hash), 32 ) ) {
    FD_LOG_WARNING(( "error writing out `hash` to blob" ));
    return 0;
  }

  /* serialize up the `hashes` SlotHash vector */
  if( !fd_bin_parse_write_u64( ctx, incr_snapshot_hashes->data.hashes.num_objs ) ) {
    FD_LOG_WARNING(( "unable to write `hashes` vector size to blob" ));
    return 0;
  }

  fd_gossip_crds_slot_hash_t * slot_hash = (fd_gossip_crds_slot_hash_t *)((uchar *)incr_snapshot_hashes + incr_snapshot_hashes->data.hashes.offset);
  for( ulong count = 0; count<incr_snapshot_hashes->data.hashes.num_objs; count++, slot_hash++ ) {
    if( !fd_bin_parse_write_u64( ctx, slot_hash->slot ) ) {
      FD_LOG_WARNING(( "unable to write `slot` out to blob" ));
      return 0;
    }

    if( !fd_bin_parse_write_blob_of_size( ctx, &(slot_hash->hash), 32 ) ) {
      FD_LOG_WARNING(( "unable to write `hash` out to blob" ));
      return 0;
    }
  }

  if( !fd_bin_parse_write_u64( ctx, incr_snapshot_hashes->data.wallclock ) ) {
    FD_LOG_WARNING(( "unable to write `wallclock` out to blob" ));
    return 0;
  }

  *bytes_consumed = incr_snapshot_hashes->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_contact_info( fd_bin_parse_ctx_t * ctx,
                                    void               * in_buf,
                                    ulong                in_buf_sz,
                                    ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_contact_info_t) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_contact_info_t * contact_info = (fd_gossip_crds_value_contact_info_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(contact_info->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_CONTACT_INFO ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey (ctx, &(contact_info->data.pubkey ) ) ) {
    FD_LOG_WARNING(( "error writing out `pubkey` pubkey" ));
    return 0;
  }

  /* serialize out `wallclock` using var-int encoding */
  if( !fd_bin_parse_write_varint_u64( ctx, contact_info->data.wallclock ) ) {
    FD_LOG_WARNING(( "unable to serialize `wallclock` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, contact_info->data.outset ) ) {
    FD_LOG_WARNING(( "unable to serialize `outset`" ));
    return 0;
  }

  if( !fd_bin_parse_write_u16( ctx, contact_info->data.shred_version ) ) {
    FD_LOG_WARNING(( "unable to serialize `shred_version` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_varint_u16( ctx, contact_info->data.version.major ) ) {
    FD_LOG_WARNING(( "unable to serialize `version.major` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_varint_u16( ctx, contact_info->data.version.minor ) ) {
    FD_LOG_WARNING(( "unable to serialize `version.minor` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_varint_u16( ctx, contact_info->data.version.patch ) ) {
    FD_LOG_WARNING(( "unable to serialize `version.patch` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, contact_info->data.version.commit ) ) {
    FD_LOG_WARNING(( "unable to serialize `version.commit` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, contact_info->data.version.feature_set ) ) {
    FD_LOG_WARNING(( "unable to serialize `version.feature_set` varint" ));
    return 0;
  }

  if( !fd_bin_parse_write_varint_u16( ctx, contact_info->data.version.client ) ) {
    FD_LOG_WARNING(( "unable to serialize `version.client` varint" ));
    return 0;
  }

  /* serialize out addrs short_vec
     since this vector is serialized as a short_vec, the size field is a u16 var-int */
  if( !fd_bin_parse_write_varint_u16( ctx, (ushort)contact_info->data.addrs.num_objs ) ) {
    FD_LOG_WARNING(( "unable to write out `addrs` vector size" ));
    return 0;
  }

  fd_ipaddr_t * ipaddr = (fd_ipaddr_t *)((uchar *)contact_info + contact_info->data.addrs.offset);
  for( ulong count=0; count<contact_info->data.addrs.num_objs; count++, ipaddr++ ) {
    if( !fd_bin_parse_write_u32( ctx, (uint)ipaddr->fam ) ) {
      FD_LOG_WARNING(( "unable to write out address family to blob" ));
      return 0;
    }

    if( ipaddr->fam == FD_SOCKETADDR_IPV4 ) {
      fd_bin_parse_write_blob_of_size( ctx, &(ipaddr->addr.ipv4_sin_addr), FD_ADDR_LEN_IPV4 );
    } else if( ipaddr->fam == FD_SOCKETADDR_IPV6 ) {
      fd_bin_parse_write_blob_of_size( ctx, &(ipaddr->addr.ipv6_sin_addr), FD_ADDR_LEN_IPV6 );
    } else {
      FD_LOG_WARNING(( "invalid address family specified for serialization - programming error."));
      return 0;
    }
  }

  /* serialize out socket entry short_vec
     as above, short_vec vectors are serialized such that their size field is a u16 var-int */
  if( !fd_bin_parse_write_varint_u16( ctx, (ushort)contact_info->data.sockets.num_objs) ) {
    FD_LOG_WARNING(( "unable to write out `sockets` vector size" ));
    return 0;
  }

  fd_gossip_socketentry_t * socket_entry = (fd_gossip_socketentry_t *)((uchar *)contact_info + contact_info->data.sockets.offset);

  for( ulong count=0; count<contact_info->data.sockets.num_objs; count++, socket_entry++ ) {
    if( !fd_bin_parse_write_u8( ctx, socket_entry->key ) ) {
      FD_LOG_WARNING(( "unable to write out `key` in socket_entry vector" ));
      return 0;
    }
    if( !fd_bin_parse_write_u8( ctx, socket_entry->index ) ) {
      FD_LOG_WARNING(( "unable to write out `index` in socket_entry vector" ));
      return 0;
    }
    if( !fd_bin_parse_write_varint_u16( ctx, socket_entry->offset ) ) {
     FD_LOG_WARNING(( "unable to write out `offset` vector size" ));
     return 0;
    }
  }

  *bytes_consumed = contact_info->hdr.obj_sz;
  return 1;
}

int
fd_gossip_encode_crds_epoch_slots( fd_bin_parse_ctx_t * ctx,
                                    void               * in_buf,
                                    ulong                in_buf_sz,
                                    ulong              * bytes_consumed ) {

  if( FD_UNLIKELY( in_buf_sz<sizeof( fd_gossip_crds_value_epoch_slots_t ) ) ) {
    FD_LOG_WARNING(( "input data is shorter than legacy version struct" ));
    return 0;
  }

  fd_gossip_crds_value_epoch_slots_t * epoch_slots = (fd_gossip_crds_value_epoch_slots_t *)in_buf;

  if( !fd_bin_parse_write_blob_of_size( ctx, &(epoch_slots->hdr.signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_CRDS_ID_EPOCH_SLOTS ) ) {
    FD_LOG_WARNING(( "unable to write `crds_id` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u8(ctx, epoch_slots->data.index ) ) {
    FD_LOG_WARNING(( "error writing out `index` pubkey" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey(ctx, &(epoch_slots->data.from ) ) ) {
    FD_LOG_WARNING(( "error writing out `from` pubkey" ));
    return 0;
  }

  /* serialize out compressed slots vector
     each compressed slots entry can be either compressed or uncompressed. */
  if( !fd_bin_parse_write_u64( ctx, epoch_slots->data.compressed_slots.num_objs ) ) {
    FD_LOG_WARNING(( "unable to write `compressed_slots` vector size to blob" ));
    return 0;
  }

  fd_gossip_crds_compressed_slots_t * compressed_slots = (fd_gossip_crds_compressed_slots_t *)((uchar *)epoch_slots + epoch_slots->data.compressed_slots.offset);
  uchar * compressed_slots_ptr = (uchar *)compressed_slots;

  for( ulong count=0; count<epoch_slots->data.compressed_slots.num_objs; count++, compressed_slots_ptr+=compressed_slots->obj_sz ) {

    compressed_slots = (fd_gossip_crds_compressed_slots_t *)compressed_slots_ptr;

    if( !fd_bin_parse_write_u32( ctx, (uint)compressed_slots->type ) ) {
      FD_LOG_WARNING(( "unable to write out `compressed_slots` variant type" ));
      return 0;
    }
    if( !fd_bin_parse_write_u64( ctx, compressed_slots->first_slot ) ) {
      FD_LOG_WARNING(( "unable to write out `compressed_slots.first_slot` type" ));
      return 0;
    }
    if( !fd_bin_parse_write_u64( ctx, compressed_slots->num ) ) {
      FD_LOG_WARNING(( "unable to write out `compressed_slots.num` type" ));
      return 0;
    }

    /* serialize out slots vector. */
    if( compressed_slots->type==FD_GOSSIP_COMPRESSION_TYPE_FLATE2 ) {
      uchar *data_ptr = (uchar *)compressed_slots + compressed_slots->compressed.offset;
      if( !fd_bin_parse_write_u64( ctx, compressed_slots->compressed.num_objs ) ) {
        FD_LOG_WARNING(( "unable to write compressed slots vector size to blob" ));
        return 0;
      }
      if( !fd_bin_parse_write_blob_of_size( ctx, data_ptr, compressed_slots->compressed.num_objs ) ) {
        FD_LOG_WARNING(( "unable to write compressed slots data to buffer" ));
        return 0;
      }

    } else if( compressed_slots->type==FD_GOSSIP_COMPRESSION_TYPE_UNCOMPRESSED ) {
      if( compressed_slots->slots.bits.num_objs==0 ) {
        if( !fd_bin_parse_write_u8( ctx, 0 ) ) {
          FD_LOG_WARNING(( "unable to write out Option tag for `compressed_slots`" ));
          return 0;
        }
        if( !fd_bin_parse_write_u64( ctx, compressed_slots->slots.len ) ) {
          FD_LOG_WARNING(( "unable to write out `compressed_slots` bitvec Len" ));
          return 0;
        }
      } else {
        if( !fd_bin_parse_write_u8( ctx, 1 ) ) {
          FD_LOG_WARNING(( "unable to write out Option tag for `compressed_slots`" ));
          return 0;
        }

        if( !fd_bin_parse_write_u64( ctx, compressed_slots->slots.bits.num_objs ) ) {
          FD_LOG_WARNING(( "unable to write out `compressed_slots` vector size" ));
          return 0;
        }

        uchar *data_ptr = (uchar *)compressed_slots + compressed_slots->slots.bits.offset;
        if( !fd_bin_parse_write_blob_of_size( ctx, data_ptr, compressed_slots->slots.bits.num_objs ) ) {
          FD_LOG_WARNING(( "unable to write uncompressed slots data to buffer" ));
          return 0;
        }
        if( !fd_bin_parse_write_u64( ctx, compressed_slots->slots.len ) ) {
          FD_LOG_WARNING(( "unable to write out `compressed_slots` bitvec Len" ));
          return 0;
        }
      }

    } else {
      FD_LOG_WARNING(( "invalid compression variant type (0x%x) - programming error.", compressed_slots->type ));
      return 0;
    }
  }

  if( !fd_bin_parse_write_u64( ctx, epoch_slots->data.wallclock ) ) {
    FD_LOG_WARNING(( "unable to write out `wallclock`" ));
    return 0;
  }

  *bytes_consumed = epoch_slots->hdr.obj_sz;
  return 1;
}
