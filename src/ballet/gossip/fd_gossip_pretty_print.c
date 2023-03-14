#include <stdlib.h>
#include <stdio.h>
#include "fd_gossip_pretty_print.h"
#include "fd_gossip_msg.h"
#include <netinet/in.h>
#include <arpa/inet.h>

/* a pretty-printer for gossip messages, for testing and debugging purposes */

char *
get_ip_addr( fd_socketaddr_t * addr,
             char            * dst   ) {
  
  switch( addr->fam ) {
  case FD_SOCKETADDR_IPV4:
    inet_ntop(AF_INET, &(addr->addr), dst, INET_ADDRSTRLEN );
    break;

  case FD_SOCKETADDR_IPV6:
    inet_ntop(AF_INET6, &(addr->addr), dst, INET6_ADDRSTRLEN );
    break;
  }
  return dst;
}

/* TODO(smcio): this is a WIP */

ulong
fd_gossip_pretty_print_crds_object( void * data ) {

  fd_gossip_crds_header_t * hdr = (fd_gossip_crds_header_t *)data;
  uint crds_id = hdr->crds_id;

  char ip_addr_str[INET6_ADDRSTRLEN];

  switch( crds_id ) {
  case FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO: {
    fd_gossip_crds_value_legacy_contact_info_t * contact_info = (fd_gossip_crds_value_legacy_contact_info_t *)hdr;

    FD_LOG_WARNING(( "  => LegacyContactInfo" ));
    FD_LOG_WARNING(( "     ------------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(contact_info->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - id", &(contact_info->data.id) );
    FD_LOG_WARNING(( "  - gossip: addr = %s, port = %d", get_ip_addr( &(contact_info->data.gossip), ip_addr_str ), contact_info->data.gossip.port ));
    FD_LOG_WARNING(( "  - tvu: addr = %s, port = %d", get_ip_addr( &(contact_info->data.tvu), ip_addr_str ), contact_info->data.tvu.port ));
    FD_LOG_WARNING(( "  - tvu_fwd: addr = %s, port = %d", get_ip_addr( &(contact_info->data.tvu_fwd), ip_addr_str ), contact_info->data.tvu_fwd.port ));
    FD_LOG_WARNING(( "  - repair: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.repair), ip_addr_str ), contact_info->data.repair.port ));
    FD_LOG_WARNING(( "  - tpu: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.tpu), ip_addr_str ), contact_info->data.tpu.port ));
    FD_LOG_WARNING(( "  - tpu_fwd: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.tpu_fwd), ip_addr_str ), contact_info->data.tpu_fwd.port ));
    FD_LOG_WARNING(( "  - tpu_vote: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.tpu_vote), ip_addr_str ), contact_info->data.tpu_vote.port ));
    FD_LOG_WARNING(( "  - rpc: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.rpc), ip_addr_str ), contact_info->data.rpc.port ));
    FD_LOG_WARNING(( "  - rpc_pub_sub: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.rpc_pub_sub), ip_addr_str ), contact_info->data.rpc_pub_sub.port ));
    FD_LOG_WARNING(( "  - serve_repair: addr = %s, port = %d",  get_ip_addr( &(contact_info->data.serve_repair), ip_addr_str ), contact_info->data.serve_repair.port ));
    FD_LOG_WARNING(( "  - wallclock: addr = 0x%lx", contact_info->data.wallclock ));
    FD_LOG_WARNING(( "  - shred_version: addr = 0x%hx", contact_info->data.shred_version ));    
    break;
  }

  case FD_GOSSIP_CRDS_ID_VOTE: {
    fd_gossip_crds_value_vote_t * vote = (fd_gossip_crds_value_vote_t *)hdr;
    
    FD_LOG_WARNING(( "  => Vote" ));
    FD_LOG_WARNING(( "     ------------" ));
    FD_LOG_WARNING(( "  - obj_sz: 0x%lx", vote->hdr.obj_sz ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(vote->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(vote->data.from) );
    FD_LOG_WARNING(( "  - index: 0x%x", vote->data.index ));
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", vote->data.wallclock ));
    //FD_LOG_WARNING(( "  - slot: 0x%lx", vote->data.slot ));

    /* TODO(smcio): printing out raw txn data */
    break;
  }

  case FD_GOSSIP_CRDS_ID_LOWEST_SLOT: {
    fd_gossip_crds_value_lowest_slot_t * lowest_slot = (fd_gossip_crds_value_lowest_slot_t *)hdr;

    FD_LOG_WARNING(( "  => LowestSlot" ));
    FD_LOG_WARNING(( "     -----------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(lowest_slot->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(lowest_slot->data.from) );
    FD_LOG_WARNING(( "  - root: addr = %lu", lowest_slot->data.root ));
    FD_LOG_WARNING(( "  - lowest: addr = %lu", lowest_slot->data.root ));
    FD_LOG_WARNING(( "  - slots: obsolete" ));
    FD_LOG_WARNING(( "  - stash: obsolete" ));
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", lowest_slot->data.wallclock ));
    break;
  }

  case FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES:
  case FD_GOSSIP_CRDS_ID_ACCOUNT_HASHES: {
    if( crds_id==FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES ) {
      FD_LOG_WARNING(( "  => SnapshotHashes" ));
      FD_LOG_WARNING(( "     ---------------" ));
    }
    else {
      FD_LOG_WARNING(( "  => AccountHashes" ));
      FD_LOG_WARNING(( "     ---------------" ));
    }

    /* fd_gossip_crds_value_snapshot_hashes_t and fd_gossip_crds_value_account_hashes_t are essentially
       the same struct, so one set of logic works to pretty-print both SnapshotHashes & AccountHashes */
    fd_gossip_crds_value_snapshot_hashes_t * snapshot_hashes = (fd_gossip_crds_value_snapshot_hashes_t *)hdr;
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(snapshot_hashes->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(snapshot_hashes->data.from) );
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", snapshot_hashes->data.wallclock ));
    FD_LOG_WARNING(( "  - hashes:" ));
    FOR_EACH_SLOT_HASH_IN_VECTOR( snapshot_hashes, data.hashes, slot_hash ) {
      FD_LOG_WARNING(( "    - base.slot: 0x%lx", slot_hash->slot ));
      fd_gossip_pretty_print_blob_as_hex( "    - base.hash", &(slot_hash->hash), 32 );
    }

    break;
  }

  case FD_GOSSIP_CRDS_ID_EPOCH_SLOTS: {
    fd_gossip_crds_value_epoch_slots_t * epoch_slots = (fd_gossip_crds_value_epoch_slots_t *)hdr;
    FD_LOG_WARNING(( "   => EpochSlots" ));
    FD_LOG_WARNING(( "     ---------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(epoch_slots->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(epoch_slots->data.from) );
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", epoch_slots->data.wallclock ));
    FD_LOG_WARNING(( "  - index: 0x%x", epoch_slots->data.index & 0xff ));
    FD_LOG_WARNING(( "  - compressed_slots: " ));
    FOR_EACH_COMPRESSED_SLOTS_IN_VECTOR( epoch_slots, data.compressed_slots, compressed_slots ) {
      FD_LOG_WARNING(( "    - type: %s, first_slot: 0x%lx, num: 0x%lx", ( compressed_slots->type == FD_GOSSIP_COMPRESSION_TYPE_FLATE2 ? "flate2" : "uncompressed" ), compressed_slots->first_slot, compressed_slots->num ));
      if( compressed_slots->type == FD_GOSSIP_COMPRESSION_TYPE_FLATE2 ) {
        GET_DATA_AND_NUM_ELEMENTS_FOR_VECTOR( compressed_slots, compressed, compressed_data, compressed_data_sz );
        fd_gossip_pretty_print_blob_as_hex( "    - compressed slots data", compressed_data, compressed_data_sz );
      } else if( FD_GOSSIP_COMPRESSION_TYPE_UNCOMPRESSED) {   /* uncompressed */
        GET_DATA_AND_NUM_ELEMENTS_FOR_VECTOR( compressed_slots, slots.bits, uncompressed_slots_data, uncompressed_slots_data_sz );
        fd_gossip_pretty_print_blob_as_hex( "    - uncompressed slots data", uncompressed_slots_data, uncompressed_slots_data_sz );
      } else {
        FD_LOG_ERR(( "unknown compression type "));
      }
    }

    break;
  }

  case FD_GOSSIP_CRDS_ID_LEGACY_VERSION: {
    fd_gossip_crds_value_legacy_version_t * legacy_version = (fd_gossip_crds_value_legacy_version_t *)hdr;
    FD_LOG_WARNING(( "   => LegacyVersion" ));
    FD_LOG_WARNING(( "     ---------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(legacy_version->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(legacy_version->data.from) );
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", legacy_version->data.wallclock ));
    FD_LOG_WARNING(( "  - major: 0x%hx", legacy_version->data.major ));
    FD_LOG_WARNING(( "  - minor: 0x%hx", legacy_version->data.minor ));
    FD_LOG_WARNING(( "  - patch: 0x%hx", legacy_version->data.patch ));
    if( legacy_version->data.commit == -1 ) FD_LOG_WARNING(( "  - commit: None (optional)" ));
    else FD_LOG_WARNING(( "  - commit: %x", (uint)legacy_version->data.commit ));
    break;
  }

  case FD_GOSSIP_CRDS_ID_VERSION: {
    fd_gossip_crds_value_version_t * version = (fd_gossip_crds_value_version_t *)hdr;
    FD_LOG_WARNING(( "   => Version" ));
    FD_LOG_WARNING(( "     ----------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(version->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(version->data.from) );
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", version->data.wallclock ));
    FD_LOG_WARNING(( "  - major: 0x%hx", version->data.major ));
    FD_LOG_WARNING(( "  - minor: 0x%hx", version->data.minor ));
    FD_LOG_WARNING(( "  - patch: 0x%hx", version->data.patch ));
    if( version->data.commit == -1 ) FD_LOG_WARNING(( "  - commit: None (optional)" ));
    else FD_LOG_WARNING(( "  - commit: %x", (uint)version->data.commit ));
    FD_LOG_WARNING(( "  - features: 0x%x", version->data.features ));
    break;
  }

  case FD_GOSSIP_CRDS_ID_NODE_INSTANCE: {
    fd_gossip_crds_value_node_instance_t * node_instance = (fd_gossip_crds_value_node_instance_t *)hdr;
    FD_LOG_WARNING(( "   => NodeInstance" ));
    FD_LOG_WARNING(( "     --------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(node_instance->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(node_instance->data.from) );
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", node_instance->data.wallclock ));
    FD_LOG_WARNING(( "  - timestamp: 0x%lx", node_instance->data.timestamp ));
    FD_LOG_WARNING(( "  - token: 0x%lx", node_instance->data.token ));
    break;
  }

  case FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED: {
    fd_gossip_crds_value_duplicate_shred_t * duplicate_shred = (fd_gossip_crds_value_duplicate_shred_t *)hdr;
    FD_LOG_WARNING(( "   => DuplicateShred" ));
    FD_LOG_WARNING(( "     --------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(duplicate_shred->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(duplicate_shred->data.from) );
    FD_LOG_WARNING(( "  - index: 0x%hx", duplicate_shred->data.index ));
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", duplicate_shred->data.wallclock ));
    FD_LOG_WARNING(( "  - shred_index: 0x%x", duplicate_shred->data.shred_index ));
    FD_LOG_WARNING(( "  - shred_type: 0x%x", duplicate_shred->data.shred_type & 0xff ));
    FD_LOG_WARNING(( "  - slot: 0x%lx", duplicate_shred->data.slot ));
    FD_LOG_WARNING(( "  - chunk_index: 0x%x", duplicate_shred->data.chunk_index & 0xff ));
    FD_LOG_WARNING(( "  - num_chunks: 0x%x", duplicate_shred->data.num_chunks & 0xff ));
    GET_DATA_AND_NUM_ELEMENTS_FOR_VECTOR( duplicate_shred, data.chunk, chunk_data, chunk_data_sz );
    fd_gossip_pretty_print_blob_as_hex( "  - chunk:", chunk_data, chunk_data_sz );
    break;
  }

  case FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES: {
    fd_gossip_crds_value_incremental_snapshot_hashes_t * incr_snapshot_hashes = (fd_gossip_crds_value_incremental_snapshot_hashes_t *)hdr;
    FD_LOG_WARNING(( "   => IncrementalSnapshotHashes" ));
    FD_LOG_WARNING(( "     ---------------------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(incr_snapshot_hashes->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(incr_snapshot_hashes->data.from) );
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", incr_snapshot_hashes->data.wallclock ));
    FD_LOG_WARNING(( "  - base.slot: 0x%lx", incr_snapshot_hashes->data.base.slot ));
    fd_gossip_pretty_print_blob_as_hex( "  - base.hash", &(incr_snapshot_hashes->data.base.hash), 32 );

    FD_LOG_WARNING(( "  - hashes:" ));
    FOR_EACH_SLOT_HASH_IN_VECTOR( incr_snapshot_hashes, data.hashes, slot_hash ) {
      FD_LOG_WARNING(( "    - base.slot: 0x%lx", slot_hash->slot ));
      fd_gossip_pretty_print_blob_as_hex( "    - base.hash", &(slot_hash->slot), 32 );
    }
    break;
  }

  case FD_GOSSIP_CRDS_ID_CONTACT_INFO: {
    fd_gossip_crds_value_contact_info_t * contact_info = (fd_gossip_crds_value_contact_info_t *)hdr;
    FD_LOG_WARNING(( "   => ContactInfo" ));
    FD_LOG_WARNING(( "     --------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(contact_info->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(contact_info->data.pubkey ) );
    //FD_LOG_WARNING(( "  - version: 0x%hx", contact_info->data.version ));
    FD_LOG_WARNING(( "  - shred_version: 0x%hx", contact_info->data.shred_version ));
    FD_LOG_WARNING(( "  - outset: 0x%lx", contact_info->data.outset ));
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", contact_info->data.wallclock ));
    FD_LOG_WARNING(( "  - version.major: 0x%hx", contact_info->data.version.major ));
    FD_LOG_WARNING(( "  - version.minor: 0x%hx", contact_info->data.version.minor ));
    FD_LOG_WARNING(( "  - version.patch: 0x%hx", contact_info->data.version.patch ));
    FD_LOG_WARNING(( "  - version.comit: 0x%x", contact_info->data.version.commit ));
    FD_LOG_WARNING(( "  - version.feature_set: 0x%x", contact_info->data.version.feature_set ));
    FD_LOG_WARNING(( "  - version.client: 0x%hx", contact_info->data.version.client ));
    FD_LOG_WARNING(( "  - addrs: "));
    FOR_EACH_ADDR_IN_VECTOR( contact_info, data.addrs, addr ) {
      FD_LOG_WARNING(( "%s", get_ip_addr( addr, ip_addr_str ) ));
    }
    FD_LOG_WARNING(( "  - socket_entry: "));
    FOR_EACH_SOCKET_ENTRY_IN_VECTOR( contact_info, data.sockets, socket_entry ) {
      FD_LOG_WARNING(( "key: 0x%x, index: 0x%x, offset: 0x%hx", socket_entry->key & 0xff, socket_entry->index & 0xff, socket_entry->offset ));
    }
    break;
  }

  default:
    FD_LOG_WARNING(( "unknown CRDS value, %u", crds_id ));
    break;
  }

  return hdr->obj_sz;
}

void
fd_gossip_pretty_print_blob_as_hex( char * member_name,
                                      void * data,
                                      ulong  data_sz ) {
  char * buf = (char *)fd_alloca( alignof(char), data_sz*8 );
  char * ptr = buf;
  uchar *pk = (uchar *)data;
  for( ulong count = 0; count < data_sz; count++ ) {
    ptr += sprintf( ptr, "0x%x ", pk[count] & 0xff );
  }
  FD_LOG_WARNING(( "%s: %s", member_name, buf ));
}

void
fd_gossip_pretty_print_pubkey( char * member_name,
                               void * pubkey ) {
  char buf[1024];
  char *ptr = buf;
  uchar *pk = (uchar *)pubkey;
  for( ulong count = 0; count < 32; count++ ) {
    ptr += sprintf( ptr, "0x%x ", pk[count] & 0xff );
  }
  FD_LOG_WARNING(( "%s: %s", member_name, buf ));
}

void
fd_gossip_pretty_print_signature( char * member_name,
                                  void * signature ) {
  char buf[1024];
  char *ptr = buf;
  uchar *sig = (uchar *)signature;
  for( ulong count = 0; count < 64; count++ ) {
    ptr += sprintf( ptr, "0x%x ", sig[count] & 0xff );
  }
  FD_LOG_WARNING(( "%s: %s", member_name, buf ));
}

void
fd_gossip_pretty_print_pull_req( fd_gossip_pull_req_t * msg ) {
  FD_LOG_WARNING(( "PullRequest" ));
  FD_LOG_WARNING(( "=============\n" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id & 0xff ));

  FD_LOG_WARNING(( "- CRDS filter" ));
  FD_LOG_WARNING(( " -------------" ));
  FD_LOG_WARNING(( "   - mask: %lx", msg->crds_filter.mask ));
  FD_LOG_WARNING(( "   - mask_bits: %x", msg->crds_filter.mask_bits ));
  FD_LOG_WARNING(( "   - mask: %lx", msg->crds_filter.bloom.bits.bits.num_objs ));

  FD_LOG_WARNING(( "   - Bloom " ));
  FD_LOG_WARNING(( "   --------- " ));

  GET_BLOOM_FILTER_DATA_AND_SIZE( msg, bloom_data, sz );
  fd_gossip_pretty_print_blob_as_hex( "      - bits", bloom_data, sz );
  FD_LOG_WARNING(( "     - num_bits_set: %lx", msg->crds_filter.bloom.num_bits_set ));
  FD_LOG_WARNING(( "     - keys: " ));
  FOR_EACH_U64_IN_VECTOR( msg, crds_filter.bloom.keys, value ) {
    FD_LOG_WARNING(( "       - 0x%lx ", value ));
  }

  FD_LOG_WARNING(( "- CRDS value" ));
  fd_gossip_crds_header_t * hdr = (fd_gossip_crds_header_t *)((uchar *)msg + msg->value.offset);
  fd_gossip_pretty_print_crds_object(hdr);
}

void
fd_gossip_pretty_print_pull_resp( fd_gossip_pull_response_t * msg ) {
  FD_LOG_WARNING(( "PullResponse" ));
  FD_LOG_WARNING(( "=============\n" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id & 0xff ));
  fd_gossip_pretty_print_pubkey( "- pubkey", &(msg->pubkey) );

  FD_LOG_WARNING(( "- CRDS ( %lu objects(s) )", msg->values.num_objs ));

  FOR_EACH_CRDS_IN_VECTOR( msg, values, crds_obj ) {
    fd_gossip_pretty_print_crds_object( crds_obj );
  }
}

void
fd_gossip_pretty_print_push( fd_gossip_push_msg_t * msg ) {
  FD_LOG_WARNING(( "Push" ));
  FD_LOG_WARNING(( "======\n" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id & 0xff ));
  fd_gossip_pretty_print_pubkey( "- pubkey", &(msg->pubkey) );

  FD_LOG_WARNING(( "- CRDS ( %lu objects(s) )", msg->values.num_objs ));

  FOR_EACH_CRDS_IN_VECTOR( msg, values, crds_obj ) {
    fd_gossip_pretty_print_crds_object( crds_obj );
  }
}

void
fd_gossip_pretty_print_ping( fd_gossip_ping_msg_t * msg ) {
  FD_LOG_WARNING(( "Ping" ));
  FD_LOG_WARNING(( "=====" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id ));
  fd_gossip_pretty_print_pubkey( "- from", &(msg->from) );
  fd_gossip_pretty_print_blob_as_hex( "- token", &(msg->token), 32 );
  fd_gossip_pretty_print_signature( "- signature", &(msg->signature) );
}

void
fd_gossip_pretty_print_pong( fd_gossip_pong_msg_t * msg ) {
  FD_LOG_WARNING(( "Pong" ));
  FD_LOG_WARNING(( "=====" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id ));
  fd_gossip_pretty_print_pubkey( "- from", &(msg->from) );
  fd_gossip_pretty_print_blob_as_hex( "- hash", &(msg->hash), 32 );
  fd_gossip_pretty_print_signature( "- signature", &(msg->signature) );
}

void
fd_gossip_pretty_print( void * data ) {

  fd_gossip_msg_t * msg = (fd_gossip_msg_t *)data;
  uint msg_id = (uint)msg->msg_id;

  FD_LOG_WARNING(( " " ));

  switch( msg_id ) {
  case FD_GOSSIP_MSG_ID_PULL_REQ:
    fd_gossip_pretty_print_pull_req( (fd_gossip_pull_req_t *)msg );
    break;
    
  case FD_GOSSIP_MSG_ID_PULL_RESP:
    fd_gossip_pretty_print_pull_resp( (fd_gossip_pull_response_t *)msg );
    break;

  case FD_GOSSIP_MSG_ID_PUSH:
    fd_gossip_pretty_print_push( (fd_gossip_push_msg_t *)msg );
    break;

  case FD_GOSSIP_MSG_ID_PING:
    fd_gossip_pretty_print_ping( (fd_gossip_ping_msg_t *)msg );
    break;
  
  case FD_GOSSIP_MSG_ID_PONG:
    fd_gossip_pretty_print_pong( (fd_gossip_pong_msg_t *)msg );
    break;

  default:
    FD_LOG_WARNING(( "unknown gossip message type" ));
    break;
  }
}
