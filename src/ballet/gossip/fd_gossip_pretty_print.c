#include <stdlib.h>
#include <stdio.h>
#include "fd_gossip_pretty_print.h"
#include "fd_gossip_msg.h"
#include <netinet/in.h>
#include <arpa/inet.h>

/* a pretty-printer for gossip messages, for testing and debugging purposes */

/* TODO(smcio): this is a WIP */

void
fd_gossip_pretty_print_crds_object( fd_gossip_crds_header_t ** crds_hdr ) {

  ulong sz_to_advance_ptr = 0;
  fd_gossip_crds_header_t * hdr = *crds_hdr;

  uint crds_id = hdr->crds_id;

  switch( crds_id ) {
  case FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO: {
    fd_gossip_crds_value_legacy_contact_info_t * contact_info = (fd_gossip_crds_value_legacy_contact_info_t *)hdr;

    FD_LOG_WARNING(( "  => LegacyContactInfo" ));
    FD_LOG_WARNING(( "     ------------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(contact_info->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - id", &(contact_info->data.id) );
    FD_LOG_WARNING(( "  - gossip: addr = %s, port = %d",  inet_ntoa(contact_info->data.gossip.addr.ipv4_sin_addr), contact_info->data.gossip.port ));
    FD_LOG_WARNING(( "  - tvu: addr = %s, port = %d",  inet_ntoa(contact_info->data.tvu.addr.ipv4_sin_addr), contact_info->data.tvu.port ));
    FD_LOG_WARNING(( "  - tvu_fwd: addr = %s, port = %d",  inet_ntoa(contact_info->data.tvu_fwd.addr.ipv4_sin_addr), contact_info->data.tvu_fwd.port ));
    FD_LOG_WARNING(( "  - repair: addr = %s, port = %d",  inet_ntoa(contact_info->data.repair.addr.ipv4_sin_addr), contact_info->data.repair.port ));
    FD_LOG_WARNING(( "  - tpu: addr = %s, port = %d",  inet_ntoa(contact_info->data.tpu.addr.ipv4_sin_addr), contact_info->data.tpu.port ));
    FD_LOG_WARNING(( "  - tpu_fwd: addr = %s, port = %d",  inet_ntoa(contact_info->data.tpu_fwd.addr.ipv4_sin_addr), contact_info->data.tpu_fwd.port ));
    FD_LOG_WARNING(( "  - tpu_vote: addr = %s, port = %d",  inet_ntoa(contact_info->data.tpu_vote.addr.ipv4_sin_addr), contact_info->data.tpu_vote.port ));
    FD_LOG_WARNING(( "  - rpc: addr = %s, port = %d",  inet_ntoa(contact_info->data.rpc.addr.ipv4_sin_addr), contact_info->data.rpc.port ));
    FD_LOG_WARNING(( "  - rpc_pub_sub: addr = %s, port = %d",  inet_ntoa(contact_info->data.rpc_pub_sub.addr.ipv4_sin_addr), contact_info->data.rpc_pub_sub.port ));
    FD_LOG_WARNING(( "  - serve_repair: addr = %s, port = %d",  inet_ntoa(contact_info->data.serve_repair.addr.ipv4_sin_addr), contact_info->data.serve_repair.port ));
    FD_LOG_WARNING(( "  - wallclock: addr = %lu", contact_info->data.wallclock ));
    FD_LOG_WARNING(( "  - shred_version: addr = 0x%hx", contact_info->data.shred_version ));

    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_legacy_contact_info_t );
    
    break;
  }

  case FD_GOSSIP_CRDS_ID_VOTE: {
    fd_gossip_crds_value_vote_t * vote = (fd_gossip_crds_value_vote_t *)hdr;
    
    FD_LOG_WARNING(( "  => Vote" ));
    FD_LOG_WARNING(( "     ------------" ));
    FD_LOG_WARNING(( "  - crds_id: 0x%x", crds_id & 0xff ));
    fd_gossip_pretty_print_signature( "  - signature", &(vote->hdr.signature) );
    fd_gossip_pretty_print_pubkey( "  - from", &(vote->data.from) );
    FD_LOG_WARNING(( "  - index: 0x%x", vote->data.index ));
    //FD_LOG_WARNING(( "  - slot: 0x%lx", vote->data.slot ));
    FD_LOG_WARNING(( "  - wallclock: 0x%lx", vote->data.wallclock ));

    /* TODO(smcio): printing out raw txn data */

    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_vote_t );
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
    FOR_EACH_U64_IN_VECTOR( lowest_slot, lowest_slot->data.slots, value ) {
      FD_LOG_WARNING(( "       - 0x%lx ", value ));
    }
    FD_LOG_WARNING(( "  - stash: obsolete" ));
    FD_LOG_WARNING(( "  - wallclock: addr = %lu", lowest_slot->data.wallclock ));

    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_lowest_slot_t );

    break;
  }

  case FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES:
  case FD_GOSSIP_CRDS_ID_ACCOUNT_HASHES:
    if( crds_id==FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES ) {
      FD_LOG_WARNING(( "  => SnapshotHashes" ));
      sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_snapshot_hashes_t );
    }
    else {
      FD_LOG_WARNING(( "  => AccountHashes" ));
      sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_account_hashes_t );
    }
    break;

  case FD_GOSSIP_CRDS_ID_EPOCH_SLOTS: 
    FD_LOG_WARNING(( "pretty-printing for EpochSlots not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_epoch_slots_t );
    break;

  case FD_GOSSIP_CRDS_ID_LEGACY_VERSION:
    FD_LOG_WARNING(( "pretty-printing for EpochSlots not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_legacy_version_t );
    break;

  case FD_GOSSIP_CRDS_ID_VERSION:
    FD_LOG_WARNING(( "pretty-printing for Version not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_version_t );
    break;

  case FD_GOSSIP_CRDS_ID_NODE_INSTANCE:
    FD_LOG_WARNING(( "pretty-printing for NodeInstance not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_node_instance_t );
    break;

  case FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED:
    FD_LOG_WARNING(( "pretty-printing for DuplicateShred not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_duplicate_shred_t );
    break;

  case FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES:
    FD_LOG_WARNING(( "pretty-printing for IncrementalSnapshotHashes not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_incremental_snapshot_hashes_t );
    break;

  case FD_GOSSIP_CRDS_ID_CONTACT_INFO:
    FD_LOG_WARNING(( "pretty-printing for ContactInfo not yet implemented" ));
    sz_to_advance_ptr = sizeof ( fd_gossip_crds_value_contact_info_t);
    break;

  default:
    FD_LOG_WARNING(( "unknown CRDS value, %u", crds_id ));
    break;
  }

  uchar *ptr = (uchar *)(*crds_hdr);
  ptr += sz_to_advance_ptr;
}

void
fd_gossip_pretty_print_arbitrary_hex( char * member_name,
                                      void * data,
                                      ulong data_sz ) {
  char buf[1024];
  char *ptr = buf;
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
  fd_gossip_pretty_print_arbitrary_hex( "      - bits", bloom_data, sz );
  FD_LOG_WARNING(( "     - num_bits_set: %lx", msg->crds_filter.bloom.num_bits_set ));
  FD_LOG_WARNING(( "     - keys: " ));
  FOR_EACH_U64_IN_VECTOR( msg, msg->crds_filter.bloom.keys, value ) {
    FD_LOG_WARNING(( "       - 0x%lx ", value ));
  }

  FD_LOG_WARNING(( "- CRDS value" ));
  fd_gossip_crds_header_t * hdr = (fd_gossip_crds_header_t *)((uchar *)msg + msg->value.offset);
  fd_gossip_pretty_print_crds_object(&hdr);
}

void
fd_gossip_pretty_print_pull_resp( fd_gossip_pull_response_t * msg ) {
  FD_LOG_WARNING(( "PullResponse" ));
  FD_LOG_WARNING(( "=============\n" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id & 0xff ));
  fd_gossip_pretty_print_pubkey( "- pubkey", &(msg->pubkey) );

  FD_LOG_WARNING(( "- CRDS ( %lu objects(s) )", msg->values.num_objs ));

  fd_gossip_crds_header_t * hdr = (fd_gossip_crds_header_t *)((uchar *)msg + msg->values.offset);
  for( ulong count = 0; count<msg->values.num_objs; count++ ) {
    fd_gossip_pretty_print_crds_object(&hdr);
  }
}

void
fd_gossip_pretty_print_push( fd_gossip_push_msg_t * msg ) {
  FD_LOG_WARNING(( "Push" ));
  FD_LOG_WARNING(( "======\n" ));

  FD_LOG_WARNING(( "- msg_id: 0x%x", msg->msg_id & 0xff ));
  fd_gossip_pretty_print_pubkey( "- pubkey", &(msg->pubkey) );

  FD_LOG_WARNING(( "- CRDS ( %lu objects(s) )", msg->values.num_objs ));

  fd_gossip_crds_header_t * hdr = (fd_gossip_crds_header_t *)((uchar *)msg + msg->values.offset);
  for( ulong count = 0; count<msg->values.num_objs; count++ ) {
    fd_gossip_pretty_print_crds_object( &hdr );
  }
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

  default:
    FD_LOG_WARNING(( "unknown gossip message type" ));
    break;
  }
}
