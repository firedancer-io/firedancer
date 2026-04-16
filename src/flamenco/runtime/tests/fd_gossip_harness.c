#undef FD_SPAD_USE_HANDHOLDING
#define FD_SPAD_USE_HANDHOLDING 1

#include "fd_solfuzz_private.h"
#include "fd_gossip_harness.h"
#include "../../gossip/fd_gossip_message.h"
#include "generated/gossip.pb.h"

/* alloc_bytes allocates a pb_bytes_array_t on the spad and copies
   src[0..len) into it. */

static pb_bytes_array_t *
alloc_bytes( fd_spad_t *   spad,
             uchar const * src,
             ulong         len ) {
  pb_bytes_array_t * arr = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( len ) );
  arr->size = (pb_size_t)len;
  if( FD_LIKELY( len ) ) memcpy( arr->bytes, src, len );
  return arr;
}

static void
convert_crds_data( fd_spad_t *                      spad,
                   fd_gossip_value_t const *         val,
                   fd_exec_test_gossip_crds_data_t * out ) {
  switch( val->tag ) {
  case FD_GOSSIP_VALUE_CONTACT_INFO:
    out->which_data = FD_EXEC_TEST_GOSSIP_CRDS_DATA_CONTACT_INFO_TAG;
    out->data.contact_info.pubkey        = alloc_bytes( spad, val->origin, sizeof(val->origin) );
    out->data.contact_info.wallclock     = val->wallclock;
    out->data.contact_info.outset        = val->contact_info->outset;
    out->data.contact_info.shred_version = val->contact_info->shred_version;
    break;
  case FD_GOSSIP_VALUE_VOTE:
    out->which_data = FD_EXEC_TEST_GOSSIP_CRDS_DATA_VOTE_TAG;
    out->data.vote.index       = val->vote->index;
    out->data.vote.from        = alloc_bytes( spad, val->origin, sizeof(val->origin) );
    out->data.vote.wallclock   = val->wallclock;
    out->data.vote.transaction = alloc_bytes( spad, val->vote->transaction, val->vote->transaction_len );
    break;
  case FD_GOSSIP_VALUE_LOWEST_SLOT:
    out->which_data = FD_EXEC_TEST_GOSSIP_CRDS_DATA_LOWEST_SLOT_TAG;
    out->data.lowest_slot.index     = 0;
    out->data.lowest_slot.from      = alloc_bytes( spad, val->origin, sizeof(val->origin) );
    out->data.lowest_slot.lowest    = val->lowest_slot->lowest;
    out->data.lowest_slot.wallclock = val->wallclock;
    break;
  case FD_GOSSIP_VALUE_EPOCH_SLOTS:
    out->which_data = FD_EXEC_TEST_GOSSIP_CRDS_DATA_EPOCH_SLOTS_TAG;
    out->data.epoch_slots.index     = val->epoch_slots->index;
    out->data.epoch_slots.from      = alloc_bytes( spad, val->origin, sizeof(val->origin) );
    out->data.epoch_slots.wallclock = val->wallclock;
    break;
  case FD_GOSSIP_VALUE_SNAPSHOT_HASHES: {
    out->which_data = FD_EXEC_TEST_GOSSIP_CRDS_DATA_SNAPSHOT_HASHES_TAG;
    fd_exec_test_gossip_snapshot_hashes_t * sh = &out->data.snapshot_hashes;
    sh->from      = alloc_bytes( spad, val->origin, sizeof(val->origin) );
    sh->full_slot = val->snapshot_hashes->full_slot;
    sh->full_hash = alloc_bytes( spad, val->snapshot_hashes->full_hash, sizeof(val->snapshot_hashes->full_hash) );
    sh->wallclock = val->wallclock;
    sh->incremental_count = (pb_size_t)val->snapshot_hashes->incremental_len;
    if( sh->incremental_count ) {
      sh->incremental = fd_spad_alloc( spad, alignof(fd_exec_test_gossip_incremental_hash_t),
                                       sh->incremental_count * sizeof(fd_exec_test_gossip_incremental_hash_t) );
      for( ulong i=0UL; i<sh->incremental_count; i++ ) {
        sh->incremental[i].slot = val->snapshot_hashes->incremental[i].slot;
        sh->incremental[i].hash = alloc_bytes( spad, val->snapshot_hashes->incremental[i].hash,
                                               sizeof(val->snapshot_hashes->incremental[i].hash) );
      }
    }
    break;
  }
  case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
    out->which_data = FD_EXEC_TEST_GOSSIP_CRDS_DATA_DUPLICATE_SHRED_TAG;
    out->data.duplicate_shred.index       = val->duplicate_shred->index;
    out->data.duplicate_shred.from        = alloc_bytes( spad, val->origin, sizeof(val->origin) );
    out->data.duplicate_shred.wallclock   = val->wallclock;
    out->data.duplicate_shred.slot        = val->duplicate_shred->slot;
    out->data.duplicate_shred.shred_index = 0;
    out->data.duplicate_shred.shred_type  = 0;
    out->data.duplicate_shred.num_chunks  = val->duplicate_shred->num_chunks;
    out->data.duplicate_shred.chunk_index = val->duplicate_shred->chunk_index;
    out->data.duplicate_shred.chunk       = val->duplicate_shred->chunk_len
                                              ? alloc_bytes( spad, val->duplicate_shred->chunk, val->duplicate_shred->chunk_len )
                                              : NULL;
    break;
  default:
    /* Deprecated or unrecognized variant -- empty data */
    out->which_data = 0;
    break;
  }
}

static void
convert_crds_value( fd_spad_t *                       spad,
                    fd_gossip_value_t const *          val,
                    fd_exec_test_gossip_crds_value_t * out ) {
  out->signature = alloc_bytes( spad, val->signature, sizeof(val->signature) );
  out->has_data  = true;
  convert_crds_data( spad, val, &out->data );
}

static void
convert_crds_values( fd_spad_t *                        spad,
                     fd_gossip_value_t const *           vals,
                     ulong                               vals_len,
                     fd_exec_test_gossip_crds_value_t ** out_vals,
                     pb_size_t *                         out_count ) {
  *out_count = (pb_size_t)vals_len;
  if( !vals_len ) {
    *out_vals = NULL;
    return;
  }
  *out_vals = fd_spad_alloc( spad, alignof(fd_exec_test_gossip_crds_value_t),
                             vals_len * sizeof(fd_exec_test_gossip_crds_value_t) );
  for( ulong i=0UL; i<vals_len; i++ ) {
    convert_crds_value( spad, &vals[i], &(*out_vals)[i] );
  }
}

static void
convert_bloom( fd_spad_t *                   spad,
               fd_gossip_bloom_t const *     bloom,
               fd_exec_test_gossip_bloom_t * out ) {
  out->keys_count = (pb_size_t)bloom->keys_len;
  if( bloom->keys_len ) {
    out->keys = fd_spad_alloc( spad, alignof(uint64_t), bloom->keys_len * sizeof(uint64_t) );
    memcpy( out->keys, bloom->keys, bloom->keys_len * sizeof(uint64_t) );
  }
  /* Copy only block_len() worth of u64 blocks, not bits_cap.
     https://github.com/tov/bv-rs/blob/0.11.1/src/bit_vec/mod.rs#L243-L245 */
  ulong bits_blocks   = (bloom->bits_len + 63UL) / 64UL;
  ulong bits_byte_len = bits_blocks * sizeof(bloom->bits[0]);
  out->bits = alloc_bytes( spad, (uchar const *)bloom->bits, bits_byte_len );
  /* Mask trailing bits beyond bits_len in the last block of the
     protobuf copy.  bv::BitVec::get_block() returns get_masked_block()
     which zeros bits past bit_len() in the last block.
     https://github.com/tov/bv-rs/blob/0.11.1/src/bit_vec/impls.rs#L30-L32
     https://github.com/tov/bv-rs/blob/0.11.1/src/traits/bits.rs#L134-L137 */
  if( bloom->bits_len & 63UL ) {
    ulong last = bits_blocks - 1UL;
    ulong mask = ( 2UL << ((bloom->bits_len - 1UL) & 63UL) ) - 1UL;
    ((ulong *)out->bits->bytes)[ last ] &= mask;
  }
  out->num_bits_set = bloom->num_bits_set;
}

static void
convert_gossip_msg( fd_spad_t *                 spad,
                    fd_gossip_message_t const * msg,
                    fd_exec_test_gossip_msg_t * out ) {
  switch( msg->tag ) {
  case FD_GOSSIP_MESSAGE_PING:
    out->which_msg = FD_EXEC_TEST_GOSSIP_MSG_PING_TAG;
    out->msg.ping.from      = alloc_bytes( spad, msg->ping->from,      sizeof(msg->ping->from) );
    out->msg.ping.token     = alloc_bytes( spad, msg->ping->token,     sizeof(msg->ping->token) );
    out->msg.ping.signature = alloc_bytes( spad, msg->ping->signature, sizeof(msg->ping->signature) );
    break;
  case FD_GOSSIP_MESSAGE_PONG:
    out->which_msg = FD_EXEC_TEST_GOSSIP_MSG_PONG_TAG;
    out->msg.pong.from      = alloc_bytes( spad, msg->pong->from,      sizeof(msg->pong->from) );
    out->msg.pong.hash      = alloc_bytes( spad, msg->pong->hash,      sizeof(msg->pong->hash) );
    out->msg.pong.signature = alloc_bytes( spad, msg->pong->signature, sizeof(msg->pong->signature) );
    break;
  case FD_GOSSIP_MESSAGE_PULL_REQUEST: {
    out->which_msg = FD_EXEC_TEST_GOSSIP_MSG_PULL_REQUEST_TAG;
    fd_exec_test_gossip_pull_request_t * pr = &out->msg.pull_request;
    pr->has_filter = true;
    pr->filter.has_filter = true;
    convert_bloom( spad, msg->pull_request->crds_filter->filter, &pr->filter.filter );
    pr->filter.mask      = msg->pull_request->crds_filter->mask;
    pr->filter.mask_bits = msg->pull_request->crds_filter->mask_bits;
    pr->has_value = true;
    convert_crds_value( spad, msg->pull_request->contact_info, &pr->value );
    break;
  }
  case FD_GOSSIP_MESSAGE_PULL_RESPONSE: {
    out->which_msg = FD_EXEC_TEST_GOSSIP_MSG_PULL_RESPONSE_TAG;
    fd_exec_test_gossip_pull_response_t * pr = &out->msg.pull_response;
    pr->pubkey = alloc_bytes( spad, msg->pull_response->from, sizeof(msg->pull_response->from) );
    convert_crds_values( spad, msg->pull_response->values,
                         msg->pull_response->values_len,
                         &pr->values, &pr->values_count );
    break;
  }
  case FD_GOSSIP_MESSAGE_PUSH: {
    out->which_msg = FD_EXEC_TEST_GOSSIP_MSG_PUSH_MESSAGE_TAG;
    fd_exec_test_gossip_push_message_t * pm = &out->msg.push_message;
    pm->pubkey = alloc_bytes( spad, msg->push->from, sizeof(msg->push->from) );
    convert_crds_values( spad, msg->push->values,
                         msg->push->values_len,
                         &pm->values, &pm->values_count );
    break;
  }
  case FD_GOSSIP_MESSAGE_PRUNE: {
    out->which_msg = FD_EXEC_TEST_GOSSIP_MSG_PRUNE_MESSAGE_TAG;
    fd_exec_test_gossip_prune_message_t * pm = &out->msg.prune_message;
    pm->pubkey   = alloc_bytes( spad, msg->prune->sender,      sizeof(msg->prune->sender) );
    pm->has_data = true;
    pm->data.pubkey      = alloc_bytes( spad, msg->prune->pubkey,      sizeof(msg->prune->pubkey) );
    pm->data.signature   = alloc_bytes( spad, msg->prune->signature,   sizeof(msg->prune->signature) );
    pm->data.destination = alloc_bytes( spad, msg->prune->destination, sizeof(msg->prune->destination) );
    pm->data.wallclock   = msg->prune->wallclock;
    pm->data.prunes_count = (pb_size_t)msg->prune->prunes_len;
    if( msg->prune->prunes_len ) {
      pm->data.prunes = fd_spad_alloc( spad, alignof(pb_bytes_array_t *),
                                       msg->prune->prunes_len * sizeof(pb_bytes_array_t *) );
      for( ulong i=0UL; i<msg->prune->prunes_len; i++ ) {
        pm->data.prunes[i] = alloc_bytes( spad, msg->prune->prunes[i], sizeof(msg->prune->prunes[i]) );
      }
    }
    break;
  }
  default:
    out->which_msg = 0;
    break;
  }
}

int
fd_solfuzz_gossip_decode( fd_solfuzz_runner_t * runner,
                          uchar *               out,
                          ulong *               out_sz,
                          uchar const *         in,
                          ulong                 in_sz ) {
  fd_gossip_message_t * msg = fd_spad_alloc( runner->spad, alignof(fd_gossip_message_t), sizeof(fd_gossip_message_t) );
  fd_memset( msg, 0, sizeof(fd_gossip_message_t) );
  fd_exec_test_gossip_effects_t effects = FD_EXEC_TEST_GOSSIP_EFFECTS_INIT_ZERO;

  int ok = fd_gossip_message_deserialize( msg, in, in_sz );
  if( ok ) {
    effects.valid   = true;
    effects.has_msg = true;
    convert_gossip_msg( runner->spad, msg, &effects.msg );
  } else {
    effects.valid   = false;
    effects.has_msg = false;
  }

  return !!sol_compat_encode( out, out_sz, &effects, &fd_exec_test_gossip_effects_t_msg );
}
