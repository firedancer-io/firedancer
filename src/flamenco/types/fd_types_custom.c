#ifndef SOURCE_fd_src_flamenco_types_fd_types_c
#error "fd_types_custom.c is part of the fd_types.c compile uint"
#endif /* !SOURCE_fd_src_flamenco_types_fd_types_c */

#include <stdio.h>

int fd_epoch_schedule_decode(fd_epoch_schedule_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode(&self->slots_per_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode(&self->warmup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->first_normal_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode(&self->first_normal_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_schedule_new(fd_epoch_schedule_t* self) {
  self->slots_per_epoch = 0;
  self->leader_schedule_slot_offset = 0;
  self->warmup = 0;
  memset( self->_pad11, 0, 7UL );
  self->first_normal_epoch = 0;
  self->first_normal_slot = 0;
}
void fd_epoch_schedule_destroy(fd_epoch_schedule_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

void fd_epoch_schedule_walk(void * w, fd_epoch_schedule_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, 32, "fd_epoch_schedule", level++);
  fun(w, &self->slots_per_epoch, "slots_per_epoch", 11, "ulong", level + 1);
  fun(w, &self->leader_schedule_slot_offset, "leader_schedule_slot_offset", 11, "ulong", level + 1);
  fun(w, &self->warmup, "warmup", 9, "uchar", level + 1);
  fun(w, &self->first_normal_epoch, "first_normal_epoch", 11, "ulong", level + 1);
  fun(w, &self->first_normal_slot, "first_normal_slot", 11, "ulong", level + 1);
  fun(w, self, name, 33, "fd_epoch_schedule", --level);
}
ulong fd_epoch_schedule_size(fd_epoch_schedule_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_epoch_schedule_encode(fd_epoch_schedule_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(&self->slots_per_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->leader_schedule_slot_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->warmup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->first_normal_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(&self->first_normal_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

// This blob of code turns a "current" vote_state into a 1_14_11 on the fly...
static ulong fd_vote_state_transcoding_size(fd_vote_state_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->node_pubkey);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size(&ele->lockout);
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if (NULL !=  self->root_slot) {
    size += sizeof(ulong);
  }
  if ( self->authorized_voters ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( self->authorized_voters ); !deq_fd_vote_historical_authorized_voter_t_iter_done( self->authorized_voters, iter ); iter = deq_fd_vote_historical_authorized_voter_t_iter_next( self->authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( self->authorized_voters, iter );
      size += fd_vote_historical_authorized_voter_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_prior_voters_size(&self->prior_voters);
  if ( self->epoch_credits ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size(&self->last_timestamp);
  return size;
}

ulong fd_vote_transcoding_state_versioned_size(fd_vote_state_versioned_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_state_0_23_5_size(&self->inner.v0_23_5);
    break;
  }
  case 1: {
    size += fd_vote_state_1_14_11_size(&self->inner.v1_14_11);
    break;
  }
  case 2: {
    size += fd_vote_state_transcoding_size(&self->inner.current);
    break;
  }
  }
  return size;
}

static int fd_vote_transcoding_state_encode(fd_vote_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode(&self->commission, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_landed_vote_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      err = fd_vote_lockout_encode(&ele->lockout, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(&votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if (self->root_slot != NULL) {
    err = fd_bincode_option_encode(1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    err = fd_bincode_uint64_encode(self->root_slot, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_option_encode(0, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  if ( self->authorized_voters ) {
    ulong authorized_voters_len = deq_fd_vote_historical_authorized_voter_t_cnt(self->authorized_voters);
    err = fd_bincode_uint64_encode(&authorized_voters_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_historical_authorized_voter_t_iter_t iter = deq_fd_vote_historical_authorized_voter_t_iter_init( self->authorized_voters ); !deq_fd_vote_historical_authorized_voter_t_iter_done( self->authorized_voters, iter ); iter = deq_fd_vote_historical_authorized_voter_t_iter_next( self->authorized_voters, iter ) ) {
      fd_vote_historical_authorized_voter_t * ele = deq_fd_vote_historical_authorized_voter_t_iter_ele( self->authorized_voters, iter );
      err = fd_vote_historical_authorized_voter_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong authorized_voters_len = 0;
    err = fd_bincode_uint64_encode(&authorized_voters_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_prior_voters_encode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt(self->epoch_credits);
    err = fd_bincode_uint64_encode(&epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode(&epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_encode(&self->last_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

static int fd_vote_transcoding_state_versioned_inner_encode(fd_vote_state_versioned_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_state_0_23_5_encode(&self->v0_23_5, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_state_1_14_11_encode(&self->v1_14_11, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_vote_transcoding_state_encode(&self->current, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_vote_transcoding_state_versioned_encode(fd_vote_state_versioned_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (0 == self->discriminant)
    err = fd_bincode_uint32_encode(&self->discriminant, ctx);
  else {
    uint disc = 1;
    err = fd_bincode_uint32_encode(&disc, ctx);
  }
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_transcoding_state_versioned_inner_encode(&self->inner, self->discriminant, ctx);
}

void
fd_gossip_ip4_addr_walk( void *                       w,
                         fd_gossip_ip4_addr_t const * self,
                         fd_types_walk_fn_t           fun,
                         char const *                 name,
                         uint                         level ) {

  char buf[ 16 ];
  sprintf( buf, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( *self ) );
  fun( w, buf, name, FD_FLAMENCO_TYPE_CSTR, "ip4_addr", level );
}

void
fd_gossip_ip6_addr_walk( void *                       w,
                         fd_gossip_ip6_addr_t const * self,
                         fd_types_walk_fn_t           fun,
                         char const *                 name,
                         uint                         level ) {

  char buf[ 40 ];
  sprintf( buf,
           "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           self->us[ 0 ], self->us[ 1 ], self->us[ 2 ], self->us[ 3 ],
           self->us[ 4 ], self->us[ 5 ], self->us[ 6 ], self->us[ 7 ] );
  fun( w, buf, name, FD_FLAMENCO_TYPE_CSTR, "ip6_addr", level );
}
