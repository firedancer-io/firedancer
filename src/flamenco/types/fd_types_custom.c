#include "fd_types.h"
#ifndef SOURCE_fd_src_flamenco_types_fd_types_c
#error "fd_types_custom.c is part of the fd_types.c compile uint"
#endif /* !SOURCE_fd_src_flamenco_types_fd_types_c */

#include <stdio.h>

int
fd_flamenco_txn_decode( fd_flamenco_txn_t *       self,
                        fd_bincode_decode_ctx_t * ctx ) {
  static FD_TL fd_txn_parse_counters_t counters[1];
  ulong bufsz = (ulong)ctx->dataend - (ulong)ctx->data;
  ulong sz;
  ulong res = fd_txn_parse_core( ctx->data, bufsz, self->txn, counters, &sz, 0 );
  if( FD_UNLIKELY( !res ) ) {
    /* TODO: Remove this debug print in prod */
    FD_LOG_DEBUG(( "Failed to decode txn (fd_txn.c:%lu)",
                   counters->failure_ring[ counters->failure_cnt % FD_TXN_PARSE_COUNTERS_RING_SZ ] ));
    return -1000001;
  }
  fd_memcpy( self->raw, ctx->data, sz );
  self->raw_sz = sz;
  ctx->data = (void *)( (ulong)ctx->data + sz );
  return 0;
}

int
fd_flamenco_txn_decode_preflight( fd_bincode_decode_ctx_t * ctx ) {
  ulong bufsz = (ulong)ctx->dataend - (ulong)ctx->data;
  fd_flamenco_txn_t self;
  ulong sz;
  ulong res = fd_txn_parse_core( ctx->data, bufsz, self.txn, NULL, &sz, 0 );
  if( FD_UNLIKELY( !res ) ) {
    return -1000001;
  }
  ctx->data = (void *)( (ulong)ctx->data + sz );
  return 0;
}

void
fd_flamenco_txn_decode_unsafe( fd_flamenco_txn_t *       self,
                               fd_bincode_decode_ctx_t * ctx ) {
  static FD_TL fd_txn_parse_counters_t counters[1];
  ulong bufsz = (ulong)ctx->dataend - (ulong)ctx->data;
  ulong sz;
  ulong res = fd_txn_parse_core( ctx->data, bufsz, self->txn, counters, &sz, 0 );
  if( FD_UNLIKELY( !res ) ) {
    FD_LOG_ERR(( "Failed to decode txn (fd_txn.c:%lu)",
                 counters->failure_ring[ counters->failure_cnt % FD_TXN_PARSE_COUNTERS_RING_SZ ] ));
    return;
  }
  fd_memcpy( self->raw, ctx->data, sz );
  self->raw_sz = sz;
  ctx->data = (void *)( (ulong)ctx->data + sz );
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
           FD_LOG_HEX16_FMT_ARGS( self->us ) );
  fun( w, buf, name, FD_FLAMENCO_TYPE_CSTR, "ip6_addr", level );
}

int fd_tower_sync_decode( fd_tower_sync_t * self, fd_bincode_decode_ctx_t * ctx ) {
  void const * data = ctx->data;
  int err = fd_tower_sync_decode_preflight( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_tower_sync_new( self );
  fd_tower_sync_decode_unsafe( self, ctx );
  return FD_BINCODE_SUCCESS;
}

int fd_tower_sync_decode_preflight( fd_bincode_decode_ctx_t * ctx ) {
  return fd_compact_tower_sync_decode_preflight( ctx );
}

void fd_tower_sync_decode_unsafe( fd_tower_sync_t * self, fd_bincode_decode_ctx_t * ctx ) {
  self->has_root = 1;
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  self->has_root = self->root != ULONG_MAX;

  ushort lockout_offsets_len;
  fd_bincode_compact_u16_decode_unsafe( &lockout_offsets_len, ctx );
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  self->lockouts = deq_fd_vote_lockout_t_alloc( ctx->valloc, lockout_offsets_max );

  for( ulong i=0; i < lockout_offsets_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->lockouts );

    fd_lockout_offset_t o;
    fd_lockout_offset_decode_unsafe( &o, ctx );

    elem->slot = ((self->root == ULONG_MAX) ? 0 : self->root)  + o.offset;
    elem->confirmation_count = o.confirmation_count;
  }

  fd_hash_decode_unsafe( &self->hash, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_timestamp = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->timestamp, ctx );
    }
  }
  fd_hash_decode_unsafe( &self->block_id, ctx );
}

int fd_tower_sync_decode_offsets( fd_tower_sync_off_t * self, fd_bincode_decode_ctx_t * ctx ) {
  FD_LOG_ERR(( "todo"));
}

int fd_tower_sync_encode( fd_tower_sync_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  FD_LOG_ERR(( "todo"));
}

int fd_solana_vote_account_decode( fd_solana_vote_account_t * self, fd_bincode_decode_ctx_t * ctx ) {
  void const * data = ctx->data;
  int err = fd_solana_vote_account_decode_preflight( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_solana_vote_account_new( self );
  fd_solana_vote_account_decode_unsafe( self, ctx );
  return FD_BINCODE_SUCCESS;
}

int fd_solana_vote_account_decode_preflight( fd_bincode_decode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_decode_preflight( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong data_len;
  err = fd_bincode_uint64_decode( &data_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( data_len ) {
    err = fd_bincode_bytes_decode_preflight( data_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight( 32, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_preflight( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_preflight( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}

void fd_solana_vote_account_decode_unsafe( fd_solana_vote_account_t * self, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  ulong data_len;
  fd_bincode_uint64_decode_unsafe( &data_len, ctx );
  if( data_len ) {
    uchar * data = fd_valloc_malloc( ctx->valloc, 8UL, data_len );
    fd_bincode_bytes_decode_unsafe( data, data_len, ctx );

    FD_SCRATCH_SCOPE_BEGIN {
      /* Deserialize content */
      fd_vote_block_timestamp_t vote_ts;
      fd_vote_state_versioned_t vs[1];
      fd_bincode_decode_ctx_t decode =
          { .data    = data,
            .dataend = data + data_len,
            .valloc  = fd_scratch_virtual() };
      int decode_err = fd_vote_state_versioned_decode( vs, &decode );
      if( FD_LIKELY( decode_err==FD_BINCODE_SUCCESS ) ) {
        switch( vs->discriminant )
        {
        case fd_vote_state_versioned_enum_current:
          vote_ts = vs->inner.current.last_timestamp;
          self->node_pubkey = vs->inner.current.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v0_23_5:
          vote_ts = vs->inner.v0_23_5.last_timestamp;
          self->node_pubkey    = vs->inner.v0_23_5.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v1_14_11:
          vote_ts = vs->inner.v1_14_11.last_timestamp;
          self->node_pubkey    = vs->inner.v1_14_11.node_pubkey;
          break;
        default:
          __builtin_unreachable();
        }
        self->last_timestamp_ts = vote_ts.timestamp;
        self->last_timestamp_slot = vote_ts.slot;
      } else {
        FD_LOG_DEBUG(( "fd_vote_state_versioned_decode failed (%d)", decode_err ));
        self->last_timestamp_ts = 0;
        self->last_timestamp_slot = 0;
        fd_memset( &self->node_pubkey, 0UL, sizeof(fd_pubkey_t) );
      }
    } FD_SCRATCH_SCOPE_END;

    fd_valloc_free( ctx->valloc, data );
  } else {
    self->last_timestamp_ts = 0;
    self->last_timestamp_slot = 0;
    fd_memset( &self->node_pubkey, 0UL, sizeof(fd_pubkey_t) );
  }

  fd_pubkey_decode_unsafe( &self->owner, ctx );
  fd_bincode_uint8_decode_unsafe( &self->executable, ctx );
  fd_bincode_uint64_decode_unsafe( &self->rent_epoch, ctx );
}

void fd_solana_vote_account_new(fd_solana_vote_account_t * self) {
  fd_memset( self, 0, sizeof(fd_solana_vote_account_t) );
  fd_pubkey_new( &self->node_pubkey );
  fd_pubkey_new( &self->owner );
}

void fd_solana_vote_account_destroy( fd_solana_vote_account_t * self, fd_bincode_destroy_ctx_t * ctx ) {
  fd_pubkey_destroy( &self->node_pubkey, ctx );
  fd_pubkey_destroy( &self->owner, ctx );
}

ulong fd_solana_vote_account_footprint( void ){ return FD_SOLANA_VOTE_ACCOUNT_FOOTPRINT; }
ulong fd_solana_vote_account_align( void ){ return FD_SOLANA_VOTE_ACCOUNT_ALIGN; }

void fd_solana_vote_account_walk( void * w, fd_solana_vote_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level ) {
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_vote_account", level++ );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  fd_pubkey_walk( w, &self->node_pubkey, fun, "node_pubkey", level );
  fun( w, &self->last_timestamp_ts, "last_timestamp_ts", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  fun( w, &self->last_timestamp_slot, "last_timestamp_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  fd_pubkey_walk( w, &self->owner, fun, "owner", level );
  fun( w, &self->executable, "executable", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun( w, &self->rent_epoch, "rent_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_vote_account", level-- );
}

ulong fd_solana_vote_account_size( fd_solana_vote_account_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  fd_pubkey_t null_key = {0};
  size += sizeof(ulong);
  if( memcmp( self->node_pubkey.key, null_key.key, sizeof(fd_pubkey_t) ) ) {
    fd_vote_state_versioned_t vote_state;
    fd_vote_state_versioned_new_disc( &vote_state, fd_vote_state_versioned_enum_current );
    vote_state.inner.current.node_pubkey = self->node_pubkey;
    vote_state.inner.current.last_timestamp = (fd_vote_block_timestamp_t){
      .timestamp =  self->last_timestamp_ts,
      .slot      =  self->last_timestamp_slot
    };
    size += fd_vote_state_versioned_size( &vote_state );
  }
  size += fd_pubkey_size( &self->owner );
  size += sizeof(char);
  size += sizeof(ulong);
  return size;
}

int fd_solana_vote_account_encode( fd_solana_vote_account_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  fd_pubkey_t null_key = {0};
  if( memcmp( self->node_pubkey.key, null_key.key, sizeof(fd_pubkey_t) ) ) {
    fd_vote_state_versioned_t vote_state;
    fd_vote_state_versioned_new_disc( &vote_state, fd_vote_state_versioned_enum_current );
    vote_state.inner.current.node_pubkey = self->node_pubkey;
    vote_state.inner.current.last_timestamp = (fd_vote_block_timestamp_t){
      .timestamp =  self->last_timestamp_ts,
      .slot      =  self->last_timestamp_slot
    };
    ulong data_len = fd_vote_state_versioned_size( &vote_state );
    err = fd_bincode_uint64_encode( data_len, ctx );
    if( FD_UNLIKELY(err) ) return err;
    err = fd_vote_state_versioned_encode( &vote_state, ctx );
    if( FD_UNLIKELY(err) ) return err;
  } else {
    err = fd_bincode_uint64_encode( 0UL, ctx );
    if( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode( &self->owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->executable), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->rent_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
