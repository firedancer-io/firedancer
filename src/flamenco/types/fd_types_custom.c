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
  ulong res = fd_txn_parse_core( ctx->data, bufsz, self->txn, counters, &sz );
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
  ulong res = fd_txn_parse_core( ctx->data, bufsz, self.txn, NULL, &sz );
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
  ulong res = fd_txn_parse_core( ctx->data, bufsz, self->txn, counters, &sz );
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

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L1054-L1060
    fd_compact_tower_sync_t compact_tower_sync[1];
    fd_bincode_decode_ctx_t decode_ctx = { .data = ctx->data, .dataend = ctx->dataend, .valloc = ctx->valloc };
    // Try to decode compact_tower_sync to check that lockout offsets don't cause an overflow
    int err = fd_compact_tower_sync_decode( compact_tower_sync, &decode_ctx );
    if( FD_UNLIKELY( err ) ) return err;
    ctx->data = decode_ctx.data;

    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L1061
    ulong root = compact_tower_sync->root != ULONG_MAX ? compact_tower_sync->root : 0;
    for (deq_fd_lockout_offset_t_iter_t iter = deq_fd_lockout_offset_t_iter_init( compact_tower_sync->lockout_offsets );
                                              !deq_fd_lockout_offset_t_iter_done( compact_tower_sync->lockout_offsets, iter );
                                        iter = deq_fd_lockout_offset_t_iter_next( compact_tower_sync->lockout_offsets, iter )) {
      const fd_lockout_offset_t * lockout_offset = deq_fd_lockout_offset_t_iter_ele_const( compact_tower_sync->lockout_offsets, iter );
      // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L1066
      err = __builtin_uaddl_overflow( root, lockout_offset->offset, &root );
      if( FD_UNLIKELY( err ) ) return err;
    }
    return FD_BINCODE_SUCCESS;
}

void fd_tower_sync_decode_unsafe( fd_tower_sync_t * self, fd_bincode_decode_ctx_t * ctx ) {
  self->has_root = 1;
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  self->has_root = self->root != ULONG_MAX;

  ushort lockout_offsets_len;
  fd_bincode_compact_u16_decode_unsafe( &lockout_offsets_len, ctx );
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  self->lockouts = deq_fd_vote_lockout_t_alloc( ctx->valloc, lockout_offsets_max );

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L1062-L1077
  ulong last_slot = ((self->root == ULONG_MAX) ? 0 : self->root);
  for( ulong i=0; i < lockout_offsets_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->lockouts );

    fd_lockout_offset_t o;
    fd_lockout_offset_decode_unsafe( &o, ctx );

    elem->slot = last_slot + o.offset;
    elem->confirmation_count = o.confirmation_count;
    last_slot = elem->slot;
  }

  fd_hash_decode_unsafe( &self->hash, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_timestamp = !!o;
    if( o ) {
      fd_bincode_int64_decode_unsafe( &self->timestamp, ctx );
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

int fd_archive_decode_skip_field( fd_bincode_decode_ctx_t * ctx, ushort tag ) {
  /* Extract the meta tag */
  tag = tag & (ushort)((1<<6)-1);
  uint len;
  switch( tag ) {
  case FD_ARCHIVE_META_CHAR:      len = sizeof(uchar);   break;
  case FD_ARCHIVE_META_CHAR32:    len = 32;              break;
  case FD_ARCHIVE_META_DOUBLE:    len = sizeof(double);  break;
  case FD_ARCHIVE_META_LONG:      len = sizeof(long);    break;
  case FD_ARCHIVE_META_UINT:      len = sizeof(uint);    break;
  case FD_ARCHIVE_META_UINT128:   len = sizeof(uint128); break;
  case FD_ARCHIVE_META_BOOL:      len = 1;               break;
  case FD_ARCHIVE_META_UCHAR:     len = sizeof(uchar);   break;
  case FD_ARCHIVE_META_UCHAR32:   len = 32;              break;
  case FD_ARCHIVE_META_UCHAR128:  len = 128;             break;
  case FD_ARCHIVE_META_UCHAR2048: len = 2048;            break;
  case FD_ARCHIVE_META_ULONG:     len = sizeof(ulong);   break;
  case FD_ARCHIVE_META_USHORT:    len = sizeof(ushort);  break;

  case FD_ARCHIVE_META_STRING: {
    ulong slen;
    int err = fd_bincode_uint64_decode( &slen, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    len = (uint)slen;
    break;
  }

  case FD_ARCHIVE_META_STRUCT:
  case FD_ARCHIVE_META_VECTOR:
  case FD_ARCHIVE_META_DEQUE:
  case FD_ARCHIVE_META_MAP:
  case FD_ARCHIVE_META_TREAP:
  case FD_ARCHIVE_META_OPTION:
  case FD_ARCHIVE_META_ARRAY: {
    int err = fd_bincode_uint32_decode( &len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    break;
  }

  default:
    return FD_BINCODE_ERR_ENCODING;
  }

  uchar * ptr = (uchar *)ctx->data;
  if ( FD_UNLIKELY((void *)(ptr + len) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;
  ctx->data = ptr + len;
  return FD_BINCODE_SUCCESS;
}

#define REDBLK_T fd_vote_reward_t_mapnode_t
#define REDBLK_NAME fd_vote_reward_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"

long fd_vote_reward_t_map_compare( fd_vote_reward_t_mapnode_t * left, fd_vote_reward_t_mapnode_t * right ) {
  return memcmp( left->elem.pubkey.uc, right->elem.pubkey.uc, sizeof(right->elem.pubkey) );
}
