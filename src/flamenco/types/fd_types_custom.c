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

void fd_option_slot_new(fd_option_slot_t* self) {
  fd_memset(self, 0, sizeof(fd_option_slot_t));
}
int fd_option_slot_decode(fd_option_slot_t* self, fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bool_decode(&self->is_some, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( !self->is_some ) return FD_BINCODE_SUCCESS;
  err = fd_bincode_uint64_decode(&self->slot, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
int fd_option_slot_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  uchar is_some;
  err = fd_bincode_bool_decode(&is_some, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( !is_some ) return FD_BINCODE_SUCCESS;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_option_slot_decode_unsafe(fd_option_slot_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_bool_decode_unsafe(&self->is_some, ctx);
  if ( !self->is_some ) return;
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
}
int fd_option_slot_encode(fd_option_slot_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bool_encode(self->is_some, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( !self->is_some ) return FD_BINCODE_SUCCESS;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_option_slot_destroy(fd_option_slot_t* self, fd_bincode_destroy_ctx_t * ctx) {
}
ulong fd_option_slot_footprint( void ){ return FD_OPTION_SLOT_FOOTPRINT; }
ulong fd_option_slot_align( void ){ return FD_OPTION_SLOT_ALIGN; }
void fd_option_slot_walk(void * w, fd_option_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun( w, &self->slot, name, FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
}
ulong fd_option_slot_size(fd_option_slot_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if (self->is_some) size += sizeof(ulong);
  return size;
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
