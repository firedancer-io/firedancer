#include "fd_types_custom.h"
#include "fd_bincode.h"
#include "fd_types.h"
#include "fd_types_meta.h"
#ifndef SOURCE_fd_src_flamenco_types_fd_types_c
#error "fd_types_custom.c is part of the fd_types.c compile unit"
#endif /* !SOURCE_fd_src_flamenco_types_fd_types_c */

#include "../runtime/fd_system_ids.h"
#include "../runtime/fd_executor_err.h"

#include <stdio.h>

int
fd_flamenco_txn_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_flamenco_txn_t);
  void const * start_data = ctx->data;
  int err = fd_flamenco_txn_decode_footprint_inner( ctx, total_sz );
  ctx->data = start_data;
  return err;
}

int
fd_flamenco_txn_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  ulong bufsz = (ulong)ctx->dataend - (ulong)ctx->data;
  fd_flamenco_txn_t self;
  ulong sz  = 0UL;
  ulong res = fd_txn_parse_core( ctx->data,
                                 bufsz,
                                 self.txn,
                                 NULL,
                                 &sz );
  if( FD_UNLIKELY( !res ) ) {
    return -1000001;
  }
  ctx->data  = (void *)( (ulong)ctx->data + sz );
  *total_sz += sz;
  return 0;
}

int FD_FN_UNUSED
fd_flamenco_txn_encode_global( fd_flamenco_txn_t const * self,
                               fd_bincode_encode_ctx_t * ctx ) {
  (void)self;
  (void)ctx;
  FD_LOG_ERR(( "only exists for testing" ));
}

void * FD_FN_UNUSED
fd_flamenco_txn_decode_global( void *                    mem,
                               fd_bincode_decode_ctx_t * ctx ) {
  (void)mem;
  (void)ctx;
  FD_LOG_ERR(( "only exists for testing" ));
}

void *
fd_flamenco_txn_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_flamenco_txn_t * self = (fd_flamenco_txn_t *)mem;
  fd_flamenco_txn_new( self );
  void *   alloc_region = (uchar *)mem + sizeof(fd_flamenco_txn_t);
  void * * alloc_mem    = &alloc_region;
  fd_flamenco_txn_decode_inner( mem, alloc_mem, ctx );
  return self;
}

int
fd_flamenco_txn_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_flamenco_txn_t * self = (fd_flamenco_txn_t *)struct_mem;
  static FD_TL fd_txn_parse_counters_t counters[1];
  ulong bufsz = (ulong)ctx->dataend - (ulong)ctx->data;
  ulong sz    = 0UL;
  ulong res   = fd_txn_parse_core( ctx->data,
                                   bufsz,
                                   self->txn,
                                   counters,
                                   &sz );
  if( FD_UNLIKELY( !res ) ) {
    // Footprint should have protected us above so we should never get here...
    FD_LOG_WARNING(( "Failed to decode txn (fd_txn.c:%lu)",
                 counters->failure_ring[ counters->failure_cnt % FD_TXN_PARSE_COUNTERS_RING_SZ ] ));
    return FD_BINCODE_ERR_UNDERFLOW;
  }
  fd_memcpy( self->raw, ctx->data, sz );
  self->raw_sz = sz;
  ctx->data = (void *)( (ulong)ctx->data + sz );
  return FD_BINCODE_SUCCESS;
}

void
fd_gossip_ip4_addr_walk( void *                       w,
                         fd_gossip_ip4_addr_t const * self,
                         fd_types_walk_fn_t           fun,
                         char const *                 name,
                         uint                         level,
                         uint                         varint ) {
  (void) varint;

  fun( w, self, name, FD_FLAMENCO_TYPE_ARR, "ip4_addr", level++, 0 );
  uchar * octet = (uchar *)self;
  for( uchar i = 0; i < 4; ++i ) {
    fun( w, &octet[i], name, FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ARR_END, "ip4_addr", level--, 0 );
  /* TODO: Add support for optional pretty-printing like serde?
     Saving this in the meantime */
  // char buf[ 16 ];
  // sprintf( buf, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( *self ) );
  // fun( w, buf, name, FD_FLAMENCO_TYPE_CSTR, "ip4_addr", level );
}

void
fd_gossip_ip6_addr_walk( void *                       w,
                         fd_gossip_ip6_addr_t const * self,
                         fd_types_walk_fn_t           fun,
                         char const *                 name,
                         uint                         level,
                         uint                         varint ) {
  (void) varint;

  fun( w, self, name, FD_FLAMENCO_TYPE_ARR, "ip6_addr", level++, 0 );
  uchar * octet = (uchar *)self;
  for( uchar i = 0; i < 16; ++i ) {
    fun( w, &octet[i], name, FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ARR_END, "ip6_addr", level--, 0 );
  /* Saving this for when we support configurable pretty-printing mode */
  // char buf[ 40 ];
  // sprintf( buf,
  //          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
  //          FD_LOG_HEX16_FMT_ARGS( self->us ) );
  // fun( w, buf, name, FD_FLAMENCO_TYPE_CSTR, "ip6_addr", level );
}

int fd_tower_sync_encode( fd_tower_sync_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  FD_LOG_ERR(( "todo"));
}

static int fd_hash_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );
static int fd_hash_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
static int fd_lockout_offset_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );
static int fd_lockout_offset_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
static int fd_vote_accounts_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );
static int fd_vote_accounts_pair_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );

int fd_tower_sync_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  /* This is a modified version of fd_compact_tower_sync_decode_footprint_inner() */
  int err = 0;
  if( FD_UNLIKELY( ctx->data>ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_bincode_uint64_decode_footprint( ctx );

  /* The first modification is that we want to grab the value fo the root. */
  ulong root = 0UL;
  fd_bincode_decode_ctx_t root_ctx = { .data = (uchar*)ctx->data - sizeof(ulong), .dataend = ctx->data };
  if( FD_UNLIKELY( ((ulong)ctx->data)+sizeof(ulong)>(ulong)ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  fd_bincode_uint64_decode_unsafe( &root, &root_ctx );
  root = root != ULONG_MAX ? root : 0UL;
  /* Done with first modification */

  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ushort lockout_offsets_len;
  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_bincode_compact_u16_decode( &lockout_offsets_len, ctx );

  if( FD_UNLIKELY( err ) ) return err;
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  *total_sz += deq_fd_lockout_offset_t_align() + deq_fd_lockout_offset_t_footprint( lockout_offsets_max );

  for( ulong i = 0; i < lockout_offsets_len; ++i ) {

    uchar const * start_data = ctx->data;
    err = fd_lockout_offset_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;

    /* The second modification is that we want to grab the lockout offset from
    the deque to make sure that we can do a checked add successfully. */
    fd_lockout_offset_t lockout_offset = {0};
    fd_bincode_decode_ctx_t lockout_ctx = { .data = start_data, .dataend = start_data+sizeof(fd_lockout_offset_t) };
    if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
    fd_lockout_offset_decode_inner( &lockout_offset, NULL, &lockout_ctx );
    err = __builtin_uaddl_overflow( root, lockout_offset.offset, &root );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    /* Done with second modification. */
  }

  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}

int fd_tower_sync_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_tower_sync_t);
  void const * start_data = ctx->data;
  int err = fd_tower_sync_decode_footprint_inner( ctx, total_sz );
  ctx->data = start_data;
  return err;
}

int fd_tower_sync_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_tower_sync_t * self = (fd_tower_sync_t *)struct_mem;
  self->has_root = 1;
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  self->has_root = self->root != ULONG_MAX;

  ushort lockout_offsets_len;
  fd_bincode_compact_u16_decode_unsafe( &lockout_offsets_len, ctx );
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  self->lockouts = deq_fd_vote_lockout_t_join_new( alloc_mem, lockout_offsets_max );

  /* NOTE: Agave does a a checked add on the sum of the root with all of the
     lockout offsets in their custom deserializer for tower sync votes. If the
     checked add is violated (this should never happen), the decode will
     return NULL.  */

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L1062-L1077
  ulong last_slot = ((self->root == ULONG_MAX) ? 0 : self->root);
  for( ulong i=0; i < lockout_offsets_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->lockouts );

    fd_lockout_offset_t o;
    fd_lockout_offset_decode_inner( &o, alloc_mem, ctx );

    elem->slot = last_slot + o.offset;
    elem->confirmation_count = o.confirmation_count;
    last_slot = elem->slot;
  }

  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_timestamp = !!o;
    if( o ) {
      fd_bincode_int64_decode_unsafe( &self->timestamp, ctx );
    }
  }
  fd_hash_decode_inner( &self->block_id, alloc_mem, ctx );
  return FD_BINCODE_SUCCESS;
}

void * fd_tower_sync_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_tower_sync_t * self = (fd_tower_sync_t *)mem;
  fd_tower_sync_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_tower_sync_t);
  void * * alloc_mem = &alloc_region;
  fd_tower_sync_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_tower_sync_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  FD_LOG_ERR(("TODO: Implement"));
}

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/de/impls.rs#L2374
//
// During the call to Duration::new(...), it normalizes the seconds and nanoseconds automatically.  We need to
// match this behavior correctly
//
void
fd_rust_duration_normalize ( fd_rust_duration_t * self ) {
  if( self->nanoseconds < 1000000000U )
    return;
  uint secs = self->nanoseconds/1000000000U;
  self->seconds += secs;
  self->nanoseconds -= secs * 1000000000U;
}

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/de/impls.rs#L2203
//
// There is an overflow check at line 2373 that turns an overflow into an encoding error
//
int
fd_rust_duration_footprint_validator ( fd_bincode_decode_ctx_t * ctx ) {
  fd_rust_duration_t *d = (fd_rust_duration_t *) ctx->data;
  if( d->nanoseconds < 1000000000U )
    return FD_BINCODE_SUCCESS;
  ulong out;
  if( __builtin_uaddl_overflow( d->seconds, d->nanoseconds/1000000000U, &out ) )
    return FD_BINCODE_ERR_ENCODING;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_accounts_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_accounts_t * self = (fd_vote_accounts_t *)struct_mem;
  ulong vote_accounts_len;
  fd_bincode_uint64_decode_unsafe( &vote_accounts_len, ctx );
  self->vote_accounts_pool = fd_vote_accounts_pair_t_map_join_new( alloc_mem, fd_ulong_max( vote_accounts_len, 50000 ) );
  self->vote_accounts_root = NULL;
  for( ulong i=0; i < vote_accounts_len; i++ ) {
    fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_acquire( self->vote_accounts_pool );
    fd_vote_accounts_pair_new( &node->elem );
    fd_vote_accounts_pair_decode_inner( &node->elem, alloc_mem, ctx );
    // https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/vote/src/vote_account.rs#L323
    // throws an error and
    if( FD_UNLIKELY( 0!=memcmp( node->elem.value.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      // https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/vote/src/vote_account.rs#L429
      // causes the entry to not get added
      fd_vote_accounts_pair_t_map_release( self->vote_accounts_pool, node );
    } else {
      fd_vote_accounts_pair_t_mapnode_t * out = NULL;
      fd_vote_accounts_pair_t_map_insert_or_replace( self->vote_accounts_pool, &self->vote_accounts_root, node, &out );
      if( !!out ) {
        fd_vote_accounts_pair_t_map_release( self->vote_accounts_pool, out );
      }
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_vote_accounts_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_accounts_global_t * self = (fd_vote_accounts_global_t *)struct_mem;
  ulong vote_accounts_len;
  fd_bincode_uint64_decode_unsafe( &vote_accounts_len, ctx );
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_vote_accounts_pair_global_t_map_align() );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_pair_global_t_map_join_new( alloc_mem, fd_ulong_max( vote_accounts_len, 50000 ) );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = NULL;
  for( ulong i=0; i < vote_accounts_len; i++ ) {
    fd_vote_accounts_pair_global_t_mapnode_t * node = fd_vote_accounts_pair_global_t_map_acquire( vote_accounts_pool );
    fd_vote_accounts_pair_new( (fd_vote_accounts_pair_t *)fd_type_pun(&node->elem) );
    fd_vote_accounts_pair_decode_inner_global( &node->elem, alloc_mem, ctx );
    if( FD_UNLIKELY( 0!=memcmp( node->elem.value.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      fd_vote_accounts_pair_global_t_map_release( vote_accounts_pool, node );
    } else {
      fd_vote_accounts_pair_global_t_mapnode_t * out = NULL;
      fd_vote_accounts_pair_global_t_map_insert_or_replace( vote_accounts_pool, &vote_accounts_root, node, &out );
      if( !!out ) {
        fd_vote_accounts_pair_global_t_map_release( vote_accounts_pool, out );
      }
    }
  }
  self->vote_accounts_pool_offset = (ulong)fd_vote_accounts_pair_global_t_map_leave( vote_accounts_pool ) - (ulong)struct_mem;
  self->vote_accounts_root_offset = (ulong)vote_accounts_root - (ulong)struct_mem;
  return FD_BINCODE_SUCCESS;
}

#define REDBLK_T fd_stake_weight_t_mapnode_t
#define REDBLK_NAME fd_stake_weight_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
long fd_stake_weight_t_map_compare( fd_stake_weight_t_mapnode_t * left, fd_stake_weight_t_mapnode_t * right ) {
  return memcmp( left->elem.key.uc, right->elem.key.uc, sizeof(right->elem.key) );
}

/* Validates the integrity of ContactInfo v2 address and socket data structures.
   This is the C equivalent of sanitize_entries() in Agave's contact_info.rs.

   ContactInfo v2 uses a compact representation where:
   - IP addresses are stored in a separate vector (addrs)
   - Socket entries reference addresses by index and have cumulative port offsets
   - Each socket has a unique protocol key (gossip, tpu, rpc, etc.)

   This function ensures the data structure is internally consistent and prevents
   various attack vectors like integer overflows or invalid references.

   Returns FD_BINCODE_SUCCESS on valid data, FD_BINCODE_ERR_ENCODING on validation failure.

   Reference: https://github.com/firedancer-io/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/contact_info.rs#L599 */
int fd_sanitize_entries( fd_gossip_contact_info_v2_t *self) {

  /* =======================================================================
     VALIDATION 1: IP ADDRESS UNIQUENESS
     ======================================================================= */

  /* Ensure all IP addresses in the addrs vector are unique.

     DIFFERENCE FROM RUST:
     - Rust uses HashSet::insert() which is O(n) average case
     - C implementation uses nested loops with memcmp() which is O(n²)
     - Trade-off: C version is simpler but less efficient for large addr lists

     In practice, ContactInfo typically has <10 addresses so performance difference is minimal. */
  for( ulong i = 0; i < self->addrs_len; i++ ) {
    for( ulong j = i + 1; j < self->addrs_len; j++ ) {
      if( FD_UNLIKELY( 0 == memcmp( &self->addrs[i], &self->addrs[j], sizeof(fd_gossip_ip_addr_t) ) ) ) {
        return FD_BINCODE_ERR_ENCODING; // Duplicate IP address detected
      }
    }
  }

  /* =======================================================================
     VALIDATION 2: SOCKET KEY UNIQUENESS
     ======================================================================= */

  /* Ensure all socket entries have unique protocol keys (gossip=0, rpc=2, tpu=5, etc.).
     Uses a 256-bit bitmask to efficiently track which keys have been seen.

     SAME AS RUST: Both implementations use identical 4×64-bit bitmask approach.
     This allows O(1) duplicate detection for any 8-bit key value. */
  ulong mask[4] = {0}; // 256-bit bitmask: each bit represents one possible key (0-255)
  for( ulong i = 0; i < self->sockets_len; i++ ) {
    uchar key = self->sockets[i].key;
    ulong mask_idx = key / 64;     // Which of the 4 ulong values to use
    ulong bit = 1UL << (key % 64); // Which bit within that ulong

    if( FD_UNLIKELY( (mask[mask_idx] & bit) != 0 ) ) {
      return FD_BINCODE_ERR_ENCODING; // Duplicate socket key detected
    }
    mask[mask_idx] |= bit; // Mark this key as seen
  }

  /* =======================================================================
     VALIDATION 3: ADDRESS REFERENCE INTEGRITY
     ======================================================================= */

  /* Verify bidirectional consistency between addrs and sockets:
     1. Every socket.index must reference a valid address (< addrs_len)
     2. Every address must be referenced by at least one socket

     This prevents:
     - Out-of-bounds array access attacks
     - Unused/orphaned addresses that waste space
     - Invalid socket configurations */
  if( self->addrs_len > 0 ) {
    /* Track which addresses are referenced by sockets.

       DIFFERENCE FROM RUST:
       - Rust uses Vec<bool> allocated on heap
       - C uses fd_alloca() for stack allocation (more efficient for small sizes)
       - Both use the same boolean array algorithm */
    uchar *hits = (uchar*)fd_alloca( 1, self->addrs_len );
    fd_memset( hits, 0, self->addrs_len );

    /* Mark all addresses that are referenced by sockets */
    for( ulong i = 0; i < self->sockets_len; i++ ) {
      uchar index = self->sockets[i].index;

      /* Check for both out-of-bounds access */
      if( FD_UNLIKELY( index >= self->addrs_len ) ) {
        return FD_BINCODE_ERR_ENCODING; // Invalid/duplicate IP address index
      }
      hits[index] = 1;
    }

    /* Ensure every address is used by at least one socket */
    for( ulong i = 0; i < self->addrs_len; i++ ) {
      if( FD_UNLIKELY( !hits[i] ) ) {
        return FD_BINCODE_ERR_ENCODING; // Unused IP address detected
      }
    }
  } else if( self->sockets_len > 0 ) {
    return FD_BINCODE_ERR_ENCODING; // Unused IP address detected
  }

  /* =======================================================================
     VALIDATION 4: PORT OFFSET OVERFLOW PROTECTION
     ======================================================================= */

  /* ContactInfo uses cumulative port offsets to save space:
     - Socket 0: port = base_port + offset[0]
     - Socket 1: port = base_port + offset[0] + offset[1]
     - Socket 2: port = base_port + offset[0] + offset[1] + offset[2]
     - etc.

     Must ensure the sum doesn't exceed 16-bit port number range (0-65535).

     SAME AS RUST: Both use 16-bit arithmetic and check for overflow.
     Rust uses checked_add() + try_fold(), C uses manual overflow detection. */
  ushort total_offset = 0;
  for( ulong i = 0; i < self->sockets_len; i++ ) {
    /* Check if adding this offset would cause 16-bit integer overflow */
    if( FD_UNLIKELY( total_offset > USHRT_MAX - self->sockets[i].offset ) ) {
      return FD_BINCODE_ERR_ENCODING; // Port offset overflow would occur
    }
    total_offset += self->sockets[i].offset;
  }

  return FD_BINCODE_SUCCESS;
}
int fd_gossip_contact_info_v2_validator( fd_bincode_decode_ctx_t * ctx, fd_gossip_contact_info_v2_t * self ) {
  int err = fd_sanitize_entries( self);
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
