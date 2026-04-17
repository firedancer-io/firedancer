#ifndef HEADER_fd_src_flamenco_runtime_fd_alut_h
#define HEADER_fd_src_flamenco_runtime_fd_alut_h

/* fd_alut.h provides APIs for interpreting Solana address lookup table
   usages.

   https://solana.com/de/developers/guides/advanced/lookup-tables */

#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#include "fd_runtime_err.h"
#include "fd_system_ids.h"
#include "sysvar/fd_sysvar_slot_hashes.h"

#define FD_ADDRLUT_STATUS_ACTIVATED    (0)
#define FD_ADDRLUT_STATUS_DEACTIVATING (1)
#define FD_ADDRLUT_STATUS_DEACTIVATED  (2)

/* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L19 */
#define FD_LOOKUP_TABLE_META_SIZE      (56)
#define FD_ADDRLUT_MAX_ENTRIES         FD_SYSVAR_SLOT_HASHES_CAP

/* Discriminants for the ProgramState enum wrapping the lookup table
   metadata in the on-disk account format. */

#define FD_ALUT_STATE_DISC_UNINITIALIZED (0U)
#define FD_ALUT_STATE_DISC_LOOKUP_TABLE  (1U)

/* fd_alut_meta_t is the in-memory representation of address lookup
   table account state (ProgramState + LookupTableMeta in Agave).
   The on-disk format is 56 bytes: u32 discriminant,
   u64 deactivation_slot, u64 last_extended_slot,
   u8 last_extended_slot_start_index, Option<Pubkey> authority
   (1-byte tag + 32 bytes), u16 _padding.  When discriminant is
   FD_ALUT_STATE_DISC_UNINITIALIZED the remaining fields are ignored. */

struct fd_alut_meta {
  uint        discriminant;
  ulong       deactivation_slot;
  ulong       last_extended_slot;
  uchar       last_extended_slot_start_index;
  uchar       has_authority;
  fd_pubkey_t authority;
};
typedef struct fd_alut_meta fd_alut_meta_t;

/* fd_alut_interp_t interprets indirect account references of a txn. */

struct fd_alut_interp {
  fd_acct_addr_t *       out_accts_alt;

  fd_txn_t const *       txn;
  uchar const *          txn_payload;
  fd_slot_hash_t const * hashes; /* deque */
  ulong                  slot;

  ulong                  alut_idx;
  ulong                  ro_indir_cnt;
  ulong                  rw_indir_cnt;
};

typedef struct fd_alut_interp fd_alut_interp_t;

FD_PROTOTYPES_BEGIN

/* fd_alut_state_encode writes a 56-byte zero-padded ALUT state header
   into [buf, buf+bufsz).  Uses meta->discriminant to decide the
   variant; fields other than discriminant are ignored when
   discriminant == FD_ALUT_STATE_DISC_UNINITIALIZED.  Returns 0 on
   success, -1 on short buffer. */

static inline int
fd_alut_state_encode( fd_alut_meta_t const * meta,
                      uchar *                buf,
                      ulong                  bufsz ) {
  if( FD_UNLIKELY( bufsz<FD_LOOKUP_TABLE_META_SIZE ) ) return -1;

  fd_memset( buf, 0, FD_LOOKUP_TABLE_META_SIZE );
  uchar * p = buf;

  FD_STORE( uint, p, meta->discriminant );
  p += sizeof(uint);

  if( meta->discriminant==FD_ALUT_STATE_DISC_LOOKUP_TABLE ) {
    FD_STORE( ulong, p, meta->deactivation_slot );
    p += sizeof(ulong);

    FD_STORE( ulong, p, meta->last_extended_slot );
    p += sizeof(ulong);

    *p = meta->last_extended_slot_start_index;
    p += 1;

    *p = (uchar)meta->has_authority;
    p += 1;

    if( meta->has_authority ) {
      fd_memcpy( p, meta->authority.key, 32 );
      p += 32;
    } else {
      p += 32;
    }

    FD_STORE( ushort, p, (ushort)0 );
  }

  return 0;
}

/* fd_alut_state_decode reads an ALUT state header from
   [data, data+data_sz).  On success populates *out (including
   out->discriminant) and returns 0.  Returns -1 on decode failure
   (short buffer or unknown discriminant). */

static inline int
fd_alut_state_decode( uchar const *    data,
                      ulong            data_sz,
                      fd_alut_meta_t * out ) {
  if( FD_UNLIKELY( data_sz<sizeof(uint) ) ) return -1;

  uchar const * p   = data;
  uchar const * end = data + data_sz;

  uint disc = FD_LOAD( uint, p );
  p += sizeof(uint);
  out->discriminant = disc;

  if( disc==FD_ALUT_STATE_DISC_UNINITIALIZED ) {
    return 0;
  }

  if( FD_UNLIKELY( disc!=FD_ALUT_STATE_DISC_LOOKUP_TABLE ) ) return -1;

  if( FD_UNLIKELY( p + 8 > end ) ) return -1;
  out->deactivation_slot = FD_LOAD( ulong, p );
  p += sizeof(ulong);

  if( FD_UNLIKELY( p + 8 > end ) ) return -1;
  out->last_extended_slot = FD_LOAD( ulong, p );
  p += sizeof(ulong);

  if( FD_UNLIKELY( p + 1 > end ) ) return -1;
  out->last_extended_slot_start_index = *p;
  p += 1;

  if( FD_UNLIKELY( p + 1 > end ) ) return -1;
  uchar has_auth = *p;
  p += 1;
  out->has_authority = has_auth;

  if( has_auth ) {
    if( FD_UNLIKELY( p + 32 > end ) ) return -1;
    fd_memcpy( out->authority.key, p, 32 );
    p += 32;
  } else {
    fd_memset( out->authority.key, 0, 32 );
    p += fd_ulong_min( 32, (ulong)(end - p) );
  }

  (void)p;
  return 0;
}

/* fd_alut_slot_hashes_position, fd_alut_status, and fd_alut_is_active
   are all helper methods for determining the number of active addresses
   in an address lookup table account. */


/* Logic here is copied from slice::binary_search_by() in Rust. While
   not fully optimized, it aims to achieve fuzzing conformance for both
   sorted and unsorted inputs. */
FD_FN_UNUSED static ulong
fd_alut_slot_hashes_position( fd_slot_hash_t const * hashes, /* deque */
                              ulong                  slot ) {
  ulong size = deq_fd_slot_hash_t_cnt( hashes );
  if( FD_UNLIKELY( size==0UL ) ) return ULONG_MAX;

  ulong base = 0UL;
  while( size>1UL ) {
    ulong half = size / 2UL;
    ulong mid = base + half;
    ulong mid_slot = deq_fd_slot_hash_t_peek_index_const( hashes, mid )->slot;
    base = (slot>mid_slot) ? base : mid;
    size -= half;
  }

  return deq_fd_slot_hash_t_peek_index_const( hashes, base )->slot==slot ? base : ULONG_MAX;
}

/* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L81-L104 */
FD_FN_UNUSED static uchar
fd_alut_status( fd_alut_meta_t const * state,
                ulong                  current_slot,
                fd_slot_hash_t const * slot_hashes /* deque */ ) {
  if( state->deactivation_slot==ULONG_MAX ) {
    return FD_ADDRLUT_STATUS_ACTIVATED;
  }

  if( state->deactivation_slot==current_slot ) {
    return FD_ADDRLUT_STATUS_DEACTIVATING;
  }

  ulong slot_hash_position = fd_alut_slot_hashes_position( slot_hashes, state->deactivation_slot );
  if( slot_hash_position!=ULONG_MAX ) {
    return FD_ADDRLUT_STATUS_DEACTIVATING;
  }

  return FD_ADDRLUT_STATUS_DEACTIVATED;
}

/* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L72-L78 */
FD_FN_UNUSED static uchar
fd_alut_is_active( fd_alut_meta_t const * self,
                   ulong                  current_slot,
                   fd_slot_hash_t const * slot_hashes  /* deque */ ) {
  uchar status = fd_alut_status( self, current_slot, slot_hashes );
  switch( status ) {
    case FD_ADDRLUT_STATUS_ACTIVATED:
    case FD_ADDRLUT_STATUS_DEACTIVATING:
      return 1;
    case FD_ADDRLUT_STATUS_DEACTIVATED:
      return 0;
    default:
      FD_LOG_CRIT(( "invalid lut status %d", status ));
  }
}

/* fd_alut_active_addresses_len returns the number of active addresses
   in an address lookup table account.
   https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L142-L164 */
FD_FN_UNUSED static int
fd_alut_active_addresses_len( fd_alut_meta_t const * self,
                              ulong                  current_slot,
                              fd_slot_hash_t const * slot_hashes, /* deque */
                              ulong                  addresses_len,
                              ulong *                active_addresses_len /* out */ ) {
  if( FD_UNLIKELY( !fd_alut_is_active( self, current_slot, slot_hashes ) ) ) {
    return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
  }

  *active_addresses_len = ( current_slot > self->last_extended_slot )
      ? addresses_len
      : self->last_extended_slot_start_index;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* fd_alut_interp_new creates a new ALUT interpreter.
   Will write indirectly referenced addresses to out_addrs.
   txn_payload points to a valid serialized transaction, txn points to
   the associated transaction descriptor.  alut_interp retains a write
   interest in out_addrs, and a read interest in txn, txn_payload, and
   hashes until it is destroyed. */

FD_FN_UNUSED static fd_alut_interp_t *
fd_alut_interp_new( fd_alut_interp_t *     interp,
                    fd_acct_addr_t *       out_addrs,
                    fd_txn_t const *       txn,
                    uchar const *          txn_payload,
                    fd_slot_hash_t const * hashes, /* deque */
                    ulong                  slot ) {
  *interp = (fd_alut_interp_t){
    .out_accts_alt = out_addrs,
    .txn           = txn,
    .txn_payload   = txn_payload,
    .hashes        = hashes,
    .slot          = slot,
    .alut_idx      = 0UL,
    .ro_indir_cnt  = 0UL,
    .rw_indir_cnt  = 0UL
  };
  return interp;
}

/* fd_alut_interp_delete destroys an ALUT interpreter object.  Releases
   references to out_addrs, txn, and txn_payload. */

FD_FN_UNUSED static void *
fd_alut_interp_delete( fd_alut_interp_t * interp ) {
  return interp;
}

static inline int
fd_alut_interp_done( fd_alut_interp_t const * interp ) {
  return interp->alut_idx >= interp->txn->addr_table_lookup_cnt;
}

/* fd_alut_interp_next resolves a subset of a txn's indirect account
   references.  Resolves all addresses that are specified in the ALUT
   at index alut_idx.  Returns one of:
   - FD_RUNTIME_EXECUTE_SUCCESS
   - FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER
   - FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA
   - FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX
   - FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND */

FD_FN_UNUSED static int
fd_alut_interp_next( fd_alut_interp_t * interp,
                     void const *       alut_addr,
                     void const *       alut_owner,
                     uchar const *      alut_data,
                     ulong              alut_data_sz ) {
  if( FD_UNLIKELY( fd_alut_interp_done( interp ) ) ) FD_LOG_CRIT(( "invariant violation" ));
  fd_acct_addr_t alut_addr_expected =
      FD_LOAD( fd_acct_addr_t, interp->txn_payload+fd_txn_get_address_tables_const( interp->txn )[ interp->alut_idx ].addr_off );
  if( FD_UNLIKELY( !fd_memeq( alut_addr, &alut_addr_expected, sizeof(fd_acct_addr_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( alut_addr,            alut_addr_b58          );
    FD_BASE58_ENCODE_32_BYTES( alut_addr_expected.b, alut_addr_expected_b58 );
    FD_LOG_CRIT(( "expected address lookup table account %s but got %s",
                  alut_addr_expected_b58, alut_addr_b58 ));
  }
  fd_txn_acct_addr_lut_t const * addr_lut =
      &fd_txn_get_address_tables_const( interp->txn )[ interp->alut_idx ];

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L96-L114 */
  if( FD_UNLIKELY( !fd_memeq( alut_owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L205-L209 */
  if( FD_UNLIKELY( alut_data_sz < FD_LOOKUP_TABLE_META_SIZE ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/accounts-db/src/accounts.rs#L141-L142 */
  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L197-L214 */
  fd_alut_meta_t meta;
  if( FD_UNLIKELY( fd_alut_state_decode( alut_data, FD_LOOKUP_TABLE_META_SIZE, &meta ) ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L200-L203 */
  if( FD_UNLIKELY( meta.discriminant != FD_ALUT_STATE_DISC_LOOKUP_TABLE ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
  }

  /* Again probably an impossible case, but the ALUT data needs to be 32-byte aligned
      https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L210-L214 */
  if( FD_UNLIKELY( (alut_data_sz - FD_LOOKUP_TABLE_META_SIZE) & 0x1fUL ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L101-L112 */
  fd_acct_addr_t const * lookup_addrs     = fd_type_pun_const( alut_data+FD_LOOKUP_TABLE_META_SIZE );
  ulong                  lookup_addrs_cnt = (alut_data_sz - FD_LOOKUP_TABLE_META_SIZE) >> 5UL; // = (dlen - 56) / 32

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L175-L176 */
  ulong active_addresses_len;
  int err = fd_alut_active_addresses_len(
      &meta,
      interp->slot,
      interp->hashes,
      lookup_addrs_cnt,
      &active_addresses_len
  );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/solana-sdk/blob/address-lookup-table-interface%40v3.0.1/address-lookup-table-interface/src/state.rs#L208-L211 */
  if( FD_UNLIKELY( active_addresses_len>lookup_addrs_cnt ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L169-L182 */
  uchar const * writable_lut_idxs = interp->txn_payload + addr_lut->writable_off;
  for( ulong j=0UL; j<addr_lut->writable_cnt; j++ ) {
    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L177-L181 */
    if( writable_lut_idxs[j] >= active_addresses_len ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
    }
    interp->out_accts_alt[ interp->rw_indir_cnt++ ] = lookup_addrs[ writable_lut_idxs[ j ] ];
  }

  uchar const * readonly_lut_idxs = interp->txn_payload + addr_lut->readonly_off;
  fd_acct_addr_t * out_accts_ro = interp->out_accts_alt + interp->txn->addr_table_adtl_writable_cnt;
  for( ulong j=0UL; j<addr_lut->readonly_cnt; j++ ) {
    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L177-L181 */
    if( readonly_lut_idxs[j] >= active_addresses_len ) {
      return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
    }
    out_accts_ro[ interp->ro_indir_cnt++ ] = lookup_addrs[ readonly_lut_idxs[ j ] ];
  }

  interp->alut_idx++;
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

FD_PROTOTYPES_END


#endif /* HEADER_fd_src_flamenco_runtime_fd_alut_h */
