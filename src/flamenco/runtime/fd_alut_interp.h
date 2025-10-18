#ifndef HEADER_fd_src_flamenco_runtime_fd_alut_h
#define HEADER_fd_src_flamenco_runtime_fd_alut_h

/* fd_alut_interp.h provides APIs for interpreting Solana address lookup
   table usages.

   https://solana.com/de/developers/guides/advanced/lookup-tables */

#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#include "fd_runtime_err.h"
#include "fd_system_ids.h"
#include "program/fd_address_lookup_table_program.h"

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
  fd_address_lookup_table_state_t table[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static( address_lookup_table_state, table, alut_data, FD_LOOKUP_TABLE_META_SIZE, NULL ) ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L200-L203 */
  if( FD_UNLIKELY( table->discriminant != fd_address_lookup_table_state_enum_lookup_table ) ) {
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
  int err = fd_get_active_addresses_len( &table->inner.lookup_table,
                                         interp->slot,
                                         interp->hashes,
                                         lookup_addrs_cnt,
                                         &active_addresses_len );
  if( FD_UNLIKELY( err ) ) return err;

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
