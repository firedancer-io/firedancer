#include "fd_alpen.h"

/* TODO Agave is expected to move away from sending votes as instructions */
#define FD_AG_VOTE_SERDES_AS_INSTRUCTION (1)

int
fd_txn_is_simple_ag_vote_transaction( fd_txn_t const * txn,
                               void     const * payload ) {
   /* base58 decode of Vote222222222222222222222222222222222222222 */
   static const uchar vote_program_id[FD_TXN_ACCT_ADDR_SZ] = {
      0x07U,0x61U,0x48U,0x1dU,0x98U,0x63U,0x1bU,0xd3U,0x7cU,0xe9U,0xc4U,0xbaU,0x4fU,0x36U,0xacU,0xdeU,
      0xc5U,0xfeU,0x0cU,0xdbU,0xa6U,0x2dU,0x4dU,0x05U,0x25U,0xedU,0xb1U,0x70U,0x47U,0xdcU,0x11U,0xf7U };

  fd_acct_addr_t const * addr_base = fd_txn_get_acct_addrs( txn, payload );
  if( FD_UNLIKELY( txn->instr_cnt!=1UL ) )                      return 0;
  if( FD_UNLIKELY( txn->transaction_version!=FD_TXN_VLEGACY ) ) return 0;
  if( FD_UNLIKELY( txn->signature_cnt>2UL ) )                   return 0;
  uchar type = *(((uchar*)payload) + txn->instr[0].data_off);
  if( FD_UNLIKELY( !( type==FD_AG_VOTE_NOTARIZE ||
                      type==FD_AG_VOTE_FINALIZE ||
                      type==FD_AG_VOTE_SKIP ||
                      type==FD_AG_VOTE_NOTARIZE_FALLBACK ||
                      type==FD_AG_VOTE_SKIP_FALLBACK ) ) )      return 0;
  ulong prog_id_idx = (ulong)txn->instr[0].program_id;
  fd_acct_addr_t const * prog_id = addr_base + prog_id_idx;
  return fd_memeq( prog_id->b, vote_program_id, FD_TXN_ACCT_ADDR_SZ );
}

int
fd_ag_vote_deserialize_from_data( fd_ag_vote_t * vote,
                                  uchar const * data ) {
#if FD_AG_VOTE_SERDES_AS_INSTRUCTION
  uchar type = data[ 0UL ];
  vote->type = type;
  if( FD_LIKELY( type==FD_AG_VOTE_NOTARIZE || type==FD_AG_VOTE_NOTARIZE_FALLBACK ) ) {
    vote->version       = data[ 1UL ];
    vote->slot          = fd_ulong_load_8( data + 2UL );
    fd_memcpy( vote->block_id, data+10UL, FD_AG_VOTE_BLOCK_ID_SZ  );
    vote->replayed_slot = fd_ulong_load_8( data + 42UL );
    fd_memcpy( vote->replayed_bank_hash, data+50UL, FD_AG_VOTE_BANK_HASH_SZ );
    return FD_AG_VOTE_SERDES_SUCCESS;
  }
  if( FD_LIKELY( type==FD_AG_VOTE_FINALIZE || type==FD_AG_VOTE_SKIP ||
                 type==FD_AG_VOTE_SKIP_FALLBACK ) ) {
    vote->slot = fd_ulong_load_8( data + 1UL );
    return FD_AG_VOTE_SERDES_SUCCESS;
  }
  /* just for redundancy */
  vote->slot = ULONG_MAX;
  return FD_AG_VOTE_SERDES_FAILURE;
#else
  /* TODO pending implementation */
#endif
}

int
fd_ag_vote_serialize_into_data( uchar * data,
                                fd_ag_vote_t const * vote ) {
#if FD_AG_VOTE_SERDES_AS_INSTRUCTION
  uchar type  = vote->type;
  data[ 0UL ] = type;
  if( FD_LIKELY( type==FD_AG_VOTE_NOTARIZE || type==FD_AG_VOTE_NOTARIZE_FALLBACK ) ) {
    data[ 1UL] = vote->version;
    fd_memcpy( data+ 2UL, &vote->slot,              sizeof(vote->slot) );
    fd_memcpy( data+10UL, vote->block_id,           FD_AG_VOTE_BLOCK_ID_SZ );
    fd_memcpy( data+42UL, &vote->replayed_slot,     sizeof(vote->replayed_slot) );
    fd_memcpy( data+50UL, vote->replayed_bank_hash, FD_AG_VOTE_BANK_HASH_SZ );
    return FD_AG_VOTE_SERDES_SUCCESS;
  }
  if( FD_LIKELY( type==FD_AG_VOTE_FINALIZE || type==FD_AG_VOTE_SKIP ||
                 type==FD_AG_VOTE_SKIP_FALLBACK ) ) {
    fd_memcpy( data+ 1UL, &vote->slot,              sizeof(vote->slot) );
    return FD_AG_VOTE_SERDES_SUCCESS;
  }
  return FD_AG_VOTE_SERDES_FAILURE;
#else
  /* TODO pending implementation */
#endif
}
