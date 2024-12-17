#include "fd_voter.h"

#include <string.h>

fd_voter_state_t const *
fd_voter_state( fd_funk_t * funk, fd_funk_txn_t const * txn, fd_funk_rec_key_t const * key ) {
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( funk, txn, key, NULL );
  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
    return NULL;
  }
  fd_account_meta_t const * meta = fd_funk_val_const( rec, fd_funk_wksp(funk) );
  FD_TEST( meta->magic == FD_ACCOUNT_META_MAGIC );
  fd_voter_state_t const * state = fd_type_pun_const( (uchar const *)meta + meta->hlen );
  #if FD_TOWER_USE_HANDHOLDING
  FD_TEST( state->discriminant <= fd_vote_state_versioned_enum_current );
  #endif
  return state;
}

ulong
fd_voter_txn_generate( fd_voter_t const *                     voter,
                       fd_compact_vote_state_update_t const * tower_sync,
                       fd_hash_t const *                      recent_blockhash,
                       uchar                                  txn_meta_out[static FD_TXN_MAX_SZ],
                       uchar                                  txn_out[static FD_TXN_MTU] ) {
  FD_LOG_NOTICE(( "[%s]: vote acc addr %s", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->addr ) ));

  int same_addr = !memcmp( &voter->validator_identity,
                           &voter->vote_authority,
                           sizeof( fd_pubkey_t ) );
  if( FD_LIKELY( same_addr ) ) {

    /* 0: validator identity
       1: vote account address
       2: vote program */

    fd_txn_accounts_t accts;
    accts.signature_cnt         = 1;
    accts.readonly_signed_cnt   = 0;
    accts.readonly_unsigned_cnt = 1;
    accts.acct_cnt              = 3;
    accts.signers_w             = &voter->validator_identity;
    accts.signers_r             = NULL;
    accts.non_signers_w         = &voter->addr;
    accts.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out,
                                   txn_out,
                                   accts.signature_cnt,
                                   &accts,
                                   recent_blockhash->uc ) );
  } else {

    /* 0: validator identity
       1: vote authority
       2: vote account address
       3: vote program */

    fd_txn_accounts_t accts;
    accts.signature_cnt         = 2;
    accts.readonly_signed_cnt   = 1;
    accts.readonly_unsigned_cnt = 1;
    accts.acct_cnt              = 4;
    accts.signers_w             = &voter->validator_identity;
    accts.signers_r             = &voter->vote_authority;
    accts.non_signers_w         = &voter->addr;
    accts.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out,
                                   txn_out,
                                   accts.signature_cnt,
                                   &accts,
                                   recent_blockhash->uc ) );
  }

  /* Add the vote instruction to the transaction. */

  fd_vote_instruction_t vote_ix;
  uchar                 vote_ix_buf[FD_TXN_MTU];
  vote_ix.discriminant                    = fd_vote_instruction_enum_compact_update_vote_state;
  vote_ix.inner.compact_update_vote_state = *tower_sync;
  fd_bincode_encode_ctx_t encode = { .data = vote_ix_buf, .dataend = ( vote_ix_buf + FD_TXN_MTU ) };
  fd_vote_instruction_encode( &vote_ix, &encode );
  ushort vote_ix_size = (ushort)fd_vote_instruction_size( &vote_ix );

  ulong txn_sz;
  if( FD_LIKELY( same_addr ) ) {
    uchar ix_accs[2];
    ix_accs[0]       = 1; /* vote account address */
    ix_accs[1]       = 0; /* vote authority */
    uchar program_id = 2; /* vote program */

    txn_sz = fd_txn_add_instr( txn_meta_out,
                               txn_out,
                               program_id,
                               ix_accs,
                               2,
                               vote_ix_buf,
                               vote_ix_size );
  } else {
    uchar ix_accs[2];
    ix_accs[0]       = 2; /* vote account address */
    ix_accs[1]       = 1; /* vote authority */
    uchar program_id = 3; /* vote program */

    txn_sz = fd_txn_add_instr( txn_meta_out,
                               txn_out,
                               program_id,
                               ix_accs,
                               2,
                               vote_ix_buf,
                               vote_ix_size );
  }
  return txn_sz;
}

// int
// fd_voter_txn_parse( uchar txn[static FD_TXN_MTU], ulong txn_sz, fd_voter_vote_t * voter_votes_out
// ) {
//   uchar      out_buf[FD_TXN_MAX_SZ];
//   fd_txn_t * parsed_txn = (fd_txn_t *)fd_type_pun( out_buf );
//   ulong      out_sz     = fd_txn_parse( txn, txn_sz, out_buf, NULL );
//   FD_TEST( out_sz );
//   FD_TEST( parsed_txn );
//   FD_TEST( parsed_txn->ix_cnt == 1 );

//   uchar   program_id           = parsed_txn->ix[0].program_id;
//   uchar * program_account_addr = txn + parsed_txn->acct_addr_off + FD_TXN_ACCT_ADDR_SZ *
//   program_id;

//   if( FD_UNLIKELY( memcmp( program_account_addr,
//                            fd_solana_vote_program_id.key,
//                            sizeof( fd_pubkey_t ) ) ) ) {
//     FD_LOG_WARNING(( "[fd_voter_txn_parse] txn program %s was not vote program id %s",
//                      FD_BASE58_ENC_32_ALLOCA( program_account_addr ),
//                      FD_BASE58_ENC_32_ALLOCA( fd_solana_vote_program_id.key ) ));
//     return -1;
//   }

//   ushort                  ix_data_sz = parsed_txn->ix[0].data_sz;
//   uchar *                 ix_data    = txn + parsed_txn->ix[0].data_off;
//   fd_valloc_t             valloc        = fd_scratch_virtual();
//   fd_bincode_decode_ctx_t decode        = { .data    = ix_data,
//                                             .dataend = ix_data + ix_data_sz,
//                                             .valloc  = valloc };

//   fd_vote_instruction_t * vote_instruction = fd_valloc_malloc( valloc,
//                                                                alignof( fd_vote_instruction_t ),
//                                                                sizeof( fd_vote_instruction_t ) );
//   int                     rc = fd_vote_instruction_decode( vote_instruction, &decode );
//   if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) {
//     FD_LOG_WARNING( ( "fd_vote_txn_parse: fail at decoding vote instruction" ) );
//     return -1;
//   }

//   /* https://github.com/anza-xyz/agave/blob/v2.0.1/vote/src/vote_parser.rs#L47-L78 */

//   switch ( vote_instruction->discriminant ) {
//       case fd_vote_instruction_enum_vote: {
//           for( deq_ulong_iter_t iter = deq_ulong_iter_init( vote_instruction->inner.vote.slots );
//        !deq_ulong_iter_done( vote_instruction->inner.vote.slots, iter );
//        iter = deq_ulong_iter_next( vote_instruction->inner.vote.slots, iter ) ) {
//     ulong slot = deq_ulong_iter_ele( vote_instruction->inner.vote.slots, iter );
//     fd_voter_votes_push_tail( vote_instruction->inner.vote.slots, slot);
//        }
//         break;
//       }
//       case fd_vote_instruction_enum_vote_switch: {
//         break;
//       }
//       case fd_vote_instruction_enum_update_vote_state: {
//         break;
//       }
//       case fd_vote_instruction_enum_update_vote_state_switch: {
//         break;
//       }
//       case fd_vote_instruction_enum_compact_update_vote_state: {
//         break;
//       }
//       case fd_vote_instruction_enum_compact_update_vote_state_switch: {
//         break;
//       }
//       case fd_vote_instruction_enum_voter_sync: {
//         break;
//       }
//       case fd_vote_instruction_enum_voter_sync_switch: {
//         break;
//       }
//   };

//   for (ulong i = 0; i < 8; i++) {
//     if (vote_instruction->discriminant == discriminants[i]) {
//       return vote_instruction;
//     }
//   }
//   return NULL;

//   if( FD_UNLIKELY( vote_instruction->discriminant !=
//                        discriminants ||
//                    vote_instruction->discriminant != fd_vote_instruction_enum_voter_sync ) ) {
//     FD_LOG_WARNING( ( "fd_vote_txn_parse: not compact_update_vote_state instruction" ) );
//     return NULL;
//   }

//   return vote_instruction;
// }
