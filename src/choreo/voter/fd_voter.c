#include "fd_voter.h"
#include <string.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

ulong
fd_vote_txn_generate( fd_voter_t *                     voter,
                      fd_compact_vote_state_update_t * vote_update,
                      uchar *                          recent_blockhash,
                      uchar                            txn_meta_out[static FD_TXN_MAX_SZ],
                      uchar                            txn_out[static FD_TXN_MTU] ) {
  fd_pubkey_t const * vote_program_addr = &fd_solana_vote_program_id;

  /* Create the transaction base */
  uchar vote_authority_is_validator_identity = ( memcmp( voter->validator_identity_pubkey->key,
                                                         voter->vote_authority_pubkey->key,
                                                         sizeof( fd_pubkey_t ) ) == 0 );
  if( FD_LIKELY( vote_authority_is_validator_identity ) ) {
    /* 0: node identity
       1: vote account address
       2: vote program */
    fd_txn_accounts_t accts;
    accts.signature_cnt         = 1;
    accts.readonly_signed_cnt   = 0;
    accts.readonly_unsigned_cnt = 1;
    accts.acct_cnt              = 3;
    accts.signers_w             = voter->validator_identity_pubkey;
    accts.signers_r             = NULL;
    accts.non_signers_w         = voter->vote_acct_addr;
    accts.non_signers_r         = vote_program_addr;
    FD_TEST( fd_txn_base_generate( txn_meta_out,
                                   txn_out,
                                   accts.signature_cnt,
                                   &accts,
                                   recent_blockhash ) );
  } else {
    /* 0: node identity
       1: authorized voter
       2: vote account address
       3: vote program */
    fd_txn_accounts_t accts;
    accts.signature_cnt         = 2;
    accts.readonly_signed_cnt   = 1;
    accts.readonly_unsigned_cnt = 1;
    accts.acct_cnt              = 4;
    accts.signers_w             = voter->validator_identity_pubkey;
    accts.signers_r             = voter->vote_authority_pubkey;
    accts.non_signers_w         = voter->vote_acct_addr;
    accts.non_signers_r         = vote_program_addr;
    FD_TEST( fd_txn_base_generate( txn_meta_out,
                                   txn_out,
                                   accts.signature_cnt,
                                   &accts,
                                   recent_blockhash ) );
  }

  /* Add the vote instruction to the transaction */

  fd_vote_instruction_t vote_instr;
  uchar                 vote_instr_buf[FD_TXN_MTU];
  vote_instr.discriminant                    = fd_vote_instruction_enum_compact_update_vote_state;
  vote_instr.inner.compact_update_vote_state = *vote_update;
  fd_bincode_encode_ctx_t encode             = { .data    = vote_instr_buf,
                                                 .dataend = ( vote_instr_buf + FD_TXN_MTU ) };
  fd_vote_instruction_encode( &vote_instr, &encode );
  ushort vote_instr_size = (ushort)fd_vote_instruction_size( &vote_instr );

  ulong txn_size;
  if( FD_LIKELY( vote_authority_is_validator_identity ) ) {
    uchar instr_accounts[2];
    instr_accounts[0] = 1; /* vote account address */
    instr_accounts[1] = 0; /* vote authority */
    uchar program_id  = 2; /* vote program */
    txn_size          = fd_txn_add_instr( txn_meta_out,
                                 txn_out,
                                 program_id,
                                 instr_accounts,
                                 2, /* 2 accounts in instr_accounts */
                                 vote_instr_buf,
                                 vote_instr_size );
  } else {
    uchar instr_accounts[2];
    instr_accounts[0] = 2; /* vote account address */
    instr_accounts[1] = 1; /* vote authority */
    uchar program_id  = 3; /* vote program */
    txn_size          = fd_txn_add_instr( txn_meta_out,
                                 txn_out,
                                 program_id,
                                 instr_accounts,
                                 2, /* 2 accounts in instr_accounts */
                                 vote_instr_buf,
                                 vote_instr_size );

  }
  return txn_size;
}

void
fd_voter_txn_sign( fd_voter_t *                     voter,
                   ulong                            txn_size,
                   uchar                            txn_meta_out[static FD_TXN_MAX_SZ],
                   uchar                            txn_out[static FD_TXN_MTU] )  {
  /* Generate the signatures */
  /* Create the transaction base */
  uchar vote_authority_is_validator_identity = ( memcmp( voter->validator_identity_pubkey->key,
                                                         voter->vote_authority_pubkey->key,
                                                         sizeof( fd_pubkey_t ) ) == 0 );
  if( FD_LIKELY( vote_authority_is_validator_identity ) ) {
    fd_txn_t * txn_meta = (fd_txn_t *)fd_type_pun( txn_meta_out );
    voter->validator_identity_sign_fun( voter->voter_sign_arg,
                                        /* sig */ txn_out + txn_meta->signature_off,
                                        /* buffer */ txn_out + txn_meta->message_off,
                                        /* len */ txn_size - txn_meta->message_off );
  } else {
    fd_txn_t * txn_meta  = (fd_txn_t *)fd_type_pun( txn_meta_out );
    uchar *    sig_start = txn_out + txn_meta->signature_off;
    uchar *    buf_start = txn_out + txn_meta->message_off;
    ulong      buf_size  = txn_size - txn_meta->message_off;
    voter->validator_identity_sign_fun( voter->voter_sign_arg,
                                        /* sig */ sig_start,
                                        /* buf */ buf_start,
                                        /* len */ buf_size );
    voter->vote_authority_sign_fun( voter->voter_sign_arg,
                                    /* sig */ sig_start + FD_TXN_SIGNATURE_SZ,
                                    /* buf */ buf_start,
                                    /* len */ buf_size );
  }
}

int
fd_vote_txn_parse( uchar                            txn_buf[static FD_TXN_MTU],
                   ulong                            txn_size,
                   fd_valloc_t                      valloc,
                   ushort *                         out_recent_blockhash_off,
                   fd_compact_vote_state_update_t * out_compact_vote_update ) {
  uchar      out_buf[FD_TXN_MAX_SZ];
  fd_txn_t * parsed_txn = (fd_txn_t *)fd_type_pun( out_buf );
  ulong      out_sz     = fd_txn_parse( txn_buf, txn_size, out_buf, NULL );
  FD_TEST( out_sz );
  FD_TEST( parsed_txn );
  FD_TEST( parsed_txn->instr_cnt == 1 );

  uchar   program_id           = parsed_txn->instr[0].program_id;
  uchar * program_account_addr = txn_buf + parsed_txn->acct_addr_off +
                                 FD_TXN_ACCT_ADDR_SZ * program_id;

  if( FD_UNLIKELY( memcmp( program_account_addr,
                           fd_solana_vote_program_id.key,
                           sizeof( fd_pubkey_t ) ) ) ) {
    FD_LOG_WARNING( ( "fd_vote_txn_parse: txn targets program %32J instead of %32J",
                      program_account_addr,
                      fd_solana_vote_program_id.key ) );
    return FD_VOTE_TXN_PARSE_ERR_WRONG_PROG;
  } else {
    fd_vote_instruction_t   vote_instr    = { 0 };
    ushort                  instr_data_sz = parsed_txn->instr[0].data_sz;
    uchar *                 instr_data    = txn_buf + parsed_txn->instr[0].data_off;
    fd_bincode_decode_ctx_t decode        = { .data    = instr_data,
                                              .dataend = instr_data + instr_data_sz,
                                              .valloc  = valloc };
    int                     decode_result = fd_vote_instruction_decode( &vote_instr, &decode );
    if( FD_UNLIKELY( decode_result != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING( ( "fd_vote_txn_parse: fail at decoding vote instruction" ) );
      return FD_VOTE_TXN_PARSE_ERR_BAD_INST;
    } else {
      if( FD_UNLIKELY( vote_instr.discriminant !=
                       fd_vote_instruction_enum_compact_update_vote_state ) ) {
        FD_LOG_WARNING( ( "fd_vote_txn_parse: not compact_update_vote_state instruction" ) );
        return FD_VOTE_TXN_PARSE_ERR_BAD_INST;
      } else {
        *out_recent_blockhash_off = parsed_txn->recent_blockhash_off;
        *out_compact_vote_update  = vote_instr.inner.compact_update_vote_state;
      }
    }
  }
  return FD_VOTE_TXN_PARSE_OK;
}
