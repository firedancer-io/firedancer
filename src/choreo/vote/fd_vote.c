#include "fd_vote.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

ulong
fd_vote_txn_generate(fd_compact_vote_state_update_t* compact_vote_update,
                     fd_pubkey_t* validator_pubkey,
                     fd_pubkey_t* vote_acct_pubkey,
                     uchar* validator_privkey,
                     uchar* vote_acct_privkey,
                     uchar* recent_blockhash,
                     uchar out_txn_meta_buf [static FD_TXN_MAX_SZ],
                     uchar out_txn_buf [static FD_TXN_MTU]
                     ) {
  /* Create the transaction base */
  fd_pubkey_t pubkeys[2], vote_program_pubkey;
  memcpy( pubkeys, validator_pubkey, sizeof(fd_pubkey_t) );
  memcpy( pubkeys + 1, vote_acct_pubkey, sizeof(fd_pubkey_t) );
  memcpy( &vote_program_pubkey, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) );

  fd_txn_accounts_t vote_txn_accounts;
  vote_txn_accounts.signature_cnt         = 2;
  vote_txn_accounts.readonly_signed_cnt   = 0;
  vote_txn_accounts.readonly_unsigned_cnt = 1;
  vote_txn_accounts.acct_cnt              = 3;                    /* 3 accounts: validator, vote account, vote program  */
  vote_txn_accounts.signers_w             = pubkeys;              /* 2 signers: validator, vote account */
  vote_txn_accounts.signers_r             = NULL;
  vote_txn_accounts.non_signers_w         = NULL;
  vote_txn_accounts.non_signers_r         = &vote_program_pubkey; /* 1 non-signer: vote program */
  FD_TEST( fd_txn_base_generate( out_txn_meta_buf, out_txn_buf, 2, &vote_txn_accounts, recent_blockhash ) );

  /* Add the vote instruction to the transaction */
  fd_vote_instruction_t vote_instr;
  uchar vote_instr_buf[FD_TXN_MTU];
  vote_instr.discriminant = fd_vote_instruction_enum_compact_update_vote_state;
  vote_instr.inner.compact_update_vote_state = *compact_vote_update;
  fd_bincode_encode_ctx_t encode = { .data = vote_instr_buf, .dataend = (vote_instr_buf + FD_TXN_MTU) };
  fd_vote_instruction_encode ( &vote_instr, &encode );
  ushort vote_instr_size = (ushort)fd_vote_instruction_size( &vote_instr );

  uchar instr_accounts[2];
  instr_accounts[0] = 1;  /* vote account   */
  instr_accounts[1] = 1;  /* vote authority */
  uchar program_id  = 2;  /* vote program   */
  ulong txn_size = fd_txn_add_instr(out_txn_meta_buf,
                                    out_txn_buf,
                                    program_id,
                                    instr_accounts,
                                    2, /* 2 accounts in instr_accounts */
                                    vote_instr_buf,
                                    vote_instr_size);

  /* Add the signatures of validator and vote account */
  fd_sha512_t sha;
  fd_txn_t * txn_meta = (fd_txn_t *) fd_type_pun( out_txn_meta_buf );
  fd_ed25519_sign( /* sig */ out_txn_buf + txn_meta->signature_off,
                   /* msg */ out_txn_buf + txn_meta->message_off,
                   /* sz  */ txn_size - txn_meta->message_off,
                   /* public_key  */ validator_pubkey->key,
                   /* private_key */ validator_privkey,
                   &sha);
  fd_ed25519_sign( /* sig */ out_txn_buf + txn_meta->signature_off + FD_TXN_SIGNATURE_SZ,
                   /* msg */ out_txn_buf + txn_meta->message_off,
                   /* sz  */ txn_size - txn_meta->message_off,
                   /* public_key  */ vote_acct_pubkey->key,
                   /* private_key */ vote_acct_privkey,
                   &sha);

  return txn_size;
}

int
fd_vote_txn_parse(uchar txn_buf [static FD_TXN_MTU],
                  ulong txn_size,
                  fd_valloc_t valloc,
                  fd_compact_vote_state_update_t *out_compact_vote_update){
  uchar out_buf[ FD_TXN_MAX_SZ ];
  fd_txn_t * parsed_txn = (fd_txn_t *)fd_type_pun( out_buf );
  ulong out_sz = fd_txn_parse( txn_buf, txn_size, out_buf, NULL );
  FD_TEST( out_sz );
  FD_TEST( parsed_txn );
  FD_TEST( parsed_txn->instr_cnt == 1);

  uchar program_id = parsed_txn->instr[0].program_id;
  uchar* program_account_addr = (txn_buf + parsed_txn->acct_addr_off
                                 + FD_TXN_ACCT_ADDR_SZ * program_id );

  if ( memcmp( program_account_addr, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    FD_LOG_WARNING( ("fd_vote_txn_parse: txn targets program %32J instead of %32J",
                     program_account_addr,
                     fd_solana_vote_program_id.key) );
    return FD_VOTE_TXN_PARSE_ERR_WRONG_PROG;
  } else {
    fd_vote_instruction_t vote_instr = { 0 };
    ushort instr_data_sz = parsed_txn->instr[0].data_sz;
    uchar* instr_data = txn_buf + parsed_txn->instr[0].data_off;
    fd_bincode_decode_ctx_t decode = {
      .data    = instr_data,
      .dataend = instr_data + instr_data_sz,
      .valloc = valloc
    };
    int decode_result = fd_vote_instruction_decode( &vote_instr, &decode );
    if( decode_result != FD_BINCODE_SUCCESS) {
      FD_LOG_WARNING(("fd_vote_txn_parse: fail at decoding vote instruction"));
      return FD_VOTE_TXN_PARSE_ERR_BAD_INST;
    } else {
      if (vote_instr.discriminant != fd_vote_instruction_enum_compact_update_vote_state) {
        FD_LOG_WARNING(("fd_vote_txn_parse: not compact_update_vote_state instruction"));
        return FD_VOTE_TXN_PARSE_ERR_BAD_INST;
      } else {
        *out_compact_vote_update = vote_instr.inner.compact_update_vote_state;
      }
    }
  }
  return FD_VOTE_TXN_PARSE_OK;
}
