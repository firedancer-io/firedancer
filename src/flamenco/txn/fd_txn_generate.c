#include "fd_txn_generate.h"

static fd_txn_instr_t * fd_txn_instr_meta_generate( uchar * out_buf, 
                                             uchar program_id,
                                             ushort acct_cnt,
                                             ushort data_sz,
                                             ushort acct_off,
                                             ushort data_off ) {
    fd_txn_instr_t * out_instr = (fd_txn_instr_t *) out_buf;
    out_instr->program_id = program_id;
    out_instr->acct_cnt   = acct_cnt;
    out_instr->data_sz    = data_sz;
    out_instr->acct_off   = acct_off;
    out_instr->data_off   = data_off;
    return out_instr;
}

ulong fd_txn_base_generate( uchar out_txn_meta[ static FD_TXN_MAX_SZ ],
                           uchar out_txn_payload[ static FD_TXN_MTU ],
                           ulong num_signatures,
                           fd_txn_accounts_t * accounts,
                           uchar * opt_recent_blockhash
                          ) {

  uchar compact_sig_cnt[3];
  uchar compact_sig_cnt_sz      = (uchar) fd_cu16_enc( (ushort)num_signatures, compact_sig_cnt );
  // Fill out txn metadata
  fd_txn_t * txn_meta             = (fd_txn_t *) out_txn_meta;
  txn_meta->acct_addr_cnt         = (ushort)accounts->acct_cnt;
  txn_meta->readonly_signed_cnt   = (uchar)accounts->readonly_signed_cnt;
  txn_meta->readonly_unsigned_cnt = (uchar)accounts->readonly_unsigned_cnt;
  txn_meta->message_off           = (ushort)(num_signatures * SIGNATURE_SZ + compact_sig_cnt_sz);
  txn_meta->signature_off         = 0;
  txn_meta->instr_cnt             = 0;

  uchar compact_acct_cnt[3];
  uchar compact_acct_cnt_sz      = (uchar) fd_cu16_enc( (ushort)txn_meta->acct_addr_cnt, compact_acct_cnt );
  txn_meta->acct_addr_off        = (ushort)(txn_meta->message_off + (sizeof(fd_txn_message_hdr_t)) + compact_acct_cnt_sz);
  txn_meta->recent_blockhash_off = (ushort)(txn_meta->acct_addr_off + (txn_meta->acct_addr_cnt * ACCOUNT_SZ));

  // Fill num_signatures at the beginning
  out_txn_payload[0] = (uchar) num_signatures;

  // Fill message header in txn payload
  uchar * write_ptr = out_txn_payload + txn_meta->message_off;
  fd_txn_message_hdr_t msg_header = { .num_signatures = (uchar)accounts->signature_cnt, 
                                      .num_readonly_signatures = (uchar)accounts->readonly_signed_cnt,
                                      .num_readonly_unsigned = (uchar)accounts->readonly_unsigned_cnt };
  fd_memcpy( write_ptr, &msg_header, sizeof(fd_txn_message_hdr_t));
  write_ptr = out_txn_payload + txn_meta->acct_addr_off - compact_acct_cnt_sz;

  // Write number of accounts (compact-u16)
  fd_memcpy( write_ptr, compact_acct_cnt, compact_acct_cnt_sz );
  write_ptr += compact_acct_cnt_sz;

  // Write accounts list to txn payload
  ulong signers_write_sz = ACCOUNT_SZ * (accounts->signature_cnt - accounts->readonly_signed_cnt);
  fd_memcpy( write_ptr, accounts->signers_w, signers_write_sz );
  write_ptr += signers_write_sz;

  fd_memcpy( write_ptr, accounts->signers_r, ACCOUNT_SZ * accounts->readonly_signed_cnt );
  write_ptr += ACCOUNT_SZ * accounts->readonly_signed_cnt;

  ulong non_signers_write_sz = ACCOUNT_SZ * (accounts->acct_cnt - accounts->readonly_unsigned_cnt - accounts->signature_cnt);
  fd_memcpy( write_ptr, accounts->non_signers_w, non_signers_write_sz);
  write_ptr += non_signers_write_sz;

  fd_memcpy( write_ptr, accounts->non_signers_r, ACCOUNT_SZ * accounts->readonly_unsigned_cnt );
  write_ptr += ACCOUNT_SZ * accounts->readonly_unsigned_cnt;
  FD_TEST( (ushort)((ulong)write_ptr - (ulong)out_txn_payload) == txn_meta->recent_blockhash_off );

  // Write recent blockhash
  if ( opt_recent_blockhash ) {
    fd_memcpy( write_ptr, opt_recent_blockhash, 32 );
    write_ptr += 32;
  }

  return (ulong)(write_ptr - out_txn_payload);
}

ulong fd_txn_add_instr( uchar * txn_meta_ptr,
                       uchar out_txn_payload[ static FD_TXN_MTU ],
                       uchar program_id,
                       uchar * accounts,
                       ulong accounts_len,
                       fd_build_instr_fun instr_fun,
                       uchar * opt_build_args,
                       ulong opt_args_len ) {

  fd_txn_t * txn_meta = (fd_txn_t *) txn_meta_ptr;
  FD_TEST( txn_meta->instr_cnt < FD_TXN_INSTR_MAX );
  FD_TEST( txn_meta->recent_blockhash_off != 0 );

  uchar * instr_start = out_txn_payload + txn_meta->recent_blockhash_off + BLOCKHASH_SZ;
  txn_meta->instr_cnt++;
  uchar compact_instr_cnt[3];
  uchar compact_instr_cnt_sz = (uchar) fd_cu16_enc( (ushort)txn_meta->instr_cnt, compact_instr_cnt );
  FD_TEST( compact_instr_cnt_sz == 1 );
  uchar * write_ptr       = instr_start;
  fd_memcpy( write_ptr, compact_instr_cnt, compact_instr_cnt_sz );
  write_ptr += compact_instr_cnt_sz;

  if ( txn_meta->instr_cnt > 1 ) {
    write_ptr = out_txn_payload + txn_meta->instr[txn_meta->instr_cnt-2].data_off + txn_meta->instr[txn_meta->instr_cnt-2].data_sz;
  }

  instr_start = write_ptr;

  fd_memcpy( write_ptr, &program_id, sizeof(uchar) );
  write_ptr += sizeof(uchar);

  uchar compact_accts_len[3];
  uchar compact_accts_len_sz = (uchar) fd_cu16_enc( (ushort)accounts_len, compact_accts_len );
  fd_memcpy( write_ptr, compact_accts_len, compact_accts_len_sz );
  write_ptr += compact_accts_len_sz;

  fd_memcpy( write_ptr, accounts, accounts_len );
  write_ptr += accounts_len;

  // Build instruction data
  uchar instr_buf[FD_TXN_MTU];
  ushort data_sz = (*instr_fun)( instr_buf, opt_build_args, opt_args_len );
  uchar compact_data_len[3];
  uint compact_data_len_sz = fd_cu16_enc( data_sz, compact_data_len );

  // Copy data array over
  fd_memcpy( write_ptr, compact_data_len, compact_data_len_sz );
  write_ptr += compact_data_len_sz;
  ushort data_off = (ushort) (write_ptr - out_txn_payload);
  fd_memcpy( write_ptr, instr_buf, data_sz );
  write_ptr += data_sz;
  ushort acct_off = (ushort) (instr_start + sizeof(uchar) + compact_accts_len_sz - out_txn_payload);

  (void) fd_txn_instr_meta_generate( (uchar*)&txn_meta->instr[txn_meta->instr_cnt-1], 
                                      program_id, 
                                      (ushort)accounts_len, 
                                      data_sz, acct_off, data_off );
  return (ulong)(write_ptr - out_txn_payload);
}
