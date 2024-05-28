#include "fd_txn_generate.h"

/* Message header type */
struct __attribute__((packed)) fd_txn_message_hdr {
  uchar num_signatures;
  uchar num_readonly_signatures;
  uchar num_readonly_unsigned;
};

typedef struct fd_txn_message_hdr fd_txn_message_hdr_t;

static fd_txn_instr_t *
fd_txn_instr_meta_generate( uchar * out_buf,
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

ulong
fd_txn_base_generate( uchar out_txn_meta[ static FD_TXN_MAX_SZ ],
                      uchar out_txn_payload[ static FD_TXN_MTU ],
                      ulong num_signatures,
                      fd_txn_accounts_t * accounts,
                      uchar * opt_recent_blockhash ) {

  /* Number of signatures cannot exceed 127. */
  FD_TEST(num_signatures <= FD_TXN_SIG_MAX);
  *out_txn_payload = (uchar)num_signatures;

  /* Fill out txn metadata */
  fd_txn_t * txn_meta             = (fd_txn_t *) out_txn_meta;
  txn_meta->acct_addr_cnt         = accounts->acct_cnt;
  txn_meta->readonly_signed_cnt   = accounts->readonly_signed_cnt;
  txn_meta->readonly_unsigned_cnt = accounts->readonly_unsigned_cnt;
  /* Number of signatures is encoded as a compact u16 but
     can always be encoded using 1 byte here. */
  txn_meta->message_off           = (ushort)(num_signatures * FD_TXN_SIGNATURE_SZ  + 1);
  txn_meta->signature_off         = (ushort)1UL;
  txn_meta->instr_cnt             = 0;

  FD_TEST(txn_meta->acct_addr_cnt < FD_TXN_ACCT_ADDR_MAX);
  txn_meta->acct_addr_off        = (ushort)(txn_meta->message_off + (sizeof(fd_txn_message_hdr_t)) + 1);
  txn_meta->recent_blockhash_off = (ushort)(txn_meta->acct_addr_off + (txn_meta->acct_addr_cnt * FD_TXN_ACCT_ADDR_SZ));

  /* Fill message header in txn payload */
  uchar * write_ptr = out_txn_payload + txn_meta->message_off;
  fd_txn_message_hdr_t msg_header = { .num_signatures = accounts->signature_cnt,
                                      .num_readonly_signatures = accounts->readonly_signed_cnt,
                                      .num_readonly_unsigned   = accounts->readonly_unsigned_cnt };
  memcpy( write_ptr, &msg_header, sizeof(fd_txn_message_hdr_t) ) ;
  write_ptr += sizeof(fd_txn_message_hdr_t);

  /* Write number of accounts */
  *write_ptr = (uchar)txn_meta->acct_addr_cnt;
  write_ptr += 1;

  /* Write accounts list to txn payload */
  ulong signers_write_sz = FD_TXN_ACCT_ADDR_SZ * (ulong)(accounts->signature_cnt - accounts->readonly_signed_cnt);
  fd_memcpy( write_ptr, accounts->signers_w, signers_write_sz );
  write_ptr += signers_write_sz;

  fd_memcpy( write_ptr, accounts->signers_r, FD_TXN_ACCT_ADDR_SZ * accounts->readonly_signed_cnt );
  write_ptr += FD_TXN_ACCT_ADDR_SZ * accounts->readonly_signed_cnt;

  ulong non_signers_write_sz = FD_TXN_ACCT_ADDR_SZ * (ulong)(accounts->acct_cnt - accounts->readonly_unsigned_cnt - accounts->signature_cnt);
  fd_memcpy( write_ptr, accounts->non_signers_w, non_signers_write_sz);
  write_ptr += non_signers_write_sz;

  fd_memcpy( write_ptr, accounts->non_signers_r, FD_TXN_ACCT_ADDR_SZ * accounts->readonly_unsigned_cnt );
  write_ptr += FD_TXN_ACCT_ADDR_SZ * accounts->readonly_unsigned_cnt;
  FD_TEST( (ushort)((ulong)write_ptr - (ulong)out_txn_payload) == txn_meta->recent_blockhash_off );

  /* Write recent blockhash */
  if( FD_LIKELY( opt_recent_blockhash ) ) {
    memcpy( write_ptr, opt_recent_blockhash, FD_TXN_BLOCKHASH_SZ );
  } else {
    memset( write_ptr, 0UL, FD_TXN_BLOCKHASH_SZ );
  }
  write_ptr += FD_TXN_BLOCKHASH_SZ;

  return (ulong)(write_ptr - out_txn_payload);
}

ulong
fd_txn_add_instr( uchar * txn_meta_ptr,
                  uchar out_txn_payload[ static FD_TXN_MTU ],
                  uchar program_id,
                  uchar const * accounts,
                  ulong accounts_sz,
                  uchar const * instr_buf,
                  ulong instr_buf_sz ) {

  fd_txn_t * txn_meta = (fd_txn_t *) txn_meta_ptr;
  FD_TEST( txn_meta->instr_cnt < FD_TXN_INSTR_MAX );
  FD_TEST( txn_meta->recent_blockhash_off != 0 );

  uchar * instr_start = out_txn_payload + txn_meta->recent_blockhash_off + FD_TXN_BLOCKHASH_SZ;
  txn_meta->instr_cnt++;
  uchar * write_ptr       = instr_start;

  uint compact_instr_cnt_sz = fd_cu16_enc( (ushort)txn_meta->instr_cnt, write_ptr );
  FD_TEST( compact_instr_cnt_sz == 1 );

  write_ptr += compact_instr_cnt_sz;

  /* Calculate offset of next instruction. */
  if ( FD_UNLIKELY( txn_meta->instr_cnt > 1 ) ) {
    write_ptr = out_txn_payload + txn_meta->instr[txn_meta->instr_cnt-2].data_off + txn_meta->instr[txn_meta->instr_cnt-2].data_sz;
  }

  instr_start = write_ptr;

  *write_ptr = program_id;
  write_ptr += sizeof(uchar);

  uint compact_accts_len_sz = fd_cu16_enc( (ushort)accounts_sz, write_ptr );
  write_ptr += compact_accts_len_sz;

  ushort acct_off = (ushort) (write_ptr - out_txn_payload);
  fd_memcpy( write_ptr, accounts, accounts_sz );
  write_ptr += accounts_sz;

  ushort data_sz = (ushort)instr_buf_sz;
  uint compact_data_len_sz = fd_cu16_enc( data_sz, write_ptr );
  write_ptr += compact_data_len_sz;

  /* Copy data buffer over */
  ushort data_off = (ushort) (write_ptr - out_txn_payload);
  fd_memcpy( write_ptr, instr_buf, data_sz );
  write_ptr += data_sz;

  (void) fd_txn_instr_meta_generate( (uchar*)&txn_meta->instr[txn_meta->instr_cnt-1],
                                      program_id,
                                      (ushort)accounts_sz,
                                      data_sz, acct_off, data_off );
  return (ulong)(write_ptr - out_txn_payload);
}

void
fd_txn_reset_instrs( uchar * txn_meta_ptr,
                     uchar out_txn_payload[ static FD_TXN_MTU ] ) {
  fd_txn_t * txn_meta = (fd_txn_t *)txn_meta_ptr;
  if( FD_UNLIKELY( txn_meta->instr_cnt == 0 ) ) {
    return;
  }

  ulong instr_start   = txn_meta->recent_blockhash_off + FD_TXN_BLOCKHASH_SZ;

  *(out_txn_payload + instr_start) = 0;
  txn_meta->instr_cnt = 0;
}
