#include "fd_solcap_writer.h"

/* This file provides a stub implementation of fd_solcap_writer for
   non-hosted targets. */

struct fd_solcap_writer {
  uchar dummy;
};

ulong
fd_solcap_writer_align( void ) {
  return alignof(fd_solcap_writer_t);
}

ulong
fd_solcap_writer_footprint( void ) {
  return sizeof(fd_solcap_writer_t);
}

fd_solcap_writer_t *
fd_solcap_writer_new( void * mem ) {
  return mem;
}

void *
fd_solcap_writer_delete( fd_solcap_writer_t * mem ) {
  return mem;
}

fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                       void *               stream FD_PARAM_UNUSED ) {
  return writer;
}

fd_solcap_writer_t *
fd_solcap_writer_flush( fd_solcap_writer_t * writer ) {
  return writer;
}

void
fd_solcap_writer_set_slot( fd_solcap_writer_t * writer FD_PARAM_UNUSED,
                           ulong                slot   FD_PARAM_UNUSED ) {}

int
fd_solcap_write_account( fd_solcap_writer_t *             writer  FD_PARAM_UNUSED,
                         void const *                     key     FD_PARAM_UNUSED,
                         fd_solana_account_meta_t const * meta    FD_PARAM_UNUSED,
                         void const *                     data    FD_PARAM_UNUSED,
                         ulong                            data_sz FD_PARAM_UNUSED,
                         void const *                     hash    FD_PARAM_UNUSED ) {
  return 0;
}

int
fd_solcap_write_account2( fd_solcap_writer_t *             writer  FD_PARAM_UNUSED,
                          fd_solcap_account_tbl_t const *  tbl     FD_PARAM_UNUSED,
                          fd_solcap_AccountMeta *          meta_pb FD_PARAM_UNUSED,
                          void const *                     data    FD_PARAM_UNUSED,
                          ulong                            data_sz FD_PARAM_UNUSED ) {
  return 0;
}

int
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer             FD_PARAM_UNUSED,
                               void const *         bank_hash          FD_PARAM_UNUSED,
                               void const *         prev_bank_hash     FD_PARAM_UNUSED,
                               void const *         account_delta_hash FD_PARAM_UNUSED,
                               void const *         poh_hash           FD_PARAM_UNUSED,
                               ulong                signature_cnt      FD_PARAM_UNUSED ) {
  return 0;
}

int
fd_solcap_write_bank_preimage2( fd_solcap_writer_t *     writer FD_PARAM_UNUSED,
                                fd_solcap_BankPreimage * preimg FD_PARAM_UNUSED ) {
  return 0;
}

int
fd_solcap_write_transaction2( fd_solcap_writer_t *    writer FD_PARAM_UNUSED,
                              fd_solcap_Transaction * txn    FD_PARAM_UNUSED ) {
  return 0;
}
