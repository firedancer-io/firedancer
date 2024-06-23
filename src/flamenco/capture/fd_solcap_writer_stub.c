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
                       void *               stream ) {
  (void)stream;
  return writer;
}

fd_solcap_writer_t *
fd_solcap_writer_flush( fd_solcap_writer_t * writer ) {
  return writer;
}

void
fd_solcap_writer_set_slot( fd_solcap_writer_t * writer,
                           ulong                slot ) {
  (void)writer; (void)slot;
} 

int
fd_solcap_write_account( fd_solcap_writer_t *             writer,
                         void const *                     key,
                         fd_solana_account_meta_t const * meta,
                         void const *                     data,
                         ulong                            data_sz,
                         void const *                     hash ) {
  (void)writer; (void)key; (void)meta; (void)data; (void)data_sz; (void)hash;
  return 0;
}

int
fd_solcap_write_account2( fd_solcap_writer_t *             writer,
                          fd_solcap_account_tbl_t const *  tbl,
                          fd_solcap_AccountMeta *          meta_pb,
                          void const *                     data,
                          ulong                            data_sz ) {
  (void)writer; (void)tbl; (void)meta_pb; (void)data; (void)data_sz;
  return 0;
}

int
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer,
                               void const *         bank_hash,
                               void const *         prev_bank_hash,
                               void const *         account_delta_hash,
                               void const *         poh_hash,
                               ulong                signature_cnt ) {
  (void)writer; (void)bank_hash; (void)prev_bank_hash; (void)account_delta_hash; (void)poh_hash; (void)signature_cnt;
  return 0;
}

int
fd_solcap_write_bank_preimage2( fd_solcap_writer_t *     writer,
                                fd_solcap_BankPreimage * preimg ) {
  (void)writer; (void)preimg;
  return 0;
}

int
fd_solcap_write_transaction2( fd_solcap_writer_t *    writer,
                              fd_solcap_Transaction * txn ) {
  (void)writer; (void)txn;
  return 0;
}
