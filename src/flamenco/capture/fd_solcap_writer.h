#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_writer_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_writer_h

#include "fd_solcap_proto.h"
#include "fd_solcap.pb.h"
#include "../types/fd_types.h"

#if FD_HAS_HOSTED

/* fd_solcap_writer_t is an opaque handle to a capture writer object.
   Currently, it implements writing SOLCAP_V1_BANK files.  See below
   on how to create and use this class. */

struct fd_solcap_writer;
typedef struct fd_solcap_writer fd_solcap_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_solcap_writer_t object lifecycle API ****************************/

/* fd_solcap_writer_{align,footprint} return align and footprint
   requirements for the memory region backing the fd_solcap_writer_t
   object.  fd_solcap_writer_align returns a power of two.
   fd_solcap_writer_footprint returns a non-zero byte count. */

ulong
fd_solcap_writer_align( void );

ulong
fd_solcap_writer_footprint( void );

/* fd_solcap_writer_new creates a new fd_solcap_writer_t object using
   the given memory region.  mem points to a memory region with matching
   align and footprint.  Returns a pointer to the writer object within
   memory region, assigns ownership of mem to the object, and assigs
   ownership of the object to the caller.  Returned pointer should not
   assumed to be a simple cast of mem.  On failure, logs error and
   returns NULL.  Reasons for failure include mem==NULL or invalid
   alignment. */

fd_solcap_writer_t *
fd_solcap_writer_new( void * mem );

/* fd_solcap_writer_delete destroys the given fd_solcap_writer_t object
   and transfers ownership of the backing memory region to the caller.
   If mem is NULL, behaves like a noop and returns NULL. */

void *
fd_solcap_writer_delete( fd_solcap_writer_t * mem );

/* fd_solcap_writer_init initializes writer to write to a new stream.
   stream is (FILE *) or the platform-specific equivalent.  The stream
   offset should be positioned to where the capture header is expected
   (usually file offset 0).  stream access mode should be write and
   should support random seeking, read is currently not required.
   Returns writer, transfers ownership of stream to writer, and
   writes the capture file header to stream on success.  On failure,
   logs reason and returns NULL and returns stream to the user.
   Reasons for failure are stream I/O error.  On failure, writer is left
   in uninitialized state (safe to retry init), and stream is left in
   unspecified state (caller should discard any writes made to stream). s*/

fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                       void *               stream );

/* fd_solcap_writer_flush finishes any outstanding writes and yields
   ownership of the stream handle back to the caller of init. Always returns 
   writer for convenience. If an error occurs, writes reason to log. */

fd_solcap_writer_t *
fd_solcap_writer_flush( fd_solcap_writer_t * writer );

/* fd_solcap_writer_t user API *****************************************

   Before calling below functions, the object must have been initialized
   successfully.  Currently, only supports SOLCAP_V1_BANK files.  For
   every slot, order of operations should be as follows:
     - set_slot
     - write_account (repeatedly)
     - write_bank_preimage
     - write_bank_hash */

/* fd_solcap_writer_set_slot starts a new slot record.  Finishes any
   previous slot record.  slot numbers must be monotonically increasing. */

void
fd_solcap_writer_set_slot( fd_solcap_writer_t * writer,
                          ulong                slot );

/* fd_solcap_write_account appends a copy of the given account (key,
   meta, data) tuple to the stream.  Must only be called for accounts
   that are part of the current slot's account delta hash. Order of
   accounts is arbitrary. */

int
fd_solcap_write_account( fd_solcap_writer_t *             writer,
                         void const *                     key,
                         fd_solana_account_meta_t const * meta,
                         void const *                     data,
                         ulong                            data_sz,
                         void const *                     hash );

int
fd_solcap_write_account2( fd_solcap_writer_t *             writer,
                          fd_solcap_account_tbl_t const *  tbl,
                          fd_solcap_AccountMeta *          meta_pb,
                          void const *                     data,
                          ulong                            data_sz );

/* fd_solcap_write_bank_preimage sets additional fields that are part
   of the current slot's bank hash preimage.  prev_bank_hash is the
   bank hash of the previous block.  account_delta_hash is the Merkle
   root of the changed accounts (these accounts should match the ones
   passed to fd_solcap_write_account).  poh_hash is the PoH hash of the
   current block.  TODO what is signature_cnt? */

int
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer,
                               void const *         bank_hash,
                               void const *         prev_bank_hash,
                               void const *         account_delta_hash,
                               void const *         poh_hash,
                               ulong                signature_cnt );

int
fd_solcap_write_bank_preimage2( fd_solcap_writer_t *     writer,
                                fd_solcap_BankPreimage * preimg );

/* fd_solcap_write_transaction writes the given transaction to the
   stream.  Must only be called for transactions that are part of the
   current slot's transaction hash. */

int fd_solcap_write_transaction( fd_solcap_writer_t * writer,
                                 void const *         txn_sig,
                                 int                  txn_err,
                                 uint                 custom_err,
                                 ulong                slot,
                                 ulong                fd_cus,
                                 ulong                solana_cus,
                                 ulong                solana_err );

int fd_solcap_write_transaction2( fd_solcap_writer_t * writer,
                                  fd_solcap_Transaction * txn );

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_writer_h */
