#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_writer_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_writer_h

#include "fd_solcap_proto.h"

#if FD_HAS_HOSTED

struct fd_solcap_writer;
typedef struct fd_solcap_writer fd_solcap_writer_t;

FD_PROTOTYPES_BEGIN

ulong
fd_solcap_writer_align( void );

ulong
fd_solcap_writer_footprint( void );

void *
fd_solcap_writer_new( void * mem );

fd_solcap_writer_t *
fd_solcap_writer_join( void * mem );

void *
fd_solcap_writer_leave( fd_solcap_writer_t * writer );

void *
fd_solcap_writer_delete( void * mem );


fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                       void *               stream );

fd_solcap_writer_t *
fd_solcap_writer_fini( fd_solcap_writer_t * writer );


int
fd_solcap_write_set_slot( fd_solcap_writer_t * writer,
                          ulong                slot );

int
fd_solcap_write_account( fd_solcap_writer_t *        writer,
                         fd_solcap_account_t const * account,
                         void const *                data,
                         ulong                       data_sz );

void
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer,
                               void const *         prev_bank_hash,
                               void const *         account_delta_hash,
                               void const *         poh_hash );

void
fd_solcap_write_bank_hash( fd_solcap_writer_t * writer,
                           uchar const *        hash );

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_writer_h */
