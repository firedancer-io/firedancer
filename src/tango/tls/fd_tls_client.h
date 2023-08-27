#ifndef HEADER_fd_src_tango_tls_fd_tls_client_h
#define HEADER_fd_src_tango_tls_fd_tls_client_h

#include "fd_tls_estate_cli.h"
#include "fd_tls_server.h"  /* ugly */

/* TODO For now, fd_tls_server and fd_tls_client are identical. */

typedef struct fd_tls_server fd_tls_client_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_tls_client_align( void );

FD_FN_CONST ulong
fd_tls_client_footprint( void );

void *
fd_tls_client_new( void * mem );

fd_tls_client_t *
fd_tls_client_join( void * );

void *
fd_tls_client_leave( fd_tls_server_t * );

void *
fd_tls_client_delete( void * );

long
fd_tls_client_handshake( fd_tls_client_t const * client,
                         fd_tls_estate_cli_t *   handshake,
                         void *                  record,
                         ulong                   record_sz,
                         int                     encryption_level );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tls_fd_tls_client_h */
