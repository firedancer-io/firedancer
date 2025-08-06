#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_writer_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_writer_h

#include "../../util/fd_util_base.h"

struct fd_solcap_writer;
typedef struct fd_solcap_writer fd_solcap_writer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_solcap_writer_tile_align( void );

FD_FN_CONST ulong
fd_solcap_writer_tile_footprint( void );

void *
fd_solcap_writer_tile_new( void * mem );

fd_solcap_writer_t *
fd_solcap_writer_tile_join( void * shtile_writer );

void *
fd_solcap_writer_tile_leave( fd_solcap_tile_writer_t * tile_writer );

void *
fd_solcap_tile_writer_delete( void * shtile_writer );

/* Make an interface by having a vt of operations
   - prepare
   - publish */
uchar *
fd_solcap_writer_prepare( fd_solcap_writer_t * backend,
                          ulong                        sz );

int
fd_solcap_writer_publish( fd_solcap_writer_t * backend,
                          uchar const *                data,
                          ulong                        sz );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_writer_backend_h */
