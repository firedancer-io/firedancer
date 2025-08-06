#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_file_writer_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_file_writer_h

#include "fd_solcap_logger_backend.h"

struct fd_solcap_file_writer;
typedef struct fd_solcap_tile_writer fd_solcap_file_writer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_solcap_file_writer_align( void );

FD_FN_CONST ulong
fd_solcap_file_writer_footprint( void );

void *
fd_solcap_file_writer_new( void * mem );

fd_solcap_file_writer_t *
fd_solcap_file_writer_join( void * shfile_writer );

void *
fd_solcap_file_writer_leave( fd_solcap_file_writer_t * file_writer );

void *
fd_solcap_file_writer_delete( void * shfile_writer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_file_writer_h */