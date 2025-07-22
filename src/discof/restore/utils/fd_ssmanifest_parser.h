#ifndef HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h
#define HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h

#include "fd_ssmsg.h"

struct fd_ssmanifest_parser_private;
typedef struct fd_ssmanifest_parser_private fd_ssmanifest_parser_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ssmanifest_parser_align( void );

FD_FN_CONST ulong
fd_ssmanifest_parser_footprint( void );

void *
fd_ssmanifest_parser_new( void * shmem );

fd_ssmanifest_parser_t *
fd_ssmanifest_parser_join( void * shmem );

void
fd_ssmanifest_parser_init( fd_ssmanifest_parser_t * parser,
                           fd_snapshot_manifest_t * manifest );

int
fd_ssmanifest_parser_consume( fd_ssmanifest_parser_t * parser,
                              uchar const *            buf,
                              ulong                    bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h */
