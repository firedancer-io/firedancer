#ifndef HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h
#define HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h

#include "fd_ssmsg.h"
#include "fd_ssparse.h"

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

#define FD_SSMANIFEST_PARSER_ADVANCE_ERROR (-1)
#define FD_SSMANIFEST_PARSER_ADVANCE_AGAIN ( 0)
#define FD_SSMANIFEST_PARSER_ADVANCE_DONE  ( 1)
int
fd_ssmanifest_parser_consume( fd_ssmanifest_parser_t * parser,
                              uchar const *            buf,
                              ulong                    bufsz,
                              acc_vec_map_t *          acc_vec_map,
                              acc_vec_t *              acc_vec_pool );

/* On-the-fly stake delegation polling interface.  After each
   fd_ssmanifest_parser_consume() call, the consumer checks
   fd_ssmanifest_parser_delegation_ready().  If it returns non-zero,
   a complete stake delegation entry is available in staging and should
   be drained.  The consumer must call
   fd_ssmanifest_parser_delegation_done() after processing. */

int
fd_ssmanifest_parser_delegation_ready( fd_ssmanifest_parser_t const * parser );

fd_snapshot_manifest_stake_delegation_t const *
fd_ssmanifest_parser_delegation_peek( fd_ssmanifest_parser_t const * parser );

void
fd_ssmanifest_parser_delegation_done( fd_ssmanifest_parser_t * parser );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h */
