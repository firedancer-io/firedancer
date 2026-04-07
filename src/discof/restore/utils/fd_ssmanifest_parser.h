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

void
fd_ssmanifest_parser_set_stake_delegation_cb(
    fd_ssmanifest_parser_t * parser,
    void (* cb)( void * ctx, fd_snapshot_manifest_stake_delegation_t const * delegation ),
    void * cb_ctx );

void
fd_ssmanifest_parser_set_vote_stakes_cb(
    fd_ssmanifest_parser_t * parser,
    void (* cb)( void * ctx, ulong epoch_idx, fd_snapshot_manifest_vote_stakes_t const * vs ),
    void * cb_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h */
