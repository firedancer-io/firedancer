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

#define FD_SSMANIFEST_PARSER_ADVANCE_ERROR        (-1)
#define FD_SSMANIFEST_PARSER_ADVANCE_AGAIN        ( 0)
#define FD_SSMANIFEST_PARSER_ADVANCE_DONE         ( 1)
#define FD_SSMANIFEST_PARSER_ADVANCE_DELEGATION   ( 2)
#define FD_SSMANIFEST_PARSER_ADVANCE_VOTE_ACCOUNT ( 3)
#define FD_SSMANIFEST_PARSER_ADVANCE_VOTE_STAKES  ( 4)

struct fd_ssmanifest_parser_advance_result {
  ulong consumed; /* bytes of buf consumed before this record was emitted */
  union {
    fd_snapshot_manifest_stake_delegation_t *  delegation;
    fd_snapshot_manifest_vote_account_full_t * vote_account;
    struct {
      ulong                                epoch_idx; /* 0,1,2 epoch_stakes slot */
      fd_snapshot_manifest_vote_stakes_t * vs;
    } vote_stakes;
  };
};

typedef struct fd_ssmanifest_parser_advance_result fd_ssmanifest_parser_advance_result_t;

int
fd_ssmanifest_parser_consume( fd_ssmanifest_parser_t *                parser,
                              uchar const *                           buf,
                              ulong                                   bufsz,
                              fd_ssmanifest_parser_advance_result_t * result );

/* Indicate to the parser that there are no more bytes coming.
   Returns DONE if the parser was at a point in the state machine
   where it is legal to finish, or ERROR otherwise.
   Must be called after the last consume(). */
int
fd_ssmanifest_parser_fini( fd_ssmanifest_parser_t * parser );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssmanifest_parser_h */
