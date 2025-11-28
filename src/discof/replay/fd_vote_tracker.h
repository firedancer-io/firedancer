#ifndef HEADER_fd_src_discof_replay_fd_vote_tracker_h
#define HEADER_fd_src_discof_replay_fd_vote_tracker_h

#include "../../util/fd_util_base.h"
#include "../../flamenco/types/fd_types.h"

FD_PROTOTYPES_BEGIN

/* TODO: Add documentation for the vote tracker. */

struct fd_vote_tracker;
typedef struct fd_vote_tracker fd_vote_tracker_t;

ulong
fd_vote_tracker_align( void );

ulong
fd_vote_tracker_footprint( void );

void *
fd_vote_tracker_new( void * mem,
                     ulong  seed );

fd_vote_tracker_t *
fd_vote_tracker_join( void * mem );

void
fd_vote_tracker_insert( fd_vote_tracker_t *    vote_tracker,
                        fd_signature_t const * vote_sig );

int
fd_vote_tracker_query_sig( fd_vote_tracker_t *    vote_tracker,
                           fd_signature_t const * vote_sig );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_states_h */
