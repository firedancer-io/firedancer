#ifndef HEADER_fd_src_discof_admin_fd_identity_transition_h
#define HEADER_fd_src_discof_admin_fd_identity_transition_h

#include "../../util/fd_util.h"

/* Observation only.  These values never drive a keyswitch or voting.
   Each snapshot has one writer.  All shared words are atomic, including
   the payload, so bounded seqlock reads have no C data races.  The
   sequentially consistent order prevents accepting a torn snapshot.
   No shared access is needed to account for an ordinary submission. */

#define FD_IDENTITY_STATE_IDLE          (0UL)
#define FD_IDENTITY_STATE_TRANSITIONING (1UL)
#define FD_IDENTITY_STATE_COMPLETE      (2UL)
#define FD_IDENTITY_STATE_FAILED        (3UL)
#define FD_IDENTITY_CONSENSUS_UNKNOWN   (0UL)
#define FD_IDENTITY_CONSENSUS_TOWER     (1UL)
#define FD_IDENTITY_CONSENSUS_ALPENGLOW (2UL)
#define FD_IDENTITY_ERROR_NONE          (0UL)
#define FD_IDENTITY_ERROR_UNAVAILABLE   (1UL)
#define FD_IDENTITY_ERROR_SAME_IDENTITY (2UL)
#define FD_IDENTITY_ERROR_SEQUENCE      (3UL)
#define FD_IDENTITY_FREEZE_REPLAY        (0UL)
#define FD_IDENTITY_FREEZE_VOTER         (1UL)
#define FD_IDENTITY_FREEZE_TXSEND        (2UL)

struct fd_identity_record {
  ulong instance[2];
  ulong sequence;
  ulong state;
  ulong consensus;
  ulong from[4];
  ulong to[4];
  ulong vote_account[4];
  ulong has_vote_account;
  ulong last_submitted_slot;
  ulong has_last_submitted_slot;
  ulong tower_root;
  ulong has_tower_root;
  ulong error;
};
typedef struct fd_identity_record fd_identity_record_t;

#define FD_IDENTITY_RECORD_WORDS (sizeof(fd_identity_record_t)/sizeof(ulong))
FD_STATIC_ASSERT( sizeof(fd_identity_record_t)==23UL*sizeof(ulong), identity_record_words );

struct __attribute__((aligned(128))) fd_identity_snapshot {
  ulong generation;
  ulong words[ FD_IDENTITY_RECORD_WORDS ];
};
typedef struct fd_identity_snapshot fd_identity_snapshot_t;

struct __attribute__((aligned(128))) fd_identity_transition {
  fd_identity_snapshot_t status;
  fd_identity_snapshot_t frozen[3];
};
typedef struct fd_identity_transition fd_identity_transition_t;

struct fd_identity_counter {
  ulong slot;
  ulong has_slot;
};
typedef struct fd_identity_counter fd_identity_counter_t;

/* Account only after successful local outbound acceptance, including
   retries.  A slot of zero is an observation, not a missing value. */
static inline void
fd_identity_submitted( fd_identity_counter_t * counter,
                       ulong                   slot ) {
  counter->slot     = fd_ulong_max( counter->slot, slot );
  counter->has_slot = 1UL;
}

static inline void
fd_identity_snapshot_write( fd_identity_snapshot_t *     snapshot,
                            fd_identity_record_t const * record ) {
  ulong words[ FD_IDENTITY_RECORD_WORDS ];
  memcpy( words, record, sizeof(words) );
  ulong generation = __atomic_load_n( &snapshot->generation, __ATOMIC_SEQ_CST );
  __atomic_store_n( &snapshot->generation, generation+1UL, __ATOMIC_SEQ_CST );
  for( ulong i=0UL; i<FD_IDENTITY_RECORD_WORDS; i++ )
    __atomic_store_n( &snapshot->words[i], words[i], __ATOMIC_SEQ_CST );
  __atomic_store_n( &snapshot->generation, generation+2UL, __ATOMIC_SEQ_CST );
}

/* Return zero when busy.  Neither producers nor RPC readers wait for
   the writer; an unavailable observation cannot delay the switch. */
static inline int
fd_identity_snapshot_read( fd_identity_snapshot_t const * snapshot,
                           fd_identity_record_t *         record ) {
  for( ulong attempt=0UL; attempt<8UL; attempt++ ) {
    ulong generation = __atomic_load_n( &snapshot->generation, __ATOMIC_SEQ_CST );
    if( generation & 1UL ) continue;
    ulong words[ FD_IDENTITY_RECORD_WORDS ];
    for( ulong i=0UL; i<FD_IDENTITY_RECORD_WORDS; i++ )
      words[i] = __atomic_load_n( &snapshot->words[i], __ATOMIC_SEQ_CST );
    if( generation!=__atomic_load_n( &snapshot->generation, __ATOMIC_SEQ_CST ) ) continue;
    memcpy( record, words, sizeof(words) );
    return 1;
  }
  return 0;
}

/* Capture the outgoing context immediately before its existing switch
   acknowledgement.  The command sequence and both identities prevent
   an old acknowledgement from completing a newer observation. */
static inline void
fd_identity_freeze( fd_identity_transition_t * shared,
                    ulong                      producer,
                    uchar const *              from,
                    uchar const *              to,
                    ulong                      consensus,
                    uchar const *              vote_account,
                    fd_identity_counter_t *    counter,
                    ulong                      tower_root ) {
  if( FD_LIKELY( shared ) ) {
    fd_identity_record_t record;
    if( fd_identity_snapshot_read( &shared->status, &record ) &&
        record.state==FD_IDENTITY_STATE_TRANSITIONING &&
        !memcmp( record.from, from, 32UL ) &&
        !memcmp( record.to,   to,   32UL ) ) {
      record.consensus               = consensus;
      record.has_vote_account        = !!vote_account;
      if( vote_account ) memcpy( record.vote_account, vote_account, 32UL );
      record.has_last_submitted_slot = counter ? counter->has_slot : 0UL;
      record.last_submitted_slot     = counter ? counter->slot     : 0UL;
      record.has_tower_root          = tower_root!=ULONG_MAX;
      record.tower_root              = tower_root;
      fd_identity_snapshot_write( &shared->frozen[producer], &record );
    }
  }
  if( counter && memcmp( from, to, 32UL ) ) memset( counter, 0, sizeof(*counter) );
}

static inline void
fd_identity_begin( fd_identity_transition_t * shared,
                   fd_identity_record_t *     record,
                   uchar const *              from,
                   uchar const *              to ) {
  if( FD_UNLIKELY( record->sequence==ULONG_MAX ) ) {
    record->state = FD_IDENTITY_STATE_FAILED;
    record->error = FD_IDENTITY_ERROR_SEQUENCE;
  } else {
    record->sequence++;
    record->state = FD_IDENTITY_STATE_TRANSITIONING;
    record->error = FD_IDENTITY_ERROR_NONE;
  }
  memcpy( record->from, from, 32UL );
  memcpy( record->to,   to,   32UL );
  record->consensus               = FD_IDENTITY_CONSENSUS_UNKNOWN;
  record->has_vote_account        = 0UL;
  record->has_last_submitted_slot = 0UL;
  record->has_tower_root          = 0UL;
  fd_identity_snapshot_write( &shared->status, record );
}

static inline int
fd_identity_matches( fd_identity_record_t const * a,
                     fd_identity_record_t const * b ) {
  return a->sequence==b->sequence &&
         !memcmp( a->instance, b->instance, sizeof(a->instance) ) &&
         !memcmp( a->from, b->from, 32UL ) &&
         !memcmp( a->to,   b->to,   32UL );
}

/* Called after the existing successful command completion.  Failure
   here describes missing evidence; it cannot fail the admin command. */
static inline void
fd_identity_finish( fd_identity_transition_t * shared,
                    fd_identity_record_t *     record,
                    int                        alpenglow ) {
  fd_identity_record_t replay, voter, txsend;
  int valid = fd_identity_snapshot_read( &shared->frozen[FD_IDENTITY_FREEZE_REPLAY], &replay ) &&
              fd_identity_snapshot_read( &shared->frozen[FD_IDENTITY_FREEZE_VOTER ], &voter  ) &&
              fd_identity_matches( record, &replay ) && fd_identity_matches( record, &voter );
  ulong consensus = alpenglow ? FD_IDENTITY_CONSENSUS_ALPENGLOW : FD_IDENTITY_CONSENSUS_TOWER;
  valid = valid && replay.consensus==consensus && voter.consensus==consensus;
  if( !alpenglow ) {
    valid = valid && fd_identity_snapshot_read( &shared->frozen[FD_IDENTITY_FREEZE_TXSEND], &txsend ) &&
            fd_identity_matches( record, &txsend );
  }
  if( record->error==FD_IDENTITY_ERROR_SEQUENCE ) valid = 0;
  if( !memcmp( record->from, record->to, 32UL ) ) {
    record->error = FD_IDENTITY_ERROR_SAME_IDENTITY;
    valid = 0;
  }
  if( valid ) {
    fd_identity_record_t const * submission = alpenglow ? &voter : &txsend;
    record->consensus               = consensus;
    record->has_vote_account        = alpenglow ? replay.has_vote_account : voter.has_vote_account;
    memcpy( record->vote_account, alpenglow ? replay.vote_account : voter.vote_account, 32UL );
    record->has_last_submitted_slot = submission->has_last_submitted_slot;
    record->last_submitted_slot     = submission->last_submitted_slot;
    record->has_tower_root          = !alpenglow && voter.has_tower_root;
    record->tower_root              = voter.tower_root;
    record->state                  = FD_IDENTITY_STATE_COMPLETE;
  } else {
    record->state = FD_IDENTITY_STATE_FAILED;
    if( !record->error ) record->error = FD_IDENTITY_ERROR_UNAVAILABLE;
  }
  fd_identity_snapshot_write( &shared->status, record );
}

#endif /* HEADER_fd_src_discof_admin_fd_identity_transition_h */
