#include "fd_adminctl.h"

#include "../../util/log/fd_log.h"

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define FD_ADMINCTL_MAGIC          (0xF17EDA2C37AD0200UL)
#define FD_ADMINCTL_STATE_MASK     (7UL)
#define FD_ADMINCTL_SEQ_SHIFT      (3UL)
#define FD_ADMINCTL_SEQ_BITS       (8UL)
#define FD_ADMINCTL_SEQ_VALUE_MASK ((1UL<<FD_ADMINCTL_SEQ_BITS)-1UL)
#define FD_ADMINCTL_TS_SHIFT       (FD_ADMINCTL_SEQ_SHIFT+FD_ADMINCTL_SEQ_BITS)
#define FD_ADMINCTL_TS_BITS        (FD_ADMINCTL_PID_SHIFT-FD_ADMINCTL_TS_SHIFT)
#define FD_ADMINCTL_TS_VALUE_MASK  ((1UL<<FD_ADMINCTL_TS_BITS)-1UL)
#define FD_ADMINCTL_PID_SHIFT      (32UL)
#define FD_ADMINCTL_RESERVE_TTL    (5UL)

#define FD_ADMINCTL_STATE_FREE       (0UL)
#define FD_ADMINCTL_STATE_RESERVED   (1UL)
#define FD_ADMINCTL_STATE_PUBLISHED  (2UL)
#define FD_ADMINCTL_STATE_PROCESSING (3UL)
#define FD_ADMINCTL_STATE_DONE       (4UL)

struct fd_adminctl_slot {
  ulong state_pid_seq;
  ulong cmd;
  ulong result;
  ulong payload_sz;
  uchar payload[ FD_ADMINCTL_PAYLOAD_MAX ];
};
typedef struct fd_adminctl_slot fd_adminctl_slot_t;

struct fd_adminctl_private {
  ulong               magic; /* ==FD_ADMINCTL_MAGIC */
  ulong               next_request_id;
  ulong               poll_idx;
  fd_adminctl_slot_t  slots[ FD_ADMINCTL_SLOT_CNT ];
};
typedef struct fd_adminctl_private fd_adminctl_t;

static inline ulong
fd_adminctl_state_pid_seq( uint  pid,
                           ulong seq,
                           ulong reserve_ts_sec,
                           ulong state ) {
  return (((ulong)pid)<<FD_ADMINCTL_PID_SHIFT) |
         ((reserve_ts_sec & FD_ADMINCTL_TS_VALUE_MASK)<<FD_ADMINCTL_TS_SHIFT) |
         ((seq & FD_ADMINCTL_SEQ_VALUE_MASK)<<FD_ADMINCTL_SEQ_SHIFT) |
         state;
}

static inline ulong
fd_adminctl_state( ulong state_pid_seq ) {
  return state_pid_seq & FD_ADMINCTL_STATE_MASK;
}

static inline ulong
fd_adminctl_state_update( ulong state_pid_seq,
                                  ulong state ) {
  return (state_pid_seq & ~FD_ADMINCTL_STATE_MASK) | state;
}

static inline ulong
fd_adminctl_reserve_ts_sec( ulong state_pid_seq ) {
  return (state_pid_seq>>FD_ADMINCTL_TS_SHIFT) & FD_ADMINCTL_TS_VALUE_MASK;
}

static inline uint
fd_adminctl_pid( ulong state_pid_seq ) {
  return (uint)(state_pid_seq>>FD_ADMINCTL_PID_SHIFT);
}

static inline ulong
fd_adminctl_now_sec( void ) {
  return (ulong)(fd_log_wallclock() / 1000000000L);
}

static inline ulong
fd_adminctl_elapsed_sec( ulong now_sec,
                         ulong then_sec ) {
  return (now_sec - then_sec) & FD_ADMINCTL_TS_VALUE_MASK;
}

static int
fd_adminctl_pid_alive( uint pid ) {
  if( FD_UNLIKELY( !pid ) ) return 0;
  if( FD_UNLIKELY( kill( (pid_t)pid, 0 ) ) ) {
    if( FD_LIKELY( errno==ESRCH ) ) return 0;
    return 1;
  }
  return 1;
}

static fd_adminctl_slot_t *
fd_adminctl_slot_laddr( fd_adminctl_t * adminctl,
                        ulong           slot_id ) {
  return &adminctl->slots[ slot_id ];
}

FD_FN_CONST ulong
fd_adminctl_align( void ) {
  return FD_ADMINCTL_ALIGN;
}

FD_FN_CONST ulong
fd_adminctl_footprint( void ) {
  return sizeof(fd_adminctl_t);
}

void *
fd_adminctl_new( void * shmem ) {
  fd_adminctl_t * adminctl = (fd_adminctl_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_adminctl_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_memset( adminctl, 0, fd_adminctl_footprint() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( adminctl->magic ) = FD_ADMINCTL_MAGIC;

  return (void *)adminctl;
}

fd_adminctl_t *
fd_adminctl_join( void * shadminctl ) {

  if( FD_UNLIKELY( !shadminctl ) ) {
    FD_LOG_WARNING(( "NULL shadminctl" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shadminctl, fd_adminctl_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shadminctl" ));
    return NULL;
  }

  fd_adminctl_t * adminctl = (fd_adminctl_t *)shadminctl;

  if( FD_UNLIKELY( adminctl->magic!=FD_ADMINCTL_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return adminctl;
}

ulong
fd_adminctl_reserve( fd_adminctl_t * adminctl,
                     void **         payload_out,
                     ulong *         payload_max_out ) {

  /* Identify the command process with a pid and a monotonically
     increasing sequence number. */
  uint  pid = (uint)getpid();
  ulong seq = FD_ATOMIC_ADD_AND_FETCH( &adminctl->next_request_id, 1UL );

  /* Track the pid of a process which may be hung */
  uint  hung_pid = UINT_MAX;
  ulong now_sec  = fd_adminctl_now_sec();

  for( ulong slot_id=0UL; slot_id<FD_ADMINCTL_SLOT_CNT; slot_id++ ) {
    fd_adminctl_slot_t * slot          = fd_adminctl_slot_laddr( adminctl, slot_id );
    ulong                state_pid_seq = FD_VOLATILE_CONST( slot->state_pid_seq );
    uint                 owner_pid     = fd_adminctl_pid( state_pid_seq );

    /* Reclaim a slot if it's a dead command.  The conditions for
       reclaiming a slot are:
       - the slot is in a command owned state (RESERVED or DONE)
       - the process for the slot is dead */
    ulong state = fd_adminctl_state( state_pid_seq );
    if( FD_UNLIKELY( (state==FD_ADMINCTL_STATE_RESERVED || state==FD_ADMINCTL_STATE_DONE) && !fd_adminctl_pid_alive( owner_pid ) ) ) {
      FD_LOG_WARNING(( "a dead command process (pid=%u) has been detected.  This is likely the "
                       "result of a process being killed before it issued the command "
                       "or consumed the result of the command", owner_pid ));
      ulong free_state_pid_seq = fd_adminctl_state_update( state_pid_seq, FD_ADMINCTL_STATE_FREE );
      if( FD_LIKELY( FD_ATOMIC_CAS( &slot->state_pid_seq, state_pid_seq, free_state_pid_seq )==state_pid_seq ) ) {
        state_pid_seq = FD_VOLATILE_CONST( slot->state_pid_seq );
        state         = fd_adminctl_state( state_pid_seq );
      } else {
        continue;
      }
    }

    /* If a slot is reserved and seems to be hung, track the pid to
       notify the caller.  Note that kill(pid,0) only checks the pid
       number; a reused pid can make a dead owner look hung. */
    if( FD_UNLIKELY( state==FD_ADMINCTL_STATE_RESERVED ) ) {
      ulong reserve_ts_sec = fd_adminctl_reserve_ts_sec( state_pid_seq );
      if( FD_UNLIKELY( fd_adminctl_pid_alive( owner_pid ) ) ) {
        if( FD_UNLIKELY( fd_adminctl_elapsed_sec( now_sec, reserve_ts_sec )>FD_ADMINCTL_RESERVE_TTL ) ) {
          hung_pid = owner_pid;
        }
      }
    }

    if( FD_UNLIKELY( state!=FD_ADMINCTL_STATE_FREE ) ) continue;

    ulong reserved_state_pid_seq = fd_adminctl_state_pid_seq( pid, seq, now_sec, FD_ADMINCTL_STATE_RESERVED );
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &slot->state_pid_seq, state_pid_seq, reserved_state_pid_seq )!=state_pid_seq ) ) continue;

    fd_memzero_explicit( slot->payload, sizeof(slot->payload) );
    *payload_out     = slot->payload;
    *payload_max_out = FD_ADMINCTL_PAYLOAD_MAX;
    return slot_id;
  }

  if( FD_UNLIKELY( hung_pid!=UINT_MAX ) ) {
    FD_LOG_WARNING(( "Unable to run command as there is another process (pid=%u) attempting to run a "
                     "command which appears to be hung (or the pid may have been reused) and has not "
                     "executed for over 5 seconds. Consider forcefully killing the process and "
                     "retrying the command.", hung_pid ));

  }

  return ULONG_MAX;
}

void
fd_adminctl_publish( fd_adminctl_t * adminctl,
                     ulong           slot_id,
                     ulong           cmd_id,
                     ulong           payload_sz ) {

  /* Now that the caller has written the payload into the adminctl's
     app region, we can publish the command to the admin tile.  At this
     point, the admin tile will own the command and return a result. */
  if( FD_UNLIKELY( slot_id>=FD_ADMINCTL_SLOT_CNT ) ) FD_LOG_CRIT(( "bad slot_id %lu", slot_id ));

  fd_adminctl_slot_t * slot          = fd_adminctl_slot_laddr( adminctl, slot_id );
  ulong                state_pid_seq = FD_VOLATILE_CONST( slot->state_pid_seq );
  if( FD_UNLIKELY( fd_adminctl_state( state_pid_seq )!=FD_ADMINCTL_STATE_RESERVED ) ) FD_LOG_CRIT(( "adminctl publish without reservation" ));

  slot->cmd        = cmd_id;
  slot->payload_sz = payload_sz;

  if( FD_UNLIKELY( FD_ATOMIC_CAS( &slot->state_pid_seq,
                                  state_pid_seq,
                                  fd_adminctl_state_update( state_pid_seq, FD_ADMINCTL_STATE_PUBLISHED ) )!=state_pid_seq ) ) {
    FD_LOG_ERR(( "The command process is in an unexpected and invalid state while sending the "
                 "the command to the running firedancer.  This is likely the result of a bug. "
                 "Please report this to the firedancer team." ));
  }
}

ulong
fd_adminctl_poll( fd_adminctl_t * adminctl,
                  ulong *         slot_id_out,
                  void **         payload_out,
                  ulong *         payload_sz_out ) {

  ulong                slot_id = adminctl->poll_idx++ % FD_ADMINCTL_SLOT_CNT;
  fd_adminctl_slot_t * slot    = fd_adminctl_slot_laddr( adminctl, slot_id );

  ulong state_pid_seq = FD_VOLATILE_CONST( slot->state_pid_seq );
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( fd_adminctl_state( state_pid_seq )!=FD_ADMINCTL_STATE_PUBLISHED ) ) return FD_ADMINCTL_CMD_IDLE;

  ulong cmd_id     = slot->cmd;
  ulong payload_sz = slot->payload_sz;

  ulong processing_state_pid_seq = fd_adminctl_state_update( state_pid_seq, FD_ADMINCTL_STATE_PROCESSING );
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &slot->state_pid_seq, state_pid_seq, processing_state_pid_seq )!=state_pid_seq ) ) return FD_ADMINCTL_CMD_IDLE;

  *slot_id_out    = slot_id;
  *payload_out    = slot->payload;
  *payload_sz_out = payload_sz;
  return cmd_id;
}

void
fd_adminctl_complete_response( fd_adminctl_t * adminctl,
                               ulong           slot_id,
                               ulong           result,
                               void const *    resp,
                               ulong           resp_sz ) {

  if( FD_UNLIKELY( resp_sz>FD_ADMINCTL_PAYLOAD_MAX ) ) FD_LOG_CRIT(( "bad resp_sz %lu", resp_sz ));

  fd_adminctl_slot_t * slot          = fd_adminctl_slot_laddr( adminctl, slot_id );
  ulong                state_pid_seq = FD_VOLATILE_CONST( slot->state_pid_seq );

  if( FD_UNLIKELY( fd_adminctl_state( state_pid_seq )!=FD_ADMINCTL_STATE_PROCESSING ) ) FD_LOG_ERR(( "adminctl complete without processing command" ));

  fd_memzero_explicit( slot->payload, slot->payload_sz );
  if( FD_UNLIKELY( resp_sz ) ) memcpy( slot->payload, resp, resp_sz );
  slot->payload_sz = resp_sz;
  slot->result     = result;
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &slot->state_pid_seq,
                                  state_pid_seq,
                                  fd_adminctl_state_update( state_pid_seq, FD_ADMINCTL_STATE_DONE ) )!=state_pid_seq ) )
    FD_LOG_ERR(( "invariant violation: adminctl_complete state update failed" ));
}

void
fd_adminctl_complete( fd_adminctl_t * adminctl,
                      ulong           slot_id,
                      ulong           result ) {
  fd_adminctl_complete_response( adminctl, slot_id, result, NULL, 0UL );
}

ulong
fd_adminctl_wait_response( fd_adminctl_t * adminctl,
                           ulong           slot_id,
                           void *          resp,
                           ulong           resp_max,
                           ulong *         resp_sz_out ) {

  fd_adminctl_slot_t * slot = fd_adminctl_slot_laddr( adminctl, slot_id );

  uint pid = (uint)getpid();

  for(;;) {
    ulong state_pid_seq = FD_VOLATILE_CONST( slot->state_pid_seq );
    FD_COMPILER_MFENCE();

    ulong state = fd_adminctl_state( state_pid_seq );
    if( FD_UNLIKELY( fd_adminctl_pid( state_pid_seq )!=pid ||
                     (state!=FD_ADMINCTL_STATE_PUBLISHED &&
                      state!=FD_ADMINCTL_STATE_PROCESSING &&
                      state!=FD_ADMINCTL_STATE_DONE) ) ) {
      FD_LOG_ERR(( "The command process is in an unexpected and invalid state while waiting for "
                   "the command to complete.  This is likely the result of a bug in firedancer. "
                   "Please report this to the firedancer team." ));
    }

    if( FD_LIKELY( state==FD_ADMINCTL_STATE_DONE ) ) {
      ulong result  = slot->result;
      ulong resp_sz = fd_ulong_min( slot->payload_sz, FD_ADMINCTL_PAYLOAD_MAX );
      if( FD_UNLIKELY( resp ) ) memcpy( resp, slot->payload, fd_ulong_min( resp_sz, resp_max ) );
      if( FD_UNLIKELY( resp_sz_out ) ) *resp_sz_out = resp_sz;
      fd_memzero_explicit( slot->payload, resp_sz );
      if( FD_LIKELY( FD_ATOMIC_CAS( &slot->state_pid_seq,
                                    state_pid_seq,
                                    fd_adminctl_state_update( state_pid_seq, FD_ADMINCTL_STATE_FREE ) )==state_pid_seq ) ) {
        return result;
      }
    }
    FD_SPIN_PAUSE();
  }
}

ulong
fd_adminctl_wait( fd_adminctl_t * adminctl,
                  ulong           slot_id ) {
  return fd_adminctl_wait_response( adminctl, slot_id, NULL, 0UL, NULL );
}
