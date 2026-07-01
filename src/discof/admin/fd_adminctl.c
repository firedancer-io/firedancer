#include "fd_adminctl.h"

#include "../../util/log/fd_log.h"

#define FD_ADMINCTL_RESERVE_TIMEOUT_SECONDS (5L)
#define FD_ADMINCTL_MAGIC                   (0xF17EDA2C37AD0100UL)
#define FD_ADMINCTL_STATE_MASK              (3UL)
#define FD_ADMINCTL_SEQ_SHIFT               (2UL)
#define FD_ADMINCTL_SEQ_BITS                (30UL)
#define FD_ADMINCTL_SEQ_INC                 (1UL<<FD_ADMINCTL_SEQ_SHIFT)
#define FD_ADMINCTL_SEQ_MASK                (((1UL<<FD_ADMINCTL_SEQ_BITS)-1UL)<<FD_ADMINCTL_SEQ_SHIFT)
#define FD_ADMINCTL_TS_SHIFT                (FD_ADMINCTL_SEQ_SHIFT+FD_ADMINCTL_SEQ_BITS)
#define FD_ADMINCTL_TS_MASK                 (~0UL<<FD_ADMINCTL_TS_SHIFT)
#define FD_ADMINCTL_TS_VALUE_MASK           ((1UL<<(64UL-FD_ADMINCTL_TS_SHIFT))-1UL)

struct fd_adminctl_private {
  ulong             magic; /* ==FD_ADMINCTL_MAGIC */
  ulong             state_seq;
  ulong             request_id;
  ulong             cmd;
  ulong             result;
  ulong             payload_sz;
  ulong             payload_checksum;
  uchar             payload[ FD_ADMINCTL_PAYLOAD_MAX ];
};
struct fd_adminctl_private;
typedef struct fd_adminctl_private fd_adminctl_t;

/* Various helpers to mask/pack/extract the timestamp, sequence, and
   state bits from the state sequence. */

static inline ulong
fd_adminctl_state( ulong state_seq ) {
  return state_seq & FD_ADMINCTL_STATE_MASK;
}

static inline ulong
fd_adminctl_state_seq_update( ulong state_seq,
                              ulong state ) {
  return (state_seq & ~FD_ADMINCTL_STATE_MASK) | state;
}

static inline ulong
fd_adminctl_state_seq_next( ulong state_seq,
                            ulong state,
                            ulong ts ) {
  ulong seq = ((state_seq & FD_ADMINCTL_SEQ_MASK) + FD_ADMINCTL_SEQ_INC) & FD_ADMINCTL_SEQ_MASK;
  return ((ts & FD_ADMINCTL_TS_VALUE_MASK)<<FD_ADMINCTL_TS_SHIFT) | seq | state;
}

static inline ulong
fd_adminctl_ts( ulong state_seq ) {
  return (state_seq & FD_ADMINCTL_TS_MASK) >> FD_ADMINCTL_TS_SHIFT;
}

static inline ulong
fd_adminctl_slot_seq( ulong state_seq ) {
  return state_seq & ~FD_ADMINCTL_STATE_MASK;
}

static FD_FN_PURE ulong
fd_adminctl_payload_checksum( ulong         slot_seq,
                              ulong         cmd,
                              ulong         payload_sz,
                              void const *  payload ) {
  ulong h = fd_hash( slot_seq, &cmd, sizeof(ulong) );
  h = fd_hash( h, &payload_sz, sizeof(ulong) );
  return fd_hash( h, payload, payload_sz );
}

static inline ulong
fd_adminctl_now_sec( void ) {
  return (ulong)(fd_log_wallclock() / 1000000000L);
}

static inline void *
fd_adminctl_payload_laddr( fd_adminctl_t * adminctl ) {
  return (void *)adminctl->payload;
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
fd_adminctl_poll( fd_adminctl_t * adminctl,
                  void *          data,
                  ulong           data_max,
                  ulong *         data_sz ) {

  *data_sz = 0UL;
  ulong state_seq = FD_VOLATILE_CONST( adminctl->state_seq );
  FD_COMPILER_MFENCE();

  ulong state = fd_adminctl_state( state_seq );
  if( FD_LIKELY( state==FD_ADMINCTL_STATE_PUBLISHED ) ) {
    /* Start consuming the command. */
    ulong slot_seq = fd_adminctl_slot_seq( state_seq );
    ulong cmd        = adminctl->cmd;
    ulong payload_sz = adminctl->payload_sz;
    ulong checksum   = adminctl->payload_checksum;

    if( FD_UNLIKELY( payload_sz>data_max ) ) {
      FD_LOG_WARNING(( "adminctl payload too big, dropping command" ));
      fd_memzero_explicit( adminctl->payload, sizeof(adminctl->payload) );
      adminctl->result = FD_ADMINCTL_RESULT_FAILED;
      FD_ATOMIC_CAS( &adminctl->state_seq, state_seq, fd_adminctl_state_seq_update( state_seq, FD_ADMINCTL_STATE_DONE ) );
      return FD_ADMINCTL_CMD_IDLE;
    }

    memcpy( data, adminctl->payload, payload_sz );
    *data_sz = payload_sz;

    /* If the checksum doesn't match, this means that the command data
       got trampled by a racing command.  Reset the state to FREE. */
    if( FD_UNLIKELY( checksum!=fd_adminctl_payload_checksum( slot_seq, cmd, *data_sz, data ) ) ) {
      fd_memzero_explicit( adminctl->payload, payload_sz );
      FD_ATOMIC_CAS( &adminctl->state_seq, state_seq, fd_adminctl_state_seq_update( state_seq, FD_ADMINCTL_STATE_FREE ) );
      return FD_ADMINCTL_CMD_IDLE;
    }

    fd_memzero_explicit( adminctl->payload, payload_sz );
    return cmd;
  }

  /* If the command is reserved, reset the adminctl state if the
     reservation has expired. */
  if( FD_UNLIKELY( state==FD_ADMINCTL_STATE_RESERVED ) ) {
    ulong now_sec     = fd_adminctl_now_sec();
    ulong reserve_sec = fd_adminctl_ts( state_seq );
    long  reserve_age = (long)now_sec - (long)reserve_sec;
    if( FD_UNLIKELY( reserve_age>(long)FD_ADMINCTL_RESERVE_TIMEOUT_SECONDS ) ) {
      FD_LOG_WARNING(( "clearing stale adminctl reservation" ));
      FD_ATOMIC_CAS( &adminctl->state_seq, state_seq, fd_adminctl_state_seq_update( state_seq, FD_ADMINCTL_STATE_FREE ) );
    }
  }

  return FD_ADMINCTL_CMD_IDLE;
}

ulong
fd_adminctl_publish( fd_adminctl_t * adminctl,
                     ulong           cmd,
                     void const *    payload,
                     ulong           payload_sz ) {
  if( FD_UNLIKELY( payload_sz>FD_ADMINCTL_PAYLOAD_MAX ) ) FD_LOG_CRIT(( "adminctl payload_sz %lu", payload_sz ));

  for(;;) {
    ulong state_seq = FD_VOLATILE_CONST( adminctl->state_seq );
    FD_COMPILER_MFENCE();

    /* If there's an active reservation or a command has been published,
       spin until it is complete. It's acceptable to start publishing
       before another process has consumed the result of a previous
       command. */
    ulong state = fd_adminctl_state( state_seq );
    if( FD_UNLIKELY( state==FD_ADMINCTL_STATE_RESERVED || state==FD_ADMINCTL_STATE_PUBLISHED ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    /* Update the state to RESERVED and set the reserve timestamp for
       the TTL atomically.  If the state seq isn't what you expect, spin
       and try later because another process beat you to it. */
    ulong reserved_state_seq = fd_adminctl_state_seq_next( state_seq, FD_ADMINCTL_STATE_RESERVED, fd_adminctl_now_sec() );
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &adminctl->state_seq, state_seq, reserved_state_seq )!=state_seq ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    /* Update the request id and return it to the command thread so it
       can wait for the result. */
    ulong request_id = FD_ATOMIC_FETCH_AND_ADD( &adminctl->request_id, 1UL ) + 1UL;
    if( FD_UNLIKELY( !request_id ) ) request_id = FD_ATOMIC_FETCH_AND_ADD( &adminctl->request_id, 1UL ) + 1UL;

    /* Copy in the payload into the adminctl payload region and compute
       a checksum of the sequence number, command, and payload. */
    void * payload_laddr = fd_adminctl_payload_laddr( adminctl );
    ulong  slot_seq      = fd_adminctl_slot_seq( reserved_state_seq );

    memcpy( payload_laddr, payload, payload_sz );
    adminctl->payload_sz       = payload_sz;
    adminctl->cmd              = cmd;
    adminctl->payload_checksum = fd_adminctl_payload_checksum( slot_seq, cmd, payload_sz, payload_laddr );
    FD_COMPILER_MFENCE();

    /* Update the state to PUBLISHED and publish the command atomically.
       If the state seq isn't what you expect, spin and try later
       because another process beat you to it. */
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &adminctl->state_seq,
                                    reserved_state_seq,
                                    fd_adminctl_state_seq_update( reserved_state_seq, FD_ADMINCTL_STATE_PUBLISHED ) )!=reserved_state_seq ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
    return request_id;
  }
}

void
fd_adminctl_complete( fd_adminctl_t * adminctl,
                      ulong           result ) {
  /* Once the command has been completed by the main process, the TTL
     timestamp should be cleared and the state should be updated to
     done.  There is no guarantee that the command process will be able
     to consume the result. */

  ulong state_seq = FD_VOLATILE_CONST( adminctl->state_seq );
  FD_COMPILER_MFENCE();

  ulong state = fd_adminctl_state( state_seq );
  if( FD_UNLIKELY( state!=FD_ADMINCTL_STATE_PUBLISHED ) ) FD_LOG_ERR(( "adminctl complete without published command" ));

  adminctl->result = result;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( adminctl->state_seq ) = fd_adminctl_state_seq_update( state_seq, FD_ADMINCTL_STATE_DONE );
}

ulong
fd_adminctl_wait( fd_adminctl_t * adminctl,
                  ulong           request_id ) {
  for(;;) {
    ulong state_seq      = FD_VOLATILE_CONST( adminctl->state_seq );
    ulong cur_request_id = FD_VOLATILE_CONST( adminctl->request_id );
    FD_COMPILER_MFENCE();

    ulong state = fd_adminctl_state( state_seq );
    if( FD_UNLIKELY( state==FD_ADMINCTL_STATE_FREE ) ) return FD_ADMINCTL_RESULT_UNKNOWN;
    if( FD_UNLIKELY( cur_request_id!=request_id ) ) return FD_ADMINCTL_RESULT_UNKNOWN;
    if( FD_LIKELY( state==FD_ADMINCTL_STATE_DONE ) ) {
      ulong result = adminctl->result;
      if( FD_LIKELY( FD_ATOMIC_CAS( (ulong *)&adminctl->state_seq, state_seq, fd_adminctl_state_seq_update( state_seq, FD_ADMINCTL_STATE_FREE ) )==state_seq ) ) return result;
    }
    FD_SPIN_PAUSE();
  }
}

