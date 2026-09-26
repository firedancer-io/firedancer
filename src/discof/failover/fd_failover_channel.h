#ifndef HEADER_fd_src_discof_failover_fd_failover_channel_h
#define HEADER_fd_src_discof_failover_fd_failover_channel_h

/* Authenticated nonblocking TCP channel for the failover pair. */

#include "fd_failover_wire.h"

#include <time.h>

#define FD_FAILOVER_CHANNEL_MAGIC         (0xF17EDA2CE5FA170AUL)
#define FD_FAILOVER_CHANNEL_CANDIDATE_MAX (16UL)

/* fd_failover_clock returns monotonic nanoseconds for every channel
   deadline.  A wall clock step must not drop a healthy pair. */
static inline long
fd_failover_clock( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (long)ts.tv_sec*1000000000L + (long)ts.tv_nsec;
}

/* Timing in nanoseconds.  We send STATUS every interval and a paired
   session that hears nothing for five intervals is dropped. */
#define FD_FAILOVER_STATUS_INTERVAL_NANOS       (   800000000L)
#define FD_FAILOVER_CHANNEL_SILENCE_NANOS       (5L*FD_FAILOVER_STATUS_INTERVAL_NANOS)
#define FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS   (   800000000L)
#define FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS   ( 12800000000L)
#define FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS (  2000000000L)

struct fd_failover_channel_metrics {
  ulong connection_attempt_cnt; /* candidate sockets started, before TLS */
  ulong paired_cnt;             /* successful TLS and HELLO pairings */
  ulong frames_sent;            /* frames written */
  ulong frames_received;        /* frames decoded, including HELLO */
  ulong tls_fail_cnt;           /* failed TLS setup or handshake */
  ulong admission_drop_cnt;     /* accepted sockets closed before TLS */
  ulong evicted_cnt;            /* accepted candidates closed to make room for our dial or the expected peer */
  ulong handshake_timeout_cnt;  /* candidates expired before pairing */
  ulong wire_fatal_cnt;         /* sessions dropped by the codec */
  ulong hello_reject_cnt;       /* fatal HELLO handshake rejects */
};

typedef struct fd_failover_channel_metrics fd_failover_channel_metrics_t;

struct fd_failover_channel;
typedef struct fd_failover_channel fd_failover_channel_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_failover_channel_align( void );

FD_FN_CONST ulong
fd_failover_channel_footprint( void );

void *
fd_failover_channel_new( void * shmem );

fd_failover_channel_t *
fd_failover_channel_join( void * shch );

/* Opens the listener on address:port.  Every member listens for as
   long as the channel lives.  Call before the sandbox, which forbids
   bind.  The address is in network byte order and the port in host
   byte order, here and in init_dialer. */
void
fd_failover_channel_init_listener( fd_failover_channel_t * channel,
                                   uint                    address,
                                   ushort                  port );

/* Sets the address:port we dial while we are a standby and not paired,
   the configured peer or the active gossip shows.  Address zero means
   it is not known and nothing is dialed.  Call it again when the
   address changes, a dial toward the old address is dropped and the new
   one dialed right away.  A paired session stays up. */
void
fd_failover_channel_init_dialer( fd_failover_channel_t * channel,
                                 uint                    address,
                                 ushort                  port );

/* Tells the listener which source address the configured peer dials
   from.  A connection from it is admitted even when every candidate slot
   is held, the oldest candidate from another address is closed for it,
   and it skips the global start bucket.  Other addresses cannot keep the
   peer out by holding the table.  Zero means no reservation. */
void
fd_failover_channel_expect_peer( fd_failover_channel_t * channel,
                                 uint                    address );

/* Configures mutual TLS and HELLO before seccomp.  Only the local junk
   keypair may be passed here, never the staked or voting keypair.
   Returns zero on success, -1 on invalid keys or TLS setup failure. */
int
fd_failover_channel_set_identity( fd_failover_channel_t *     channel,
                                  uchar const *               junk_keypair,
                                  fd_failover_hello_t const * hello );

/* Puts our member certificate, the staked key's signature over the
   cert prefix and our junk pubkey, into HELLO.  We neither accept nor
   dial before we have it.  Returns zero on success, -1 if it does not
   verify against our HELLO. */
int
fd_failover_channel_set_member_cert( fd_failover_channel_t * channel,
                                     uchar const *           member_cert );

/* Closes all sockets and releases the TLS context. */
void
fd_failover_channel_fini( fd_failover_channel_t * channel );

/* Returns how many connections are still in their TCP, TLS or HELLO
   handshake, the paired session not counted. */
FD_FN_PURE ulong
fd_failover_channel_pending( fd_failover_channel_t const * channel );

/* Updates the role we put in HELLO.  A paired session stays up, the
   HELLO is only read during a handshake.  We dial only as a standby, so
   an unpaired channel stops dialing when we become active and starts
   again when we are a standby that knows the active's address. */
void
fd_failover_channel_set_role( fd_failover_channel_t * channel,
                              ulong                   role );

/* Drives the channel, now is the caller's clock in nanos.  Sets
   *charge_busy when it made progress.  Returns 1 with *out_type,
   out_payload and *out_payload_sz filled when a verified post HELLO frame
   arrived, else 0.  out_payload must hold FD_FAILOVER_PAYLOAD_MAX bytes. */
int
fd_failover_channel_poll( fd_failover_channel_t * channel,
                          long                    now,
                          int *                   charge_busy,
                          ushort *                out_type,
                          uchar *                 out_payload,
                          ulong *                 out_payload_sz );

/* Writes one authenticated frame, now is the caller's clock in nanos.
   Returns 0 on success, -1 when the channel is not paired, already has a
   pending frame, or encoding or writing fails.  Encoding and write
   failures tear down the session. */
int
fd_failover_channel_send( fd_failover_channel_t * channel,
                          long                    now,
                          ushort                  type,
                          uchar const *           payload,
                          ulong                   payload_sz );

/* Accessors. */
FD_FN_PURE ulong                                 fd_failover_channel_state     ( fd_failover_channel_t const * channel );
FD_FN_PURE int                                   fd_failover_channel_listen_fd ( fd_failover_channel_t const * channel );
FD_FN_PURE int                                   fd_failover_channel_tx_pending( fd_failover_channel_t const * channel );
FD_FN_PURE fd_failover_hello_t const *           fd_failover_channel_peer_hello( fd_failover_channel_t const * channel );
FD_FN_PURE fd_failover_channel_metrics_t const * fd_failover_channel_metrics   ( fd_failover_channel_t const * channel );

/* Reads the bound port back from the listen socket, for binds to port zero. */
ushort
fd_failover_channel_listen_port( fd_failover_channel_t const * channel );

/* Closes any live connection and returns the channel to its resting state, listening or backoff. */
void
fd_failover_channel_hangup( fd_failover_channel_t * channel,
                            long                    now );

/* Drops a paired session after an authenticated protocol violation. */
void
fd_failover_channel_protocol_error( fd_failover_channel_t * channel,
                                    long                    now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_channel_h */
