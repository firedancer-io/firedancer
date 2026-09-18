#ifndef HEADER_fd_src_discof_failover_fd_failover_channel_h
#define HEADER_fd_src_discof_failover_fd_failover_channel_h

/* Authenticated nonblocking TCP channel for one failover pair. */

#include "fd_failover_wire.h"

#include <time.h>

#define FD_FAILOVER_CHANNEL_MAGIC (0xF17EDA2CE5FA170AUL)
#define FD_FAILOVER_CHANNEL_CANDIDATE_MAX (16UL)

/* fd_failover_clock returns monotonic nanoseconds for every channel
   deadline.  A wall clock step must not drop a healthy pair. */
static inline long
fd_failover_clock( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (long)ts.tv_sec*1000000000L + (long)ts.tv_nsec;
}

/* Default reconnect backoff and handshake deadline in nanoseconds. */
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
  ulong evicted_cnt;            /* candidates closed to admit the configured peer */
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

/* Opens the listener and selects it as the active transport. */
void
fd_failover_channel_init_listener( fd_failover_channel_t * channel,
                                   uint                    address,
                                   ushort                  port );

/* Sets the dialer endpoint for future use. */
void
fd_failover_channel_init_dialer( fd_failover_channel_t * channel,
                                 uint                    address,
                                 ushort                  port );

/* Tells a listener which source address the configured peer dials from.
   A connection from it is admitted even when every candidate slot is
   held, the oldest candidate from another address is closed for it, and
   it skips the global start bucket.  Other addresses cannot keep the
   peer out by holding the table.  Zero means no reservation. */
void
fd_failover_channel_expect_peer( fd_failover_channel_t * channel,
                                 uint                    address );

/* Configures mutual TLS and HELLO before seccomp. Only the stable local
   junk keypair may be passed here, never the staked or voting keypair.
   Returns zero on success, -1 on invalid keys or TLS setup failure. */
int
fd_failover_channel_set_identity( fd_failover_channel_t *     channel,
                                  uchar const *               junk_keypair,
                                  uchar const *               peer_junk_pubkey,
                                  fd_failover_hello_t const * hello );

/* Closes all sockets and releases the TLS context. */
void fd_failover_channel_fini( fd_failover_channel_t * channel );

FD_FN_PURE ulong fd_failover_channel_pending( fd_failover_channel_t const * channel );

void
fd_failover_channel_set_timing( fd_failover_channel_t * channel,
                                long                    hello_timeout_nanos,
                                long                    silence_nanos,
                                long                    backoff_min_nanos,
                                long                    backoff_max_nanos );

/* Resizes only the silence window, once the peer's STATUS cadence is
   known from its HELLO.  Safe while paired. */
void
fd_failover_channel_set_silence( fd_failover_channel_t * channel,
                                 long                    silence_nanos );

/* Update the role and term we put in HELLO.  The peer checks every frame
   against the HELLO it paired on, so the channel has to know when either
   changes.  The identity and config hash are set once at setup and not
   touched here.  Safe to call while paired, the HELLO is only read during
   a handshake. */
void
fd_failover_channel_set_role( fd_failover_channel_t * channel,
                              ulong                   role,
                              ulong                   term );

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
FD_FN_PURE ulong                                fd_failover_channel_state     ( fd_failover_channel_t const * channel );
FD_FN_PURE int                                  fd_failover_channel_listen_fd ( fd_failover_channel_t const * channel );
FD_FN_PURE ulong                                fd_failover_channel_ack_seq   ( fd_failover_channel_t const * channel );
FD_FN_PURE ulong                                fd_failover_channel_tx_seq    ( fd_failover_channel_t const * channel );
FD_FN_PURE int                                  fd_failover_channel_tx_pending( fd_failover_channel_t const * channel );
FD_FN_PURE fd_failover_hello_t const *          fd_failover_channel_peer_hello( fd_failover_channel_t const * channel );
FD_FN_PURE fd_failover_channel_metrics_t const * fd_failover_channel_metrics  ( fd_failover_channel_t const * channel );

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
