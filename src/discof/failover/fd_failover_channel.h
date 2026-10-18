#ifndef HEADER_fd_src_discof_failover_fd_failover_channel_h
#define HEADER_fd_src_discof_failover_fd_failover_channel_h

/* Authenticated nonblocking TCP channel for the failover pair. */

#include "fd_failover_wire.h"
#include "../../waltz/tls/fd_tls.h"

#include <time.h>

#define FD_FAILOVER_CHANNEL_MAGIC         (0xF17EDA2CE5FA170AUL)
#define FD_FAILOVER_CHANNEL_CANDIDATE_MAX (64UL)

#define FD_FAILOVER_NANOS_PER_SECOND   (1000000000UL)
#define FD_FAILOVER_LOG_INTERVAL_NANOS (60L*(long)FD_FAILOVER_NANOS_PER_SECOND)

#define FD_FAILOVER_ACCEPT_RATE           (8192UL)
#define FD_FAILOVER_ACCEPT_BURST          (128UL)
#define FD_FAILOVER_ADMIT_RATE            (128UL)
#define FD_FAILOVER_ADMIT_BURST           (16UL)
#define FD_FAILOVER_VERIFY_RATE           (128UL)
#define FD_FAILOVER_VERIFY_BURST          (16UL)
#define FD_FAILOVER_ACCEPT_PER_POLL       (16UL)
#define FD_FAILOVER_LISTEN_BACKLOG        (256)
#define FD_FAILOVER_RECONNECT_RATE        (4UL)
#define FD_FAILOVER_RECONNECT_BURST       (2UL)
#define FD_FAILOVER_PRIORITY_VERIFY_RATE  (16UL)
#define FD_FAILOVER_PRIORITY_VERIFY_BURST (4UL)
#define FD_FAILOVER_ADMISSION_START_NANOS ((long)FD_FAILOVER_NANOS_PER_SECOND)
#define FD_FAILOVER_ADMISSION_PROOF_NANOS (2L*(long)FD_FAILOVER_NANOS_PER_SECOND)

struct fd_failover_proof_signer {
  void * ctx;
  void (* sign_fn)( void * ctx, uchar sig[ 64 ], uchar const msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ] );
};
typedef struct fd_failover_proof_signer fd_failover_proof_signer_t;

/* fd_failover_clock returns monotonic nanoseconds for every channel
   deadline. */
static inline long
fd_failover_clock( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (long)ts.tv_sec*(long)FD_FAILOVER_NANOS_PER_SECOND + (long)ts.tv_nsec;
}

/* Handshake, operation and retry limits in nanoseconds. */
#define FD_FAILOVER_CHANNEL_IDLE_NANOS          ( 64000000000L)
#define FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS   (   800000000L)
#define FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS   ( 12800000000L)
#define FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS (  4000000000L)
#define FD_FAILOVER_CHANNEL_KEEPALIVE_NANOS     (FD_FAILOVER_CHANNEL_IDLE_NANOS/4L)

struct fd_failover_channel_metrics {
  ulong accept_cnt;
  ulong accept_limited_cnt;
  ulong source_reject_cnt;
  ulong budget_reject_cnt;
  ulong capacity_reject_cnt;
  ulong reconnect_cnt;
  ulong handshake_timeout_cnt;
  ulong proof_reject_cnt;
  ulong hello_reject_cnt;
  ulong tls_fail_cnt;
  ulong wire_fatal_cnt;
  ulong paired_cnt;
  ulong handshake_duration_nanos;
  ulong handshake_latest_nanos;
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

/* Opens the listener on address:port. */
void
fd_failover_channel_init_listener( fd_failover_channel_t * channel,
                                   uint                    address,
                                   ushort                  port );

/* Starts dialing and retrying at address:port.  A changed nonzero
   destination replaces an established session.  Zero stops dialing. */
void
fd_failover_channel_init_dialer( fd_failover_channel_t * channel,
                                 uint                    address,
                                 ushort                  port );

/* Configures admission and mutual TLS with separate proof and TLS
   signers.  Identity private keys stay in the sign tile. */
int
fd_failover_channel_set_identity( fd_failover_channel_t *     channel,
                                  uchar const                 junk_pubkey[ 32 ],
                                  fd_tls_sign_t               signer,
                                  fd_failover_proof_signer_t   proof_signer,
                                  fd_failover_hello_t const *  hello );

/* Closes all sockets and releases the TLS context. */
void
fd_failover_channel_fini( fd_failover_channel_t * channel );

/* Returns how many connections are still in their TCP, TLS or HELLO
   handshake.  The paired session does not count. */
FD_FN_PURE ulong
fd_failover_channel_pending( fd_failover_channel_t const * channel );

/* Updates the role in the next HELLO and leaves a paired session up, so
   an open handoff can finish after the roles change. */
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
FD_FN_PURE ulong                       fd_failover_channel_state     ( fd_failover_channel_t const * channel );
FD_FN_PURE int                         fd_failover_channel_listen_fd ( fd_failover_channel_t const * channel );
FD_FN_PURE int                         fd_failover_channel_tx_pending( fd_failover_channel_t const * channel );
FD_FN_PURE fd_failover_hello_t const * fd_failover_channel_peer_hello( fd_failover_channel_t const * channel );

FD_FN_PURE fd_failover_channel_metrics_t const *
fd_failover_channel_metrics( fd_failover_channel_t const * channel );

/* Changes whenever a new authenticated session replaces the previous one. */
FD_FN_PURE ulong fd_failover_channel_generation( fd_failover_channel_t const * channel );

/* Reads the bound port back from the listen socket, for binds to port zero. */
ushort
fd_failover_channel_listen_port( fd_failover_channel_t const * channel );

/* Closes any live connection and returns the channel to its resting state. */
void
fd_failover_channel_hangup( fd_failover_channel_t * channel,
                            long                    now );

/* Drops a paired session after an authenticated protocol violation. */
void
fd_failover_channel_protocol_error( fd_failover_channel_t * channel,
                                    long                    now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_failover_fd_failover_channel_h */
