#ifndef HEADER_fd_src_discof_failover_fd_failover_channel_h
#define HEADER_fd_src_discof_failover_fd_failover_channel_h

/* Authenticated nonblocking TCP channel for the failover pair. */

#include "fd_failover_wire.h"
#include "../../waltz/tls/fd_tls.h"

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

/* Handshake, operation and retry limits in nanoseconds. */
#define FD_FAILOVER_CHANNEL_IDLE_NANOS          ( 64000000000L)
#define FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS   (   800000000L)
#define FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS   ( 12800000000L)
#define FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS (  2000000000L)

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

/* Starts a handoff's dial and retries at address:port.  Address zero
   stops retries and leaves a paired session up until the caller hangs
   up. */
void
fd_failover_channel_init_dialer( fd_failover_channel_t * channel,
                                 uint                    address,
                                 ushort                  port );

/* Configures mutual TLS and HELLO before seccomp, with our junk pubkey
   and the signer for CertificateVerify.  The private key stays in the
   sign tile.  Returns zero on success, -1 on invalid keys or TLS setup
   failure. */
int
fd_failover_channel_set_identity( fd_failover_channel_t *     channel,
                                  uchar const                 junk_pubkey[ 32 ],
                                  fd_tls_sign_t               signer,
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

/* Updates the role in the next HELLO.  An open handoff may finish
   its acknowledgement after the roles change. */
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
/* Changes whenever a new authenticated session replaces the previous one. */
FD_FN_PURE ulong fd_failover_channel_generation( fd_failover_channel_t const * channel );

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
