#ifndef HEADER_fd_src_waltz_quic_tests_fd_quic_sandbox_h
#define HEADER_fd_src_waltz_quic_tests_fd_quic_sandbox_h

#include "../fd_quic.h"
#include "../../../tango/mcache/fd_mcache.h"
#include "../../../tango/dcache/fd_dcache.h"
#include "../../../util/net/fd_ip4.h"

/* fd_quic_sandbox_t is used to setup and analyze a conversation with
   fd_quic.  It manages an instrumented fd_quic_t instance and records
   its outgoing packets.   The packet capture is a ring buffer
   (mcache/dcache pair) that captures the last N packets.

   fd_quic_sandbox_t is single-threaded only.  fd_quic_sandbox_t cannot
   be shared across different address spaces. The usual mcache lockless
   concurrency patterns for accessing the captured packet ring are thus
   unnecessary.  It is not safe to declare a fd_quic_sandbox_t variable,
   use the object lifecycle API instead. */

struct fd_quic_sandbox {
  /* Static members (values only changed by new/delete) */

  ulong            magic;       /* ==FD_QUIC_SANDBOX_MAGIC */
  fd_quic_t *      quic;        /* the QUIC instance to be tested */
  fd_frag_meta_t * pkt_mcache;  /* captured packet descriptor */
  void *           pkt_dcache;  /* captured packet data */
  ulong            pkt_mtu;     /* captured packet max payload sz */

  /* State */

  ulong  pkt_seq_r;   /* seq no of next packet not yet read */
  ulong  pkt_seq_w;   /* seq no of next packet to publish */
  ulong  pkt_chunk;   /* publisher chunk index */
  ulong  wallclock;   /* time as seen by fd_quic (ns) */
};

typedef struct fd_quic_sandbox fd_quic_sandbox_t;

/* FD_QUIC_SANDBOX_MAGIC is a unique random number identifying an
   fd_quic_sandbox_t object. */

#define FD_QUIC_SANDBOX_MAGIC (0xf072dd5e98bb6e91UL)  /* random */

/* FD_QUIC_SANDBOX_SELF_IP4 is the default IP address of the sandbox
   fd_quic_t. */

#define FD_QUIC_SANDBOX_SELF_IP4  FD_IP4_ADDR( 30, 0, 0, 1 )

/* FD_QUIC_SANDBOX_PEER_IP4 is the default IP address of the mock peer
   that the sandbox fd_quic_t is talking with. */

#define FD_QUIC_SANDBOX_PEER_IP4  FD_IP4_ADDR( 30, 0, 0, 2 )

/* FD_QUIC_SANDBOX_SELF_PORT is the default UDP port of the sandbox
   fd_quic_t. */

#define FD_QUIC_SANDBOX_SELF_PORT ((ushort)9000)

/* FD_QUIC_SANDBOX_PEER_PORT is the default UDP port of the mock peer
   that the sandbox fd_quic_t is talking with. */

#define FD_QUIC_SANDBOX_PEER_PORT ((ushort)9001)

/* FD_QUIC_SANDBOX_IDLE_TIMEOUT is the default fd_quic idle timeout. */

#define FD_QUIC_SANDBOX_IDLE_TIMEOUT (1000000000UL)  /* 1s */

/* Object lifecycle ***************************************************/

FD_PROTOTYPES_BEGIN

/* fd_quic_sandbox_{align,footprint} describe requirements for the
   memory region backing an fd_quic_sandbox_t.

   quic_limits are the parameters for the fd_quic_t owned by
   fd_quic_sandbox_t.  pkt_cnt are the number of packets that are
   buffered (must be a power of 2).  mtu is the max size of each packet
   (only the UDP datagram, not including Ethernet or IPv4 headers).

   fd_quic_footprint returns 0UL if any of the parameters are invalid
   and can thus be used for fast validation. */

ulong
fd_quic_sandbox_align( void );

ulong
fd_quic_sandbox_footprint( fd_quic_limits_t const * quic_limits,
                           ulong                    pkt_cnt,
                           ulong                    mtu );

/* fd_quic_sandbox_new formats the memory region 'mem' for use as an
   fd_quic_sandbox_t.  The arguments must match those given to
   fd_quic_sandbox_footprint when creating the memory region (assumes
   that parameters are valid, i.e. footprint returned non-zero).
   Returns mem on success.  On failure, returns NULL and logs reason for
   failure. */

void *
fd_quic_sandbox_new( void *                   mem,
                     fd_quic_limits_t const * quic_limits,
                     ulong                    pkt_cnt,
                     ulong                    mtu );

/* fd_quic_sandbox_join joins the caller to the fd_quic_sandbox_t
   at 'mem' and returns the handle (not necessarily the same pointer).

   NOTE: Before using any API functions, call fd_quic_sandbox_init
         first.  The fd_quic_sandbox_t is uninitialized on the first
         join! */

fd_quic_sandbox_t *
fd_quic_sandbox_join( void * mem );

/* fd_quic_sandbox_init resets the fd_quic_sandbox_t to a common state.

   sandbox points to a local join to the fd_quic_sandbox_t.
   role is one of FD_QUIC_ROLE_{CLIENT,SERVER}.

   On return,
   - the fake wallclock is 0UL
   - the embedded fd_quic_t instance is in 'initialized state' (via
     fd_quic_init), having no connections and empty object pools
   - the packet capture ring is empty
   - the idle_timeout is 1s
   - the local identity key is Ed25519 secret of b'\x41' * 32 */

fd_quic_sandbox_t *
fd_quic_sandbox_init( fd_quic_sandbox_t * sandbox,
                      int                 role );

/* fd_quic_sandbox_leave undoes a local join to the fd_quic_sandbox_t
   and returns a pointer to the first byte of the memory region (same
   as the 'mem' argument in join). */

void *
fd_quic_sandbox_leave( fd_quic_sandbox_t * sandbox );

/* fd_quic_sandbox_delete destroys an fd_quic_sandbox_t object and
   releases the memory region back to the caller. */

void *
fd_quic_sandbox_delete( void * mem );

FD_PROTOTYPES_END

/* Encryption *********************************************************/

FD_PROTOTYPES_BEGIN

/* fd_quic_sandbox_{self,peer}_ed25519_keypair is the default Ed25519
   key pair of the sandbox fd_quic_t and the mock peer respectively.

   The first 32 bytes is the scalar/private key, the last 32 bytes is
   the encoded public key. */

extern uchar const fd_quic_sandbox_self_ed25519_keypair[64];
extern uchar const fd_quic_sandbox_peer_ed25519_keypair[64];

/* fd_quic_sandbox_aes128_{key,iv} are the default AES-128-GCM secret
   key and IV of the sandbox fd_quic_t and mock peer.  They are the
   same for anywhere symmetric crypto is used, except for the QUIC
   initial layer where the protocol hardcoded keys are useds. */

extern uchar const fd_quic_sandbox_aes128_key[16];
extern uchar const fd_quic_sandbox_aes128_iv [12];

FD_PROTOTYPES_END

/* Packet Capture *****************************************************/

FD_PROTOTYPES_BEGIN

/* fd_quic_sandbox_next_packet reads the next buffered packet that
   fd_quic_t might have sent earlier.  Returns a pointer to the frag
   descriptor and advances the read index if a packet was available.
   Returns NULL if there is no new packet.  If packet loss occurs due
   to fd_quic having overrun the reader, logs a warning. Use
   fd_quic_sandbox_packet_data to get a pointer to the data. */

fd_frag_meta_t const *
fd_quic_sandbox_next_packet( fd_quic_sandbox_t * sandbox );

/* fd_quic_sandbox_packet_data returns a pointer to the first byte of
   packet data, given a fd_frag_meta_t in the sandbox pkt cap mcache. */

FD_FN_CONST static inline uchar *
fd_quic_sandbox_packet_data( fd_quic_sandbox_t *    sandbox,
                             fd_frag_meta_t const * frag ) {
  void * base = (void *)sandbox;  /* aligned by FD_CHUNK_ALIGN */
  return fd_chunk_to_laddr( base, frag->chunk );
}

FD_PROTOTYPES_END

/* Mock API ***********************************************************/

/* fd_quic_sandbox_new_conn_established injects a new established
   connection into the fd_quic_t state.  Uses the fd_rng_t to randomly
   populate identifiers such as the conn ID.  Returns the newly created
   fd_quic_conn_t on success (owned by fd_quic_t).  Returns NULL if no
   free conn slots are available or the conn ID map is full.

   Note that the returned pointer may become invalid at some point
   because the fd_quic_t might free it (e.g. connection failed due to
   protocol error).

   The new connection is configured as such:
   - The QUIC version is v1
   - Zero quota for streams
   - Zero quota for stream data
   - Zero quota for data
   - The self endpoint is FD_QUIC_SANDBOX_SELF_IP4:FD_QUIC_SANDBOX_SELF_PORT
   - The peer endpoint is FD_QUIC_SANDBOX_PEER_IP4:FD_QUIC_SANDBOX_PEER_PORT */

fd_quic_conn_t *
fd_quic_sandbox_new_conn_established( fd_quic_sandbox_t * sandbox,
                                      fd_rng_t *          rng );

/* fd_quic_sandbox_send_frame sends the given QUIC frame to the sandbox
   fd_quic instance via the given connection.  This entrypoint side
   steps decryption and jumps directly to frame handling.  Some frame
   handlers require packet metadata.
   The memory region at [frame,frame+frame_sz) contains the wire
   encoding of the frame. */

void
fd_quic_sandbox_send_frame( fd_quic_sandbox_t * sandbox,
                            fd_quic_conn_t *    conn,
                            fd_quic_pkt_t *     pkt_meta,
                            uchar const *       frame,
                            ulong               frame_sz );

/* fd_quic_sandbox_send_lone_frame wraps fd_quic_sandbox_send_frame but
   with realistic packet meta.  It simulates a frame sent in a single
   QUIC packet and advances the packet number accordingly. */

void
fd_quic_sandbox_send_lone_frame( fd_quic_sandbox_t * sandbox,
                                 fd_quic_conn_t *    conn,
                                 uchar const *       frame,
                                 ulong               frame_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_tests_fd_quic_sandbox_h */
