#ifndef HEADER_fd_src_waltz_neigh_fd_neigh4_probe_h
#define HEADER_fd_src_waltz_neigh_fd_neigh4_probe_h

/* fd_neigh4_probe.h is a hack to indirectly trigger ARP requests in
   Linux.

   ### Background

   When sending an IP packet via the Firedancer network stack, it is
   the net tile's responsibility to pick the network interface to send
   the packet out on, as well as the destination MAC address.

   The dst MAC address is taken from a neighbor table entry given the
   "next hop" (an output of a previously done route table lookiup).
   The neighbor table is directly mirrored from the Linux kernel.

   If no matching neighbor table entry exists, the system should send
   broadcast an ARP request (e.g. "who is 192.168.12.13? tell
   192.168.12.4").  ARP replies to this request will then go to the
   kernel.  The kernel also needs to be told that it should expect an
   ARP reply to avoid drops.

   ### Possible Solutions

   1. Add a neighbor table entry, send out the ARP request via XDP:
      `ip neigh add IP_ADDR nud incomplete`
      Requires CAP_NET_ADMIN (to send RTM_NEWNEIGH)

   2. Add a neighbor table entry, make the kernel issue the ARP
      request: `ip neigh add IP_ADDR nud incomplete use`
      Requires CAP_NET_ADMIN (to send RTM_NEWNEIGH)

   3. Send a UDP datagram which indirectly makes the kernel do an ARP
      request: `echo "hello" | nc -u IP_ADDR:65535`
      Does not require privileges

   4. Send an IP packet (ICMP echo, invalid ICMP, invalid next proto...)
      which indirectly makes the kernel do an ARP request
      `ping IP_ADDR -c 1`
      Requires CAP_NET_RAW to create a SOCK_RAW socket

   Solution 2 is theoretically ideal.  Unfortunately, it requires the
   netlink API caller to be in the root user namespace, which would
   break assumptions made in fd_sandbox.

   fd_neigh4_probe implements solution 3 because it requires the least
   amount of privileges. */

#include "fd_neigh4_map.h"
#include "../fd_token_bucket.h"

/* The fd_neigh4_prober_t class provides "neighbor probing"
   functionality as described above using empty UDP/IP packets. */

/* 128 burst + 3/s * 15s needs at most 173 live records.  History is
   independent of the kernel-mirrored neighbor map: failed probes must
   not leave placeholders there merely to remember their deadline. */
#define FD_NEIGH4_PROBE_HISTORY_MAX (256UL)

struct fd_neigh4_prober {
  int sock_fd;  /* UDP socket with IP_TTL 1 */

  /* probe_delay specifies the delay in ticks for successive ARP
     requests to the same IP address (see fd_tickcount()) */
  long probe_delay;

  /* Token bucket rate limiter on any outgoing ARP probes */
  fd_token_bucket_t rate_limit;

  /* Metric counter for probes suppressed by local rate limit */
  ulong local_rate_limited_cnt;

  struct {
    uint ip4_addr;
    int  valid;
    long suppress_until;
  } history[ FD_NEIGH4_PROBE_HISTORY_MAX ];

  /* Metric counter for probes suppressed by global admission limits
     (token bucket or, defensively, bounded history capacity). */
  ulong global_rate_limited_cnt;
};

typedef struct fd_neigh4_prober fd_neigh4_prober_t;

FD_PROTOTYPES_BEGIN

/* fd_neigh4_prober_init initializes a neigh4_prober object.  Creates a
   new unbound UDP socket (socket(2)) with an IPv4 TTL of one
   (setsockopt(2)).  max_probes_per_second and max_probe_burst configure
   token bucket rate limit parameters for outgoing probe packets.
   probe_delay_seconds sets the min wait time between two probe packet
   sends for the same dst IP.  max_probe_burst plus the rounded-up
   number of probes permitted during probe_delay_seconds must be less
   than FD_NEIGH4_PROBE_HISTORY_MAX (one slot reserved for rounding). */

void
fd_neigh4_prober_init( fd_neigh4_prober_t * prober,
                       float                max_probes_per_second,
                       ulong                max_probe_burst,
                       float                probe_delay_seconds );

/* fd_neigh4_prober_fini closes the neigh4_prober socket. */

void
fd_neigh4_prober_fini( fd_neigh4_prober_t * prober );

/* fd_neigh4_probe sends out an empty UDP packet to port 65535 with the
   IP time-to-live field set to 0.  ip4_addr is an IP address on a
   neighboring subnet for which the neighbor discovery process should
   be started.  ip4_addr is big endian.  now is a recent fd_tickcount()
   value.  Returns the errno value produced by sendto(2) or 0 on success. */

int
fd_neigh4_probe( fd_neigh4_prober_t * prober,
                 fd_neigh4_entry_t *  entry,
                 uint                 ip4_addr,
                 long                 now );

/* fd_neigh4_probe_rate_limited calls fd_neigh4_probe unless that would
   violate rate limits.  Returns 0 if a probe was sent out.  Returns
   positive errno on probe failure.  Returns -1 if rate limit was hit. */

static inline int
fd_neigh4_probe_rate_limited(
    fd_neigh4_prober_t * prober,
    fd_neigh4_entry_t *  entry,
    uint                 ip4_addr,
    long                 now
) {
  /* Local rate limit */
  if( now < FD_NEIGH4_PROBE_SUPPRESS_UNTIL_GET( entry ) ) {
    prober->local_rate_limited_cnt++;
    return -1;
  }
  ulong slot = ULONG_MAX;
  for( ulong i=0UL; i<FD_NEIGH4_PROBE_HISTORY_MAX; i++ ) {
    if( !prober->history[ i ].valid || now>=prober->history[ i ].suppress_until ) {
      if( slot==ULONG_MAX ) slot=i;
    } else if( prober->history[ i ].ip4_addr==ip4_addr ) {
      prober->local_rate_limited_cnt++;
      return -1;
    }
  }

  /* Never evict unexpired history.  Valid initialization sizes this
     above the token-bucket bound; fail closed if that invariant fails. */
  if( FD_UNLIKELY( slot==ULONG_MAX ) ) {
    prober->global_rate_limited_cnt++;
    return -1;
  }

  /* Global rate limit */
  if( !fd_token_bucket_consume( &prober->rate_limit, 1.0f, now ) ) {
    prober->global_rate_limited_cnt++;
    return -1;
  }

  /* Remember admitted attempts, including send failures.  Globally
     rejected requests consume no history and cannot fill this cache. */
  prober->history[ slot ].ip4_addr       = ip4_addr;
  prober->history[ slot ].valid          = 1;
  prober->history[ slot ].suppress_until = now + prober->probe_delay;
  FD_NEIGH4_PROBE_SUPPRESS_UNTIL_SET( entry, now + prober->probe_delay );
  return fd_neigh4_probe( prober, entry, ip4_addr, now );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_neigh_fd_neigh4_probe_h */
