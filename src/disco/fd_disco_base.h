#ifndef HEADER_fd_src_disco_fd_disco_base_h
#define HEADER_fd_src_disco_fd_disco_base_h

#include "../tango/fd_tango.h"

FD_PROTOTYPES_BEGIN

/* fd_disco_lazy_default returns a target interval between housekeeping
   events in ns (laziness) for a producer / consumer that has a maximum
   credits of cr_max / lag behind the producer of lag_max.

   To understand this default, note that a producer should receive / a
   consumer should transmit complete flow control credits least at often
   as the time it takes a producer to exhaust all its credits / a slow
   consumer to process a worst case backlog of lag_max credits.
   Otherwise, the communications throughput will be limited by the rate
   credits can flow from consumer to producer rather than the rate the
   producer can publish / consumer can receive.  At the same time, we
   don't want to be too eager to return credits to avoid consumer to
   producer credit communications competing for NOC resources with
   producer to consumer communications.

   This implies we need to update all flow control information on a tile
   somewhat faster than:

     cr_max max( typical time it takes a producer to consume a credit,
                 typical time it takes a consumer to produce a credit )

   Practical considerations applied to this yield a useful conservative
   lower bound:

   Assume credits are network packets (as is often the case), the above
   times are the typical time it takes a producer / consumer to generate
   / process a packet.  Given a producer line-rating minimal sized
   Ethernet frames (672 bits) at 100G into a mcache / dcache and
   consumers that are keeping up with this producer (both highly
   unrealistically harsh situations in the real world as this implies
   Ethernet payloads much much smaller than typical real world payloads
   and a consumer that can process packets in just a handful of ns), the
   above suggests housekeeping done somewhat than:

     ~(cr_max pkt)(672 bit/pkt/100 Gbit/ns)

   will be adequate for all practical purposes. Given that the typical
   randomized housekeeping event will be at most ~1.5 lazy, we have:

     lazy < ~cr_max*672/100e9/1.5 ~ 4.48 cr_max

   We use 9 (1+floor( cr_max/4 ) ~ 2.25 cr_max to keep things simple we
   also saturate cr_max at ULONG_MAX/8 to avoid overflow.  Note that
   that while this might seem aggressive per credit, since cr_max is
   typically values in thousands to hundreds of thousands, this
   corresponds to default laziness in the tens microseconds to
   millseconds.  */

FD_FN_CONST static inline long
fd_disco_lazy_default( ulong cr_max ) {
  return (long)(9UL*((fd_ulong_min( cr_max, ULONG_MAX>>3 ) >> 2) + 1UL));
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_base_h */

