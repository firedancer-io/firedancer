#ifndef HEADER_fd_src_flamenco_gossip_fd_active_set_private_h
#define HEADER_fd_src_flamenco_gossip_fd_active_set_private_h

#include "../../util/bits/fd_bits.h"

static inline ulong
fd_active_set_stake_bucket( ulong _stake ) {
  ulong stake = _stake / 1000000000;
  ulong bucket = 64UL - (ulong)__builtin_clzl(stake);
  return fd_ulong_min( bucket, 24UL );
}

#endif /* HEADER_fd_src_flamenco_gossip_fd_active_set_private_h */
