/* Gossip verify tile sits before the gossip (dedup?) tile to verify incoming
   gossip packets */
#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "../../../../disco/fd_disco.h"
#include "../../../../flamenco/gossip/fd_gossip.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/store/util.h"
#include "../../../../flamenco/runtime/fd_system_ids.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../util/net/fd_net_headers.h"