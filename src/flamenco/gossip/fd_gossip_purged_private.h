#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_purged_private_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_purged_private_h

/* Container instantiations backing fd_gossip_purged.c.  Kept out of
   fd_gossip_purged.h so its includers (fd_gossip.h, fd_crds.h, ...)
   do not compile them. */

#include "fd_gossip_purged.h"

#define POOL_NAME purged_pool
#define POOL_T    fd_crds_purged_t
#define POOL_IDX_T uint
#define POOL_NEXT pool.next
#include "../../util/tmpl/fd_pool.c"

#define TREAP_NAME      purged_treap
#define TREAP_T         fd_crds_purged_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ((q>e->treap.hash_prefix)-(q<e->treap.hash_prefix))
#define TREAP_IDX_T     uint
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_NEXT      treap.next
#define TREAP_PREV      treap.prev
#define TREAP_LT(e0,e1) ((e0)->treap.hash_prefix<(e1)->treap.hash_prefix)
#define TREAP_PARENT    treap.parent
#define TREAP_LEFT      treap.left
#define TREAP_RIGHT     treap.right
#define TREAP_PRIO      treap.prio
#include "../../util/tmpl/fd_treap.c"

#define DLIST_NAME  failed_inserts_dlist
#define DLIST_ELE_T fd_crds_purged_t
#define DLIST_IDX_T uint
#define DLIST_PREV  expire.prev
#define DLIST_NEXT  expire.next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  replaced_dlist
#define DLIST_ELE_T fd_crds_purged_t
#define DLIST_IDX_T uint
#define DLIST_PREV  expire.prev
#define DLIST_NEXT  expire.next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  no_contact_info_dlist
#define DLIST_ELE_T fd_crds_purged_t
#define DLIST_IDX_T uint
#define DLIST_PREV  expire.prev
#define DLIST_NEXT  expire.next
#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME               nci_origin_map
#define MAP_KEY                origin
#define MAP_ELE_T              fd_crds_purged_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_IDX_T              uint
#define MAP_PREV               nci_map.prev
#define MAP_NEXT               nci_map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) fd_hash32( (key)->uc, (seed) )
#define MAP_MULTI              1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_purged_private_h */
