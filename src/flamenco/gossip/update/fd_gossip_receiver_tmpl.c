#include "../crds/fd_crds.h"
#include "fd_gossip_update_msg.h"

#ifndef GOSSIP_RECEIVER_NAME
#error "GOSSIP_RECEIVER_NAME must be defined"
#endif

/* FD_GOSSIP_RECEIVER_SHOULD_INSERT defines a custom insertion filter for an
   incoming fd_contact_info_t * ci. Inserts all new entries by default. */
#ifndef GOSSIP_RECEIVER_SHOULD_INSERT
#define GOSSIP_RECEIVER_SHOULD_INSERT(ci) 1
#endif

/* GOSSIP_RECEIVER_SHOULD_OVERRIDE defines a custom override check to
   determine if an incoming fd_contact_info_t * new should override
   an existing fd_contact_info_t * old. Default overrides all old entries
   since a gossip update message is only published if it upserts the Gossip
   CRDS table. */
#ifndef GOSSIP_RECEIVER_SHOULD_OVERRIDE
#define GOSSIP_RECEIVER_SHOULD_OVERRIDE(new,old) 1
#endif

#define FD_GOSSIP_RECEIVER_FRAG_MAX_SZ FD_GOSSIP_UPDATE_SZ_CONTACT_INFO

#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_NEW       (0)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_REMOVED   (1)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_UPDATED   (2)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_NOOP      (3)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_UNKNOWN   (4)

#define GOSSIP_RX(name) FD_EXPAND_THEN_CONCAT3(GOSSIP_RECEIVER_NAME,_,name)

struct GOSSIP_RX(update) {
  uchar result;
  union {
      fd_contact_info_t const * contact_info;
      fd_pubkey_t               rm_pk;
  };
  ulong _unused_stake;
};

typedef struct GOSSIP_RX(update) GOSSIP_RX(update_t);

struct GOSSIP_RX(entry) {
  fd_contact_info_t ci[1];
  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } lookup;
  struct {
    ulong prev;
    ulong next;
  } insert_dlist;

};

typedef struct GOSSIP_RX(entry) GOSSIP_RX(entry_t);

#define POOL_NAME          GOSSIP_RX(pool)
#define POOL_T             GOSSIP_RX(entry_t)
#define POOL_NEXT          pool.next

#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME           GOSSIP_RX(map)
#define MAP_ELE_T          GOSSIP_RX(entry_t)
#define MAP_KEY_T          fd_pubkey_t
#define MAP_KEY            ci->pubkey
#define MAP_IDX_T          ulong
#define MAP_NEXT           lookup.next
#define MAP_PREV           lookup.prev
#define MAP_KEY_HASH(k,s)  ((k)->ul[3]^s)
#define MAP_KEY_EQ(k0,k1)  (!(memcmp((k0)->ul,(k1)->ul,sizeof(fd_pubkey_t))))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1

#include "../../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  GOSSIP_RX(insert_dlist)
#define DLIST_ELE_T GOSSIP_RX(entry_t)
#define DLIST_PREV  insert_dlist.prev
#define DLIST_NEXT  insert_dlist.next

#include "../../../util/tmpl/fd_dlist.c"

struct GOSSIP_RX(private) {
  GOSSIP_RX(entry_t) *        pool;
  GOSSIP_RX(map_t) *          entries;
  GOSSIP_RX(insert_dlist_t) * insert_dlist;
};

typedef struct GOSSIP_RX(private) GOSSIP_RX(t);

typedef ulong GOSSIP_RX(iter_t);

static inline GOSSIP_RX(update_t)
GOSSIP_RX(handle_contact_info_update)( GOSSIP_RX(t) *                    receiver,
                            fd_gossip_update_message_t const * msg ) {
  GOSSIP_RX(update_t)  update;
  GOSSIP_RX(entry_t) * entry = GOSSIP_RX(map_ele_query)( receiver->entries, &msg->contact_info.pubkey, NULL, receiver->pool );
  if( FD_UNLIKELY( !entry ) ) {
    if ( !GOSSIP_RECEIVER_SHOULD_INSERT(&msg->contact_info) ) {
      update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_NOOP;
      return update;
    }
    entry = GOSSIP_RX(pool_ele_acquire)( receiver->pool );
    if( FD_UNLIKELY( !entry ) ) {
      /* Should not happen assuming Gossip's contact info view is valid */
      FD_LOG_ERR(( "Failed to insert new entry for pubkey %s", FD_BASE58_ENC_32_ALLOCA( msg->contact_info.pubkey.uc ) ));
    }
    fd_memcpy( entry->ci, &msg->contact_info, sizeof(fd_contact_info_t) );

    GOSSIP_RX(insert_dlist_ele_push_tail)( receiver->insert_dlist, entry, receiver->pool );
    GOSSIP_RX(map_ele_insert)( receiver->entries, entry, receiver->pool );
    update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_NEW;
  } else {
    if ( !GOSSIP_RECEIVER_SHOULD_OVERRIDE(&msg->contact_info, entry->ci) ) {
      update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_NOOP;
      return update;
    }
    fd_memcpy( entry->ci, &msg->contact_info, sizeof(fd_contact_info_t) );
    update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_UPDATED;
  }
  update.contact_info = entry->ci;
  return update;
}

static inline GOSSIP_RX(update_t)
GOSSIP_RX(handle_contact_info_remove)( GOSSIP_RX(t)  *                   receiver,
                            fd_gossip_update_message_t const * msg ) {
  GOSSIP_RX(update_t) update;
  GOSSIP_RX(entry_t) * entry = GOSSIP_RX(map_ele_remove)( receiver->entries, &msg->contact_info.pubkey, NULL, receiver->pool );
  if( FD_UNLIKELY( !entry ) ) {
    /* Should not happen assuming Gossip's contact info view is valid */
    FD_LOG_ERR(( "Failed to remove entry for pubkey %s", FD_BASE58_ENC_32_ALLOCA( msg->contact_info.pubkey.uc ) ));
  }
  GOSSIP_RX(insert_dlist_ele_remove)( receiver->insert_dlist, entry, receiver->pool );
  GOSSIP_RX(pool_ele_release)( receiver->pool, entry );

  update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_REMOVED;
  fd_memcpy( &update.rm_pk, &msg->contact_info.pubkey, sizeof(fd_pubkey_t) );
  return update;
}

FD_FN_CONST static inline ulong
GOSSIP_RX(align)( void ) {
  return GOSSIP_RX(map_align)();
}

FD_FN_CONST static inline ulong
GOSSIP_RX(footprint)( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, GOSSIP_RX(align)(), sizeof(GOSSIP_RX(t)) );
  l = FD_LAYOUT_APPEND( l, GOSSIP_RX(pool_align)(), GOSSIP_RX(pool_footprint)( CRDS_MAX_CONTACT_INFO ) );
  l = FD_LAYOUT_APPEND( l, GOSSIP_RX(map_align)(), GOSSIP_RX(map_footprint)( GOSSIP_RX(map_chain_cnt_est)( CRDS_MAX_CONTACT_INFO ) ) );
  l = FD_LAYOUT_APPEND( l, GOSSIP_RX(insert_dlist_align)(), GOSSIP_RX(insert_dlist_footprint)() );
  return FD_LAYOUT_FINI( l, GOSSIP_RX(align)() );
}

static inline void *
GOSSIP_RX(new)( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, GOSSIP_RX(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  GOSSIP_RX(t) * receiver = FD_SCRATCH_ALLOC_APPEND( l, GOSSIP_RX(align)(), sizeof(GOSSIP_RX(t)) );
  void * _pool             = FD_SCRATCH_ALLOC_APPEND( l, GOSSIP_RX(pool_align)(), GOSSIP_RX(pool_footprint)( CRDS_MAX_CONTACT_INFO ) );
  void * _map              = FD_SCRATCH_ALLOC_APPEND( l, GOSSIP_RX(map_align)(), GOSSIP_RX(map_footprint)( GOSSIP_RX(map_chain_cnt_est)( CRDS_MAX_CONTACT_INFO ) ) );
  void * _dlist            = FD_SCRATCH_ALLOC_APPEND( l, GOSSIP_RX(insert_dlist_align)(), GOSSIP_RX(insert_dlist_footprint)() );
  FD_SCRATCH_ALLOC_FINI( l, GOSSIP_RX(align)() );

  receiver->pool = GOSSIP_RX(pool_join)( GOSSIP_RX(pool_new)( _pool, CRDS_MAX_CONTACT_INFO ) );
  FD_TEST( receiver->pool );

  receiver->entries = GOSSIP_RX(map_join)( GOSSIP_RX(map_new)( _map, GOSSIP_RX(map_chain_cnt_est)( CRDS_MAX_CONTACT_INFO ), 0UL /* seed */ ) );
  FD_TEST( receiver->entries );

  receiver->insert_dlist = GOSSIP_RX(insert_dlist_join)( GOSSIP_RX(insert_dlist_new)( _dlist ) );
  FD_TEST( receiver->insert_dlist );

  return receiver;
}

static inline GOSSIP_RX(t) *
GOSSIP_RX(join)( void * shreceiver ) {
  if( FD_UNLIKELY( !shreceiver ) ) {
    FD_LOG_WARNING(( "NULL shreceiver" ));
    return NULL;
  }

  return (GOSSIP_RX(t) *) shreceiver;
}

/* fd_gossip_receiver_sig_check returns 0 if an incoming gossip_out frag is
   useful to fd_gossip_receiver by checking the frag's signature, and non-zero
   otherwise. */
static inline int
GOSSIP_RX(sig_check)( ulong sig ) {
   return !( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ||
             sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE );
}

/* fd_gossip_receiver_frag_sz_check returns 1 if the size of the incoming
   gossip update fragment is valid */
static inline int
GOSSIP_RX(frag_sz_check)( ulong sz ) {
  return ( sz==FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE ||
           sz==FD_GOSSIP_UPDATE_SZ_CONTACT_INFO );
}



GOSSIP_RX(update_t)
GOSSIP_RX(process_update_msg)( GOSSIP_RX(t) *                     receiver,
                                       fd_gossip_update_message_t const * msg ) {
  switch( msg->tag ) {
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO:
      return GOSSIP_RX(handle_contact_info_update)( receiver, msg );
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE:
      return GOSSIP_RX(handle_contact_info_remove)( receiver, msg );
    default:
      return (GOSSIP_RX(update_t)){
        .result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_UNKNOWN
      };
      break;
  }
}

ulong
GOSSIP_RX(num_peers)( GOSSIP_RX(t) const * receiver ) {
  return GOSSIP_RX(pool_used)( receiver->pool );
}

GOSSIP_RX(iter_t)
GOSSIP_RX(iter_init)( GOSSIP_RX(t) * receiver ) {
  return GOSSIP_RX(insert_dlist_iter_fwd_init)( receiver->insert_dlist, receiver->pool );
}

int
GOSSIP_RX(iter_done)( GOSSIP_RX(t) const * receiver,
                      GOSSIP_RX(iter_t)    iter ) {
  return GOSSIP_RX(insert_dlist_iter_done)( iter, receiver->insert_dlist, receiver->pool );
}

GOSSIP_RX(iter_t)
GOSSIP_RX(iter_next)( GOSSIP_RX(t) const * receiver,
                      GOSSIP_RX(iter_t)    iter ) {
  return GOSSIP_RX(insert_dlist_iter_fwd_next)( iter, receiver->insert_dlist, receiver->pool );
}

fd_contact_info_t const *
GOSSIP_RX(iter_ele_const)( GOSSIP_RX(t) const * receiver,
                           GOSSIP_RX(iter_t)    iter ) {
  GOSSIP_RX(entry_t) const * entry = GOSSIP_RX(insert_dlist_iter_ele_const)( iter, receiver->insert_dlist, receiver->pool );
  if( FD_UNLIKELY( !entry ) ) {
    FD_LOG_ERR(( "Invalid iterator state" ));
  }
  return entry->ci;
}

#undef FD_GOSSIP_RECEIVER_SHOULD_INSERT
#undef FD_GOSSIP_RECEIVER_SHOULD_OVERRIDE
