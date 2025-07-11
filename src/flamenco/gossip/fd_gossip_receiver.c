#include "fd_gossip_receiver.h"
#include "crds/fd_crds.h"
#include "fd_gossip_update_msg.h"
#include <time.h>

struct fd_gossip_receiver_entry {
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

typedef struct fd_gossip_receiver_entry fd_gossip_receiver_entry_t;

#define POOL_NAME          receiver_pool
#define POOL_T             fd_gossip_receiver_entry_t
#define POOL_NEXT          pool.next

#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME           receiver_map
#define MAP_ELE_T          fd_gossip_receiver_entry_t
#define MAP_KEY_T          fd_pubkey_t
#define MAP_KEY            ci->pubkey
#define MAP_IDX_T          ulong
#define MAP_NEXT           lookup.next
#define MAP_PREV           lookup.prev
#define MAP_KEY_HASH(k,s)  ((k)->ul[3]^s)
#define MAP_KEY_EQ(k0,k1)  (!(memcmp((k0)->ul,(k1)->ul,sizeof(fd_pubkey_t))))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1

#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  insert_dlist
#define DLIST_ELE_T fd_gossip_receiver_entry_t
#define DLIST_PREV  insert_dlist.prev
#define DLIST_NEXT  insert_dlist.next

#include "../../util/tmpl/fd_dlist.c"

struct fd_gossip_receiver_private {
  fd_gossip_receiver_entry_t * pool;
  receiver_map_t *             entries;
  insert_dlist_t *             insert_dlist;
};

FD_FN_CONST ulong
fd_gossip_receiver_align( void ) {
  return receiver_map_align();
}

FD_FN_CONST ulong
fd_gossip_receiver_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_gossip_receiver_align(), sizeof(fd_gossip_receiver_t) );
  l = FD_LAYOUT_APPEND( l, receiver_pool_align(), receiver_pool_footprint( CRDS_MAX_CONTACT_INFO ) );
  l = FD_LAYOUT_APPEND( l, receiver_map_align(), receiver_map_footprint( receiver_map_chain_cnt_est( CRDS_MAX_CONTACT_INFO ) ) );
  l = FD_LAYOUT_APPEND( l, insert_dlist_align(), insert_dlist_footprint() );
  return FD_LAYOUT_FINI( l, fd_gossip_receiver_align() );
}

void *
fd_gossip_receiver_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_receiver_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_receiver_t * receiver = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_receiver_align(), sizeof(fd_gossip_receiver_t) );
  void * _pool                    = FD_SCRATCH_ALLOC_APPEND( l, receiver_pool_align(), receiver_pool_footprint( CRDS_MAX_CONTACT_INFO ) );
  void * _map                     = FD_SCRATCH_ALLOC_APPEND( l, receiver_map_align(), receiver_map_footprint( receiver_map_chain_cnt_est( CRDS_MAX_CONTACT_INFO ) ) );
  void * _dlist                   = FD_SCRATCH_ALLOC_APPEND( l, insert_dlist_align(), insert_dlist_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, fd_gossip_receiver_align() );

  receiver->pool = receiver_pool_join( receiver_pool_new( _pool, CRDS_MAX_CONTACT_INFO ) );
  FD_TEST( receiver->pool );

  receiver->entries = receiver_map_join( receiver_map_new( _map, receiver_map_chain_cnt_est( CRDS_MAX_CONTACT_INFO ), 0UL /* seed */ ) );
  FD_TEST( receiver->entries );

  receiver->insert_dlist = insert_dlist_join( insert_dlist_new( _dlist ) );
  FD_TEST( receiver->insert_dlist );

  return receiver;
}

fd_gossip_receiver_t *
fd_gossip_receiver_join( void * shreceiver ) {
  if( FD_UNLIKELY( !shreceiver ) ) {
    FD_LOG_WARNING(( "NULL shreceiver" ));
    return NULL;
  }

  return (fd_gossip_receiver_t *) shreceiver;
}

static inline fd_gossip_receiver_update_t
handle_contact_info_update( fd_gossip_receiver_t *             receiver,
                            fd_gossip_update_message_t const * msg ) {
  fd_gossip_receiver_update_t update;
  fd_gossip_receiver_entry_t * entry = receiver_map_ele_query( receiver->entries, &msg->contact_info.pubkey, NULL, receiver->pool );
  if( FD_UNLIKELY( !entry ) ) {
    entry = receiver_pool_ele_acquire( receiver->pool );
    if( FD_UNLIKELY( !entry ) ) {
      /* Should not happen assuming Gossip's contact info view is valid */
      FD_LOG_ERR(( "Failed to insert new entry for pubkey %s", FD_BASE58_ENC_32_ALLOCA( msg->contact_info.pubkey.uc ) ));
    }
    fd_memcpy( entry->ci, &msg->contact_info, sizeof(fd_contact_info_t) );

    insert_dlist_ele_push_tail( receiver->insert_dlist, entry, receiver->pool );
    receiver_map_ele_insert( receiver->entries, entry, receiver->pool );
    update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_NEW;
  } else {
    fd_memcpy( entry->ci, &msg->contact_info, sizeof(fd_contact_info_t) );
    update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_UPDATED;
  }
  update.contact_info = entry->ci;
  return update;
}

static inline fd_gossip_receiver_update_t
handle_contact_info_remove( fd_gossip_receiver_t *             receiver,
                            fd_gossip_update_message_t const * msg ) {
  fd_gossip_receiver_update_t update;
  fd_gossip_receiver_entry_t * entry = receiver_map_ele_remove( receiver->entries, &msg->contact_info.pubkey, NULL, receiver->pool );
  if( FD_UNLIKELY( !entry ) ) {
    /* Should not happen assuming Gossip's contact info view is valid */
    FD_LOG_ERR(( "Failed to remove entry for pubkey %s", FD_BASE58_ENC_32_ALLOCA( msg->contact_info.pubkey.uc ) ));
  }
  insert_dlist_ele_remove( receiver->insert_dlist, entry, receiver->pool );
  receiver_pool_ele_release( receiver->pool, entry );

  update.result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_REMOVED;
  fd_memcpy( &update.rm_pk, &msg->contact_info.pubkey, sizeof(fd_pubkey_t) );
  return update;
}

fd_gossip_receiver_update_t
fd_gossip_receiver_process_update_msg( fd_gossip_receiver_t *             receiver,
                                       fd_gossip_update_message_t const * msg ) {
  switch( msg->tag ) {
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO:
      return handle_contact_info_update( receiver, msg );
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE:
      return handle_contact_info_remove( receiver, msg );
    default:
      return (fd_gossip_receiver_update_t){
        .result = FD_GOSSIP_RECEIVER_UPDATE_RESULT_UNKNOWN
      };
      break;
  }
}

ulong
fd_gossip_receiver_num_peers( fd_gossip_receiver_t const * receiver ) {
  return receiver_pool_used( receiver->pool );
}

fd_gossip_receiver_iter_t
fd_gossip_receiver_iter_init( fd_gossip_receiver_t * receiver ) {
  return insert_dlist_iter_fwd_init( receiver->insert_dlist, receiver->pool );
}

int
fd_gossip_receiver_iter_done( fd_gossip_receiver_t const * receiver,
                              fd_gossip_receiver_iter_t    iter ) {
  return insert_dlist_iter_done( iter, receiver->insert_dlist, receiver->pool );
}

fd_gossip_receiver_iter_t
fd_gossip_receiver_iter_next( fd_gossip_receiver_t const * receiver,
                              fd_gossip_receiver_iter_t    iter ) {
  return insert_dlist_iter_fwd_next( iter, receiver->insert_dlist, receiver->pool );
}

fd_contact_info_t const *
fd_gossip_receiver_iter_ele_const( fd_gossip_receiver_t const * receiver,
                                   fd_gossip_receiver_iter_t    iter ) {
  fd_gossip_receiver_entry_t const * entry = insert_dlist_iter_ele_const( iter, receiver->insert_dlist, receiver->pool );
  if( FD_UNLIKELY( !entry ) ) {
    FD_LOG_ERR(( "Invalid iterator state" ));
  }
  return entry->ci;
}

