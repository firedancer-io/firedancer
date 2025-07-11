#ifndef src_flamenco_gossip_fd_gossip_receiver_h
#define src_flamenco_gossip_fd_gossip_receiver_h

#include "fd_contact_info.h"
#include "fd_gossip_update_msg.h"

/* fd_gossip_receiver provides an API for maintaining and querying a
   Contact Info table based on fd_gossip_update_message_t messages
   published by Gossip. */

struct fd_gossip_receiver_private;
typedef struct fd_gossip_receiver_private fd_gossip_receiver_t;

#define FD_GOSSIP_RECEIVER_FRAG_MAX_SZ FD_GOSSIP_UPDATE_SZ_CONTACT_INFO

#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_NEW       (0)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_REMOVED   (1)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_UPDATED   (2)
#define FD_GOSSIP_RECEIVER_UPDATE_RESULT_UNKNOWN   (3)

struct fd_gossip_receiver_update {
  uchar result;
  union {
      fd_contact_info_t const * contact_info; /* if result is NEW or UPDATED */
      fd_pubkey_t               rm_pk;        /* if result is REMOVED */
  };
  ulong _unused_stake; /* unfilled at the moment */
};

typedef struct fd_gossip_receiver_update fd_gossip_receiver_update_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gossip_receiver_align( void );

FD_FN_CONST ulong
fd_gossip_receiver_footprint( void );

void *
fd_gossip_receiver_new( void * shmem );

fd_gossip_receiver_t *
fd_gossip_receiver_join( void * shreceiver );

/* fd_gossip_receiver_sig_check returns 0 if an incoming gossip_out frag is
   useful to fd_gossip_receiver by checking the frag's signature, and non-zero
   otherwise. */
static inline int
fd_gossip_receiver_sig_check( ulong sig ) {
   return !( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ||
             sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE );
}

/* fd_gossip_receiver_frag_sz_check returns 1 if the size of the incoming
   gossip update fragment is valid */
static inline int
fd_gossip_receiver_frag_sz_check( ulong sz ) {
  return ( sz==FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE ||
           sz==FD_GOSSIP_UPDATE_SZ_CONTACT_INFO );
}

/* fd_gossip_receiver_process_update_msg updates the internal
   Contact Info table based on an incoming msg and returns
   an update result. */

fd_gossip_receiver_update_t
fd_gossip_receiver_process_update_msg( fd_gossip_receiver_t *             receiver,
                                       fd_gossip_update_message_t const * msg );

ulong
fd_gossip_receiver_num_peers( fd_gossip_receiver_t const * receiver );

/* fd_gossip_receiver_iter_init provides an iterator for iterating through the
   Contact Info table in insertion order. Only insertions and removals from
   fd_gossip_receiver_process_update_msg affect this ordering, updates do
   not. This is a wrapper around fd_dlist, so the safety rules carry over. */
typedef ulong fd_gossip_receiver_iter_t;

fd_gossip_receiver_iter_t
fd_gossip_receiver_iter_init( fd_gossip_receiver_t * receiver );

int
fd_gossip_receiver_iter_done( fd_gossip_receiver_t const * receiver,
                              fd_gossip_receiver_iter_t    iter );

fd_gossip_receiver_iter_t
fd_gossip_receiver_iter_next( fd_gossip_receiver_t const * receiver,
                              fd_gossip_receiver_iter_t    iter );

fd_contact_info_t const *
fd_gossip_receiver_iter_ele_const( fd_gossip_receiver_t const * receiver,
                                   fd_gossip_receiver_iter_t    iter );

#endif
