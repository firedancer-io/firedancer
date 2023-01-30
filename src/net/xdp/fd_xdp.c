#include "fd_xdp.h"

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "fd_xdp_private.h"

#include "../../util/fd_util.h"

/* TODO move this into more appropriate header file
   and set based on architecture, etc. */
#define FD_ACQUIRE() __asm__ __volatile__( "" : : : "memory" )
#define FD_RELEASE() __asm__ __volatile__( "" : : : "memory" )

/* create a new xdp endpoint

   Args
     intf           the name of the interface to attach to
     config         the xdp configuration */

fd_xdp_t *
fd_xdp_new( char const * intf, fd_xdp_config_t const * config ) {
  /* some basic validation */
#if 0
  if( config->bpf_pgm_file == NULL ) {
    FD_LOG_WARNING(( "fd_xdp_new: Must specify bpf program file name (bpf_pgm_file)" ));
    return NULL;
  }
#endif

  /* local copy of fd_xdp */
  fd_xdp_t self = {0};

  /* set file descriptors to -1 to avoid closing fd 0 on error */
  self.xdp_sock = -1;

  /* keep copy of config */
  memcpy( &self.config, config, sizeof(*config) );

  /* find interface */
  self.ifindex = if_nametoindex( intf );
  if( self.ifindex == 0 ) {
    FD_LOG_WARNING(( "Unable to find interface %s: %d %s", intf, errno, strerror( errno ) ));
    return NULL;
  }

  /* create xdp socket */
  self.xdp_sock = socket( AF_XDP, SOCK_RAW, 0 );
  if( self.xdp_sock < 0 ) {
    FD_LOG_WARNING(( "Error occurred creating socket for interface %s. Error: %d %s",
        intf, errno, strerror( errno ) ));
    return NULL;
  }

  /* assume we need at least one entry in each ring */
  /* TODO verify this requirement */
  if( self.config.completion_ring_size == 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: completion_ring_size is zero" ));
    goto fd_xdp_new_err;
  }

  if( self.config.fill_ring_size == 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: fill_ring_size is zero" ));
    goto fd_xdp_new_err;
  }

  if( self.config.rx_ring_size == 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: rx_ring_size is zero" ));
    goto fd_xdp_new_err;
  }

  if( self.config.tx_ring_size == 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: tx_ring_size is zero" ));
    goto fd_xdp_new_err;
  }

  /* default for number of frames */
  if( self.config.frame_count == 0 ) {
    /* default as specified in header */
    self.config.frame_count = self.config.completion_ring_size +
        self.config.fill_ring_size + self.config.rx_ring_size + self.config.tx_ring_size;
  }

  /* default for frame memory size */
  if( self.config.frame_memory_size == 0 ) {
    /* if frame_memory_size not specified, frame_memory MUST be NULL */
    if( self.config.frame_memory != NULL ) {
      FD_LOG_WARNING(( "fd_xdp_new: whenever frame_memory_size == 0, "
            "frame_memory MUST be a valid pointer to appropriate memory" ));
      goto fd_xdp_new_err;
    }
    self.config.frame_memory_size = self.config.frame_size * self.config.frame_count;
  }

  /* check memory region has enough space */
  if( self.config.frame_count * self.config.frame_size > self.config.frame_memory_size ) {
    FD_LOG_WARNING(( "Not enough memory for frames. frame_count=%lu "
          "frame_size=%lu frame_memory_size=%lu", self.config.frame_count,
          self.config.frame_size, self.config.frame_memory_size ));
    goto fd_xdp_new_err;
  }

  self.umem.headroom   = 0; // TODO make configurable
  self.umem.chunk_size = (uint32_t)self.config.frame_size;
  self.umem.len        = self.config.frame_memory_size;
  self.umem.addr       = 0; // set later

  if( self.config.frame_memory == NULL ) {
    /* allocate aligned memory */
    posix_memalign( &self.owned_mem, (size_t)sysconf( _SC_PAGESIZE ), self.umem.len );
    if( !self.owned_mem ) {
      FD_LOG_WARNING(( "fd_xdp_new: Unable to allocate frame memory. Error: %d %s",
            errno, strerror( errno ) ));
      goto fd_xdp_new_err;
    }

    self.config.frame_memory = self.owned_mem;
  }

  self.umem.addr = (size_t)self.config.frame_memory;

  /* register memory with XDP socket */
  if( setsockopt( self.xdp_sock, SOL_XDP, XDP_UMEM_REG, &self.umem, sizeof(self.umem) ) < 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: Unable to set XDP_UMEM_REG. Error: %d %s", errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  /* set ring sizes */

  if( setsockopt( self.xdp_sock, SOL_XDP, XDP_UMEM_FILL_RING, &self.config.fill_ring_size, sizeof(self.config.fill_ring_size) ) < 0 ) {
    FD_LOG_WARNING(( "Unable to set umem fill ring size. Error: %d %s",
        errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  if( setsockopt( self.xdp_sock, SOL_XDP, XDP_UMEM_COMPLETION_RING, &self.config.completion_ring_size, sizeof(self.config.completion_ring_size) ) < 0 ) {
    FD_LOG_WARNING(( "Unable to set umem completion ring size. Error: %d %s",
        errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  if( setsockopt( self.xdp_sock, SOL_XDP, XDP_RX_RING, &self.config.rx_ring_size, sizeof(self.config.rx_ring_size) ) < 0 ) {
    FD_LOG_WARNING(( "Unable to set umem rx ring size. Error: %d %s",
        errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  if( setsockopt( self.xdp_sock, SOL_XDP, XDP_TX_RING, &self.config.tx_ring_size, sizeof(self.config.tx_ring_size) ) < 0 ) {
    FD_LOG_WARNING(( "Unable to set umem tx ring size. Error: %d %s",
        errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  socklen_t opt_length = sizeof(self.offsets);
  if( getsockopt( self.xdp_sock, SOL_XDP, XDP_MMAP_OFFSETS, &self.offsets, &opt_length ) < 0) {
    FD_LOG_WARNING(( "Unable to retrieve ring offsets. Error: %d %s", errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  /* action to take upon error in mmap */
#define _ { \
    FD_LOG_WARNING(( "fd_xdp_new: Error occurred in mmap. Error: %d %s", errno, strerror( errno ) )); \
    goto fd_xdp_new_err; \
  }

  /* instantiate mmaps for each ring */
  FD_RING_ITER_TYPES(FD_RING_MMAP,self,_,)

#undef _

  struct sockaddr_xdp sa = {
    .sxdp_family = PF_XDP,
    .sxdp_ifindex = self.ifindex,
    .sxdp_queue_id = 0
  };

  /* bind the socket to the specified interface */
  if( bind( self.xdp_sock, (void*)&sa, sizeof(sa) ) < 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: Unable to bind to interface %s. Error: %d %s\n", intf,
        errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  //if( self.config.bpf_pin_name == NULL ) {
  //  /* TODO relax this condition? */
  //  FD_LOG_ERR(( "fd_xdp_new: Must specify bpf_pin_name" ));
  //  goto fd_xdp_new_err;
  //}

  if( self.config.bpf_pin_dir == NULL ) {
    /* TODO relax this condition? */
    FD_LOG_ERR(( "fd_xdp_new: Must specify bpf_pin_dir" ));
    goto fd_xdp_new_err;
  }

  char buf[512];
  int rc = snprintf( buf, sizeof(buf), "%s/%s/maps/xsks_map", config->bpf_pin_dir, intf );

  if( rc < 0 || (size_t)rc > sizeof( buf ) ) {
    FD_LOG_ERR(( "fd_xdp_new: bpf xsks map file name overflow\n" ));
    goto fd_xdp_new_err;
  }
  //char const * bpf_pin_map = "/sys/fs/bpf/firedancer/firedancer_xsks_map";
  char const * bpf_pin_map = buf;
  self.xdp_map_fd = bpf_obj_get( bpf_pin_map );
  if( self.xdp_map_fd < 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: bpf_obj_get failed on file %s. Error: %d %s\n",
          bpf_pin_map, errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  rc = snprintf( buf, sizeof(buf), "%s/%s/maps/udp_map", config->bpf_pin_dir, intf );
  if( rc < 0 || (size_t)rc > sizeof( buf ) ) {
    FD_LOG_ERR(( "fd_xdp_new: bpf udp map file name overflow\n" ));
    goto fd_xdp_new_err;
  }
  //char const * bpf_pin_udp_map = "/sys/fs/bpf/firedancer/firedancer_udp_map";
  char const * bpf_pin_udp_map = buf;
  self.xdp_udp_map_fd = bpf_obj_get( bpf_pin_udp_map );
  if( self.xdp_udp_map_fd < 0 ) {
    FD_LOG_WARNING(( "fd_xdp_new: bpf_obj_get failed on file %s. Error: %d %s\n",
          bpf_pin_udp_map, errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  /* 4. bpf_obj_get( "/sys/fs/bpf/xdp_bpf_prog" )                                                    */
  /*     - Input:            Path used to pin the program in (1)                                     */
  /*     - syscall command:  BPF_OBJ_GET                                                             */
  /*     - Returns:          bpf_fd                                                                  */
  /* 5. bpf_object__open( <path to xdp_bpf.o> )                                                      */
  /*     - Input:            Path to well-known eBPF object file                                     */
  /*     - syscall command:  N/A, this just opens the ELF file                                       */
  /*     - Returns:          bpf_obj                                                                 */
  /* 6. bpf_obj_get( "/sys/fs/bpf/xsks_map" )                                                        */
  /*     - Input:            Path where map is pinned during (3)                                     */
  /*     - syscall command:  BPF_OBJ_GET                                                             */
  /*     - Returns:          bpf_xsks_map_fd                                                         */
  /* 7. bpf_map__reuse_fd( <map>, bpf_xsks_map_fd )                                                  */
  /*     - Input:            Named map object from bpf_obj, and the file descriptor retried from (6) */
  /*     - syscall command:  ??? TODO                                                                */
  /*     - Returns:          None                                                                    */
  /* 8. bpf_set_link_xdp_fd( if_index, bpf_fd )                                                      */
  /*     - Input:            Interface index, bpf_fd from (4)                                        */
  /* 9. bpf_map_update_elem( bpf_xsks_map_fd, key, sock )                                            */
  /*     - Input:            Map file descriptor retrieved from (6), AF_XDP socket file descriptor   */
  /*     - syscall command:  BPF_MAP_UPDATE_ELEM                                                     */
  /*     - Side effects:     Associate packets with <key> to this AF_XDP socket                      */

  /* set key zero to the socket */
  int      key   = 0;
  uint64_t flags = 0;
  if( bpf_map_update_elem( self.xdp_map_fd, &key, &self.xdp_sock, flags ) ) {
    FD_LOG_WARNING(( "fd_xdp_new: Unable to update xsks map to set the socket fd. Error: %d %s\n",
          errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  /* xdp is all configured */

  /* construct fd_xdp */
  fd_xdp_t * rtn = (fd_xdp_t*)malloc( sizeof( fd_xdp_t ) );
  if( rtn == NULL ) {
    FD_LOG_WARNING(( "fd_xdp_new: Unable to allocate enough space for fd_xdp_t. "
          "Error: %d %s", errno, strerror( errno ) ));
    goto fd_xdp_new_err;
  }

  memcpy( rtn, &self, sizeof( self ) );

  return rtn;

fd_xdp_new_err:
  /* error occurred, perform clean shutdown, releasing all resources */

  if( self.xdp_sock >= 0 ) close( self.xdp_sock );
  if( self.owned_mem ) free( self.owned_mem );
  if( self.xdp_map_fd >= 0 ) close( self.xdp_map_fd );
  return NULL;
}

void
fd_xdp_delete( fd_xdp_t * xdp ) {
  /* calling delete on NULL is allowed */
  if( FD_UNLIKELY( !xdp ) ) return;

  if( FD_UNLIKELY( xdp->ifindex > (1u<<30u) ) ) {
    FD_LOG_WARNING(( "fd_xdp_delete: attempt to delete xdp object, but ifindex outside normal range" ));
  }

  /* remove BPF program from interface */
  if( bpf_set_link_xdp_fd( (int)xdp->ifindex, -1, 0 ) ) {
    FD_LOG_WARNING(( "fd_xdp_delete: Error occurred trying to remove bpf program from "
          "interface %d. Error: %d %s", xdp->ifindex, errno, strerror( errno ) ));
    /* continue releasing resources here */
  }

  /* close xdp socket */
  if( close( xdp->xdp_sock ) ) {
    fprintf( stderr, "error closing fd fd: %d %s\n", errno, strerror( errno ) );
  }

  /* free memory, if necessary */
  free( xdp->owned_mem );

  /* free self */
  free( xdp );

  FD_RING_ITER_TYPES(FD_RING_USE,);


}


/* add key to xdp flow steering map */
void
fd_xdp_add_key( fd_xdp_t * xdp, unsigned key ) {
  uint64_t flags = BPF_ANY;
  int      value = 0; // TODO this is the key in the xsks table
                      // at present there is only ever one
  if( bpf_map_update_elem( xdp->xdp_udp_map_fd, &key, &value, flags ) ) {
    FD_LOG_WARNING(( "fd_xdp_add_key: Unable to update xdp map to set the socket fd. Error: %d %s\n",
          errno, strerror( errno ) ));
  }
}


/* remove key from xdp flow steering map */
void
fd_remove_key( fd_xdp_t * xdp, unsigned key ) {
  /* ignore errors */
  bpf_map_delete_elem( xdp->xdp_udp_map_fd, &key );
}


/* enqueue a batch of frames for receive
   For each k in [0,count-1] enqueues frame at offset offset[k]

   These frames are enqueued in order. Some frames may not be
   enqueued, and these will be the frames referred to by offset[N+]

   returns:
     The count of frames enqueued
*/
size_t
fd_xdp_rx_enqueue( fd_xdp_t * xdp, uint64_t * offset, size_t count ) {
  /* to make frames available for receive, we enqueue onto the fill ring */

  /* fill ring */
  fd_ring_fr_desc_t * fill = &xdp->ring_fr;

  /* fetch cached consumer, producer */
  uint64_t prod = fill->cached_prod;
  uint64_t cons = fill->cached_cons;

  /* ring capacity */
  uint64_t cap  = fill->sz;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = fill->cached_cons = *fill->cons;
  }

  /* sz is min( available, count ) */
  size_t sz = cap - ( prod - cons );
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  uint64_t * ring = fill->ring;
  uint64_t mask = fill->sz - 1;
  for( uint64_t j = 0; j < sz; ++j ) {
    uint64_t k = prod & mask;
    ring[k] = offset[j];

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
  fill->cached_prod = *fill->prod = prod;

  /* TODO do we need to check for wakeup here? */

  return sz;
}


/* enqueue a batch of frames for receive
   For each k in [0,count-1] enqueues frame at offset meta[k]->offset

   These frames are enqueued in order. Some frames may not be
   enqueued, and these will be the frames referred to by meta->offset[N+]

   returns:
     The count of frames enqueued
*/
size_t
fd_xdp_rx_enqueue2( fd_xdp_t * xdp, fd_xdp_frame_meta_t * meta, size_t count ) {
  /* to make frames available for receive, we enqueue onto the fill ring */

  /* fill ring */
  fd_ring_fr_desc_t * fill = &xdp->ring_fr;

  /* fetch cached consumer, producer */
  uint64_t prod = fill->cached_prod;
  uint64_t cons = fill->cached_cons;

  /* assuming frame sizes are powers of 2 */
  uint64_t frame_mask = xdp->config.frame_size - 1u;

  /* ring capacity */
  uint64_t cap  = fill->sz;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = fill->cached_cons = *fill->cons;
  }

  /* sz is min( available, count ) */
  size_t sz = cap - ( prod - cons );
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  uint64_t * ring = fill->ring;
  uint64_t mask = fill->sz - 1;
  for( uint64_t j = 0; j < sz; ++j ) {
    uint64_t k = prod & mask;
    ring[k] = meta[j].offset & frame_mask;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
  fill->cached_prod = *fill->prod = prod;

  /* TODO do we need to check for wakeup here? */

  return sz;
}


/* enqueue a batch of frames for transmit

   For each k in [0,count-1] enqueues frame at offset meta[k].offset
   of size meta[k].sz bytes

   Frames should be complete before making this call

   No changes should be made to any frame until it is returned via
   fd_xdp_tx_complete

   These frames are transmitted in order. Some frames may not be
   enqueued, and these will be the frames referred to by meta[N+]

   Unqueued frames may be retried

   returns:
     The count of frames enqueued */
size_t
fd_xdp_tx_enqueue( fd_xdp_t * xdp, fd_xdp_frame_meta_t * meta, size_t count ) {
  /* to submit frames for tx, we enqueue onto the tx ring */

  /* tx ring */
  fd_ring_tx_desc_t * tx = &xdp->ring_tx;

  /* fetch cached consumer, producer */
  uint64_t prod = tx->cached_prod;
  uint64_t cons = tx->cached_cons;

  /* ring capacity */
  uint64_t cap  = tx->sz;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = tx->cached_cons = *tx->cons;
  }

  /* sz is min( available, count ) */
  size_t sz = cap - ( prod - cons );
  /* TODO this doesn't work as expected
     if we early exit here, no wakeup occurs, sendto doesn't get called again
     and the ring doesn't get serviced
     This implies we need to call sendto AGAIN even if the ring hasn't changed
  if( sz == 0 )    return 0;
  */
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  fd_ring_entry_tx_t * ring = tx->ring;
  uint64_t mask = tx->sz - 1;
  for( uint64_t j = 0; j < sz; ++j ) {
    uint64_t k = prod & mask;
    ring[k].addr    = meta[j].offset;
    ring[k].len     = meta[j].sz;
    ring[k].options = 0;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
  tx->cached_prod = *tx->prod = prod;

  /* XDP tells us whether we need to specifically wake up the driver/hw */
  if( fd_xdp_tx_need_wakeup( xdp ) ) {
    sendto( xdp->xdp_sock, NULL, 0, MSG_DONTWAIT, NULL, 0 );
  }

  return sz;
}


/* complete receive batch

   Retrieves batch of rx frames, along with metadata

   xdp        The xdp to use
   batch      An array of competions to fill with receive info
   capacity   The number of elements in the batch array

   Returns:
     The count of completions written to batch */
size_t
fd_xdp_rx_complete( fd_xdp_t * xdp, fd_xdp_frame_meta_t * batch, size_t capacity ) {
  /* rx ring */
  fd_ring_rx_desc_t * rx = &xdp->ring_rx;

  uint64_t prod = rx->cached_prod;
  uint64_t cons = rx->cached_cons;

  /* how many frames are available? */
  uint64_t avail = prod - cons;

  /* should we update the cache */
  if( avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = rx->cached_prod = *rx->prod;
    avail = prod - cons;
  }

  uint64_t sz = avail;
  if( sz > capacity ) sz = capacity;

  uint64_t mask = rx->sz - 1;
  fd_ring_entry_rx_t * ring = rx->ring;
  for( uint64_t j = 0; j < sz; ++j ) {
    uint64_t k = cons & mask;
    batch[j].offset = ring[k].addr;
    batch[j].sz     = ring[k].len;
    batch[j].flags  = 0;

    cons++;
  }

  FD_RELEASE();

  rx->cached_cons = *rx->cons = cons;

  return sz;
}


/* complete transmit batch

   Retrieves batch of tx frames which have completed the tx operation
   Frames referred to in the returned array may now be modified safely

   xdp        The xdp to use
   batch      An array of competions to fill with frame info
   capacity   The number of elements in the batch array

   Returns:
     The count of completions written to batch */
size_t
fd_xdp_tx_complete( fd_xdp_t * xdp, uint64_t * batch, size_t capacity ) {
  /* cr ring */
  fd_ring_cr_desc_t * cr = &xdp->ring_cr;

  uint64_t prod = cr->cached_prod;
  uint64_t cons = cr->cached_cons;

  /* how many frames are available? */
  uint64_t avail = prod - cons;

  /* should we update the cache */
  if( avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = cr->cached_prod = *cr->prod;
    avail = prod - cons;
  }

  uint64_t sz = avail;
  if( sz > capacity ) sz = capacity;

  uint64_t mask = cr->sz - 1;
  fd_ring_entry_cr_t * ring = cr->ring;
  for( uint64_t j = 0; j < sz; ++j ) {
    uint64_t k = cons & mask;
    batch[j] = ring[k];

    cons++;
  }

  FD_RELEASE();

  cr->cached_cons = *cr->cons = cons;

  return sz;
}


/* complete transmit batch

   Retrieves batch of tx frames which have completed the tx operation
   Frames referred to in the returned array may now be modified safely

   xdp        The xdp to use
   batch      An array of competions to fill with frame info
   capacity   The number of elements in the batch array

   Returns:
     The count of completions written to batch */
size_t
fd_xdp_tx_complete2( fd_xdp_t * xdp, fd_xdp_frame_meta_t * batch, size_t capacity ) {
  /* cr ring */
  fd_ring_cr_desc_t * cr = &xdp->ring_cr;

  uint64_t prod = cr->cached_prod;
  uint64_t cons = cr->cached_cons;

  /* how many frames are available? */
  uint64_t avail = prod - cons;

  /* should we update the cache */
  if( avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = cr->cached_prod = *cr->prod;
    avail = prod - cons;
  }

  uint64_t sz = avail;
  if( sz > capacity ) sz = capacity;

  uint64_t mask = cr->sz - 1;
  fd_ring_entry_cr_t * ring = cr->ring;
  for( uint64_t j = 0; j < sz; ++j ) {
    uint64_t k = cons & mask;
    batch[j].offset = ring[k];

    cons++;
  }

  FD_RELEASE();

  cr->cached_cons = *cr->cons = cons;

  return sz;
}

/* returns whether a wakeup is required to complete a tx operation */
int
fd_xdp_tx_need_wakeup( fd_xdp_t * xdp ) {
  return !!( *xdp->ring_tx.flags & XDP_RING_NEED_WAKEUP );
}

/* returns whether a wakeup is required to complete a rx operation */
int
fd_xdp_rx_need_wakeup( fd_xdp_t * xdp ) {
  /* this refers to the fill ring */
  return !!( *xdp->ring_fr.flags & XDP_RING_NEED_WAKEUP );
}

uint64_t
fd_xdp_get_frame_memory( fd_xdp_t * xdp ) {
  return xdp->umem.addr;
}



