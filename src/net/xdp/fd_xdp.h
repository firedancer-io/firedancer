#ifndef HEADER_fd_xdp_h
#define HEADER_fd_xdp_h

#include <linux/if_link.h>

#include "../../util/fd_util_base.h"

/* opaque handle */
struct fd_xdp;
typedef struct fd_xdp fd_xdp_t;

/* structure used for configuring fd_xdp
   can initialize to reasonable defaults via:
     fd_xdp_config_init( &xdp_config ) */
struct fd_xdp_config {
  ulong        completion_ring_size; // number of frames in completion ring
                                     // completion ring returns sent frames back
                                     // from kernel to firedancer for reuse
  ulong        fill_ring_size;       // number of frames in fill ring
                                     // fill ring returns full RX frames to firedancer
                                     // for processing
  ulong        rx_ring_size;         // number of frames in rx ring
  ulong        tx_ring_size;         // number of frames in tx ring

  ulong        frame_size;           // max size of a frame
  ulong        frame_count;          // total number of frames

  void *       frame_memory;         // pointer into tx, rx frame memory
                                     // if null, fd_xdp_new will allocate properly
                                     // aligned memory
  ulong        frame_memory_size;    // amount of memory available at frame_memory
                                     // if frame_memory is null, fd_xdp will use:
                                     // ( completion_ring_size + fill_ring_size +
                                     //   rx_ring_size + tx_ring_size ) * frame_size
                                     // this is enough memory for all in-flight
                                     // frames

  ulong        xdp_mode;             // XDP mode
                                     // if set to zero, will default to XDP_FLAGS_SKB_MODE
                                     // allowed values are zero and the following:
                                     //   XDP_FLAGS_SKB_MODE      Most generic mode
                                     //   XDP_FLAGS_DRV_MODE      Driver supported XDP
                                     //   XDP_FLAGS_HW_MODE       Hardware supported XDP
                                     // These flags are found in linux/if_link.h
                                     // XDP_FLAGS_DRV_MODE requires support in the driver
                                     // but should be faster than SKB mode
                                     // Likewise XDP_FLAGS_HW_MODE requires support in the
                                     // hardware, but may be faster than HW mode

  char const * bpf_pgm_file;         // location of the BPF program to load onto the NIC
                                     // This program is required to forward the appropriate
                                     // traffic to Firedancer
                                     // If NULL the default of fd_bpf.o will be used

  char const * bpf_pin_name;         // name used to pin the loaded bpf program in /sys/fs/bpf

  char const * bpf_pin_dir;          // directory name used to bin the maps used by the bpf program

  uint         intf_queue;           // which interface queue to bind to
                                     // useful for load balancing in combination with:
                                     //   sudo ethtool -L <nic> combined <cnt>
};
typedef struct fd_xdp_config fd_xdp_config_t;


/* structure for providing metadata for rx and tx frames */
struct fd_xdp_frame_meta {
  ulong offset;        // The offset of the start of packet
  uint sz;             // Size of the data
  uint flags;          // Some flags - None defined yet
};
typedef struct fd_xdp_frame_meta fd_xdp_frame_meta_t;

FD_PROTOTYPES_BEGIN

/* initialize fd_xdp_config with defaults
   This function is not necessary, but may simplify usage of fd_xdp */
static inline void
fd_xdp_config_init( fd_xdp_config_t * config ) {
  fd_memset( config, 0, sizeof( *config ) );
  config->completion_ring_size = 1024;
  config->fill_ring_size       = 1024;
  config->tx_ring_size         = 1024;
  config->rx_ring_size         = 1024;

  config->frame_size           = 2048;

  config->frame_memory         = NULL;
  config->frame_memory_size    = 0;
}

/* determine alignment and footprint of an xdp instance */
size_t
fd_xdp_align( void );

size_t
fd_xdp_footprint( fd_xdp_config_t * config );

/* Create a new xdp interface  */
/* TODO
   how to set up ring, such that other Firedancer components
   can access properly? */

fd_xdp_t *
fd_xdp_new( void *                  mem,
            char const *            intf,
            fd_xdp_config_t const * config );

/* destroy an xdp interface, releasing all resources */
void
fd_xdp_delete( fd_xdp_t * xdp );

/* add key to xdp flow steering map
   currently there is one map, and it holds udp port numbers

   TODO support multiple maps: udp-port and conn_id hash

   0. check dest port, pass
   1. assume 8-byte conn_id, lookup, forward
   2. hash source ip:port, forward */
void
fd_xdp_add_key( fd_xdp_t * xdp,
                uint       key );

/* returns whether a wakeup is required to complete a tx operation */
int
fd_xdp_tx_need_wakeup( fd_xdp_t * xdp );

/* returns whether a wakeup is required to complete a rx operation */
int
fd_xdp_rx_need_wakeup( fd_xdp_t * xdp );


/* enqueue a batch of frames for receive
   For each k in [0,count-1] enqueues frame at offset offset[k]

   These frames are enqueued in order. Some frames may not be
   enqueued, and these will be the frames referred to by offset[N+]

   fd_xdp_rx_enqueue and fd_xdp_rx_enqueue2 are the same, except
   fd_xdp_rx_enqueue2 takes fd_xdp_frame_meta_t* instead of ulong*
     and simply ignores the redundant info

   returns:
     The count of frames enqueued */
ulong
fd_xdp_rx_enqueue( fd_xdp_t * xdp,
                   ulong *    offset,
                   ulong      count );

ulong
fd_xdp_rx_enqueue2( fd_xdp_t *            xdp,
                    fd_xdp_frame_meta_t * meta,
                    ulong                 count );


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
ulong
fd_xdp_tx_enqueue( fd_xdp_t *            xdp,
                   fd_xdp_frame_meta_t * meta,
                   ulong                 count );


/* complete receive batch

   Retrieves batch of rx frames, along with metadata

   xdp        The xdp to use
   batch      An array of competions to fill with receive info
   capacity   The number of elements in the batch array

   Returns:
     The count of completions written to batch */
ulong
fd_xdp_rx_complete( fd_xdp_t *            xdp,
                    fd_xdp_frame_meta_t * batch,
                    ulong                 capacity );


/* complete transmit batch

   Retrieves batch of tx frames which have completed the tx operation

   fd_xdp_tx_complete and fd_xdp_tx_complete2 are the same, except
   fd_xdp_tx_complete2 takes fd_xdp_frame_meta_t* instead of ulong*
     and simply ignores the redundant info

   xdp        The xdp to use
   batch      An array of competions to fill with receive info
   capacity   The number of elements in the batch array

   Returns:
     The count of completions written to batch */
ulong
fd_xdp_tx_complete( fd_xdp_t * xdp,
                    ulong *    batch,
                    ulong      capacity );

ulong
fd_xdp_tx_complete2( fd_xdp_t *            xdp,
                     fd_xdp_frame_meta_t * batch,
                     ulong                 capacity );

/* get the base frame memory pointer */
ulong
fd_xdp_get_frame_memory( fd_xdp_t * xdp );

/* fd_bpf_install

   Used to install a bpf program on an interface and pin it via files
   in /sys/fs/bpf
   This allows us to separate the bpf program installation from the
   firedancer runtime, meaning the minimum set of capabilities are
   needed for the runtime.

   Args
    bpf_file        the name of the bpf file to install
    intf            the name of the interface
    bpf_pin_name    the name of the pinned object in /sys/fs/bpf
    bpf_pin_dir     the name of the directory for pinning the bpf
                      program and maps

   Returns
     0          success
     rc         return code from libbpf */
int
fd_bpf_install( char const * bpf_file,
                char const * intf,
                char const * bpf_pin_dir,
                char const * bpf_pin_name,
                int          mode,
                int          log_level );

FD_PROTOTYPES_END

#endif // HEADER_fd_xdp_h

