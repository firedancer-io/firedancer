#ifndef HEADER_fd_src_waltz_snp_fd_snp_app_h
#define HEADER_fd_src_waltz_snp_fd_snp_app_h

#include "fd_snp_common.h"

#define FD_SNP_APP_ALIGN (8UL)
#define FD_SNP_APP_MAGIC (0xf17eda2ce7529a99UL)

/* TYPES */

/* CALLBACKS */

/* send/tx callback is invoked by fd_snp_app_send* to actually send
   the packet over the wire (or to a different process). */
typedef int
( * fd_snp_app_cb_tx_t )( void const *  ctx,          /* callback context */
                          uchar *       packet,       /* packet to send */
                          ulong         packet_sz,    /* size of packet to send */
                          fd_snp_meta_t meta );       /* connection metadata */

/* recv/rx callback is invoked by fd_snp_app_recv to process data
   received from peer. */
typedef int
( * fd_snp_app_cb_rx_t )( void const *  ctx,          /* callback context */
                          fd_snp_peer_t peer,         /* source peer */
                          uchar const * data,         /* app data received from peer */
                          ulong         data_sz,      /* size of app data received from peer */
                          fd_snp_meta_t meta );       /* connection metadata */

/* fd_snp_app_callbacks_t groups all the callbacks for fd_snp_app_t. */
struct fd_snp_app_callbacks {
  void *             ctx;
  fd_snp_app_cb_tx_t tx;
  fd_snp_app_cb_rx_t rx;
};
typedef struct fd_snp_app_callbacks fd_snp_app_callbacks_t;

/* fd_snp_app_t is a type to represent a SNP app context. */
struct __attribute__((aligned(FD_SNP_APP_ALIGN))) fd_snp_app {
  ulong                  magic;
  fd_snp_app_callbacks_t cb;
};
typedef struct fd_snp_app fd_snp_app_t;

FD_PROTOTYPES_BEGIN

/* ALLOC */

FD_FN_CONST static inline ulong
fd_snp_app_align( void ) {
  return FD_SNP_APP_ALIGN;
}

/* fd_snp_app_footprint returns the footprint of the fd_snp_app_t structure. */
ulong
fd_snp_app_footprint( void );

/* fd_snp_app_new initializes a new fd_snp_app_t structure. */
void *
fd_snp_app_new( void * mem );

/* fd_snp_app_join joins the caller to the fd_snp_app.
   shsnp points to the first byte of the memory region backing the SNP app in
   the caller's address space. */
fd_snp_app_t *
fd_snp_app_join( void * shsnp );

/* APP API */

/* fd_snp_app_recv receives data from a peer.
   Concretely, it invokes the receive callback registered in the snp_app context `ctx`,
   passing a pointer to the payload data (the position of the payload depends on the
   incoming packet protocol).
   packet, packet_sz and meta are received from the fd_snp_process_packet()
   function (via its receive callback). */
int
fd_snp_app_recv( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar const *        packet,       /* input packet */
                 ulong                packet_sz,    /* size of input packet */
                 fd_snp_meta_t        meta );       /* connection metadata */

/* fd_snp_app_send sends data to a peer.
   Concretely, it prepares packet by storing data in the right position,
   depending on the protocol (SNP vs UDP) and invokes the send callback
   registered in the snp_app context `ctx`. */
int
fd_snp_app_send( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar *              packet,       /* output packet buffer */
                 ulong                packet_sz,    /* (max) size of output packet buffer */
                 void const *         data,         /* app data to send to peer */
                 ulong                data_sz,      /* size of app data to send to peer */
                 fd_snp_meta_t        meta );       /* connection metadata */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_snp_fd_snp_app_h */
