#ifndef HEADER_fd_src_waltz_snp_fd_snp_app_h
#define HEADER_fd_src_waltz_snp_fd_snp_app_h

#include "fd_snp_common.h"

#define FD_SNP_APP_ALIGN (8UL)
#define FD_SNP_APP_MAGIC (1234567890UL)

/* TYPES */

/* fd_snp_app_limits_t is a type to store config limits.
   The size of fd_snp_app_t depends on these limits. */
struct __attribute__((aligned(FD_SNP_APP_ALIGN))) fd_snp_app_limits {
  ulong max_peers_cnt;
};
typedef struct fd_snp_app_limits fd_snp_app_limits_t;

/* CALLBACKS */

/* send/tx callback.
   This is invoked by fd_snp_app_send* to actually send the packet over
   the wire (or to a different process). */
typedef int
( * fd_snp_app_cb_tx_t )( void const *  ctx,          /* callback context */
                          uchar *       packet,       /* packet to send */
                          ulong         packet_sz,    /* size of packet to send */
                          fd_snp_meta_t meta );       /* connection metadata */

/* recv/rx callback.
  This is invoked by fd_snp_app_recv to process data received from peer. */
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
  fd_snp_app_limits_t    limits;
  fd_snp_app_callbacks_t cb;
  fd_snp_peer_t *        peers;
};
typedef struct fd_snp_app fd_snp_app_t;

FD_PROTOTYPES_BEGIN

/* ALLOC */

FD_FN_CONST static inline ulong
fd_snp_app_align( void ) {
  return FD_SNP_APP_ALIGN;
}

ulong
fd_snp_app_footprint( fd_snp_app_limits_t const * limits );

void *
fd_snp_app_new( void * mem, fd_snp_app_limits_t const * limits );

fd_snp_app_t *
fd_snp_app_join( void * shsnp );

/* APP API */

int
fd_snp_app_recv( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar const *        packet,       /* input packet */
                 ulong                packet_sz,    /* size of input packet */
                 fd_snp_meta_t        meta );       /* connection metadata */

int
fd_snp_app_send( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar *              packet,       /* output packet buffer */
                 ulong                packet_sz,    /* (max) size of output packet buffer */
                 void const *         data,         /* app data to send to peer */
                 ulong                data_sz,      /* size of app data to send to peer */
                 fd_snp_meta_t        meta );       /* connection metadata */

int
fd_snp_app_send_many( fd_snp_app_t const * ctx,
                      uchar *              packet,
                      ulong                packet_sz,
                      fd_snp_peer_t *      peers,
                      ulong                peers_sz,
                      void const *         data,
                      ulong                data_sz,
                      fd_snp_meta_t        meta );

int
fd_snp_app_send_broadcast( fd_snp_app_t const * ctx,
                           uchar *              packet,
                           ulong                packet_sz,
                           void const *         data,
                           ulong                data_sz,
                           fd_snp_meta_t        meta );

FD_PROTOTYPES_END

#endif
