#ifndef HEADER_fd_src_waltz_quic_tests_fd_quic_helpers_h
#define HEADER_fd_src_waltz_quic_tests_fd_quic_helpers_h

#include "../fd_quic.h"
#include "../../aio/fd_aio_pcapng.h"
#include "../../udpsock/fd_udpsock.h"
#include "../../tls/test_tls_helper.h"
#include "../../../util/net/fd_eth.h"
#include <stdio.h>

/* Common helpers for QUIC tests.  The tests using these gain the
   following command-line options:

     --pcap <path>   Append test traffic to pcapng 1.0 at given file
                     path (encryption secrets included) */

/* fd_quic_virtual_pair_t is used to connect two local QUICs via
   direct fd_aio.  Optionally supports packet capture. */

struct fd_quic_virtual_pair {
  fd_quic_t * quic_a;
  fd_quic_t * quic_b;

  /* aio_{a2b,b2a} point to the first hop of each aio chain */
  fd_aio_t const * aio_a2b;
  fd_aio_t const * aio_b2a;

  fd_aio_pcapng_t pcapng_a2b;
  fd_aio_pcapng_t pcapng_b2a;
};
typedef struct fd_quic_virtual_pair fd_quic_virtual_pair_t;

FD_PROTOTYPES_BEGIN

extern FILE * fd_quic_test_pcap;

/* fd_quic_test_boot boots the QUIC test environment.
   Should be called after fd_boot().

   fd_quic_test_halt halts the QUIC test environment.
   Should be called before fd_halt(). */

void
fd_quic_test_boot( int *    pargc,
                   char *** pargv );
void
fd_quic_test_halt( void );

void
fd_quic_config_anonymous( fd_quic_t * quic,
                          int         role );

void
fd_quic_config_test_signer( fd_quic_t *              quic,
                            fd_tls_test_sign_ctx_t * sign_ctx );

/* fd_quic_new_anonymous creates an anonymous QUIC instance with the
   given limits.  Vacant config fields are auto-generated, except for
   role (server or client). Returns QUIC instance without local join on
   success.  Halts program on error. Caller is responsible for cleaning
   up QUIC. */

fd_quic_t *
fd_quic_new_anonymous( fd_wksp_t *              wksp,
                       fd_quic_limits_t const * limits,
                       int                      role,
                       fd_rng_t *               rng );

/* fd_quic_new_anonymous_small is like fd_quic_new_anonymous but with
   arbitrary small limits for convenience. */

fd_quic_t *
fd_quic_new_anonymous_small( fd_wksp_t * wksp,
                             int         role,
                             fd_rng_t *  rng );

/* fd_quic_virtual_pair_init sets up an aio loop between the two given QUIC
   objects.  That is, an fd_aio_send() call by quicA will trigger
   a synchronous callback to the aio receive to the quicB.  (FIXME This
   assumes no reentrancy in QUIC)  If user requested pcap, causes
   packets to get logged.  May only be called once per thread.  Any
   allocated resources get released at halt. */

void
fd_quic_virtual_pair_init( fd_quic_virtual_pair_t * pair,
                           fd_quic_t * quicA,
                           fd_quic_t * quicB );

/* fd_quic_virtual_pair_fini destroys an aio loop between the two given
   QUIC objects. */

void
fd_quic_virtual_pair_fini( fd_quic_virtual_pair_t * pair );

void
fd_quic_test_cb_tls_keylog( void *       quic_ctx,
                            char const * line );

FD_PROTOTYPES_END

/* fd_quic_udpsock is a command-line helper for creating an UDP channel
   over AF_XDP or UDP sockets. */

struct fd_quic_udpsock {
  int type;
# define FD_QUIC_UDPSOCK_TYPE_UDPSOCK 2

  uint   listen_ip;
  ushort listen_port;

  fd_wksp_t * wksp;  /* Handle to the workspace owning the objects */
  union {
    struct {
      fd_udpsock_t * sock;
      int            sock_fd;
    } udpsock;
  };

  fd_aio_t const * aio;
};
typedef struct fd_quic_udpsock fd_quic_udpsock_t;

FD_PROTOTYPES_BEGIN

fd_quic_udpsock_t *
fd_quic_client_create_udpsock(fd_quic_udpsock_t * udpsock,
                              fd_wksp_t *      wksp,
                              fd_aio_t const * rx_aio,
                              uint listen_ip);

fd_quic_udpsock_t *
fd_quic_udpsock_create( void *           _sock,
                        int *            argc,
                        char ***         argv,
                        fd_wksp_t *      wksp,
                        fd_aio_t const * rx_aio );

void *
fd_quic_udpsock_destroy( fd_quic_udpsock_t * udpsock );

void
fd_quic_udpsock_service( fd_quic_udpsock_t const * udpsock );


/* fd_quic_netem injects packet loss and reordering into an aio link. */

struct fd_quic_netem_reorder_buf {
  ulong sz;
  uchar buf[2048];
};

struct fd_quic_netem {
  fd_aio_t         local;
  fd_aio_t const * dst;
  float            thresh_drop;
  float            thresh_reorder;

  struct fd_quic_netem_reorder_buf reorder_buf[2];
  int                              reorder_mru; /* most recently written reorder buf */
};

typedef struct fd_quic_netem fd_quic_netem_t;

fd_quic_netem_t *
fd_quic_netem_init( fd_quic_netem_t * netem,
                    float             thres_drop,
                    float             thres_reorder );

/* fd_quic_netem_send implements fd_aio_send for fd_quic_netem_t. */

int
fd_quic_netem_send( void *                    ctx, /* fd_quic_net_em_t */
                    fd_aio_pkt_info_t const * batch,
                    ulong                     batch_cnt,
                    ulong *                   opt_batch_idx,
                    int                       flush );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_tests_fd_quic_helpers_h */
