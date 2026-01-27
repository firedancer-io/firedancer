#ifndef HEADER_fd_src_disco_events_fd_event_client_h
#define HEADER_fd_src_disco_events_fd_event_client_h

#include "fd_circq.h"
#include "../keyguard/fd_keyguard_client.h"
#include <complex.h>

#if FD_HAS_OPENSSL
#include <openssl/ssl.h>
#endif

#define FD_EVENT_CLIENT_STATE_DISCONNECTED    (0)
#define FD_EVENT_CLIENT_STATE_CONNECTING      (1)
#define FD_EVENT_CLIENT_STATE_AUTHENTICATING  (2)
#define FD_EVENT_CLIENT_STATE_CONFIRMING_AUTH (3)
#define FD_EVENT_CLIENT_STATE_CONNECTED       (4)

struct fd_event_client;
typedef struct fd_event_client fd_event_client_t;

struct fd_event_client_metrics {
  ulong transport_fail_cnt;
  ulong transport_success_cnt;
  ulong events_sent;
  ulong events_acked;
  ulong bytes_written;
  ulong bytes_read;
};

typedef struct fd_event_client_metrics fd_event_client_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_event_client_align( void );

FD_FN_CONST ulong
fd_event_client_footprint( ulong buf_max );

void *
fd_event_client_new( void *                 shmem,
                     fd_keyguard_client_t * keyguard_client,
                     fd_rng_t *             rng,
                     fd_circq_t *           circq,
                     int                    so_sndbuf,
                     char const *           endpoint,
                     uchar const *          identity_pubkey,
                     char const *           client_version,
                     ulong                  instance_id,
                     ulong                  boot_id,
                     ulong                  machine_id,
                     ulong                  buf_max );

fd_event_client_t *
fd_event_client_join( void * shec );

fd_event_client_metrics_t const *
fd_event_client_metrics( fd_event_client_t const * client );

ulong
fd_event_client_state( fd_event_client_t const * client );

ulong
fd_event_client_id_reserve( fd_event_client_t * client );

void
fd_event_client_init_genesis_hash( fd_event_client_t * client,
                                   uchar const *       genesis_hash );

void
fd_event_client_init_shred_version( fd_event_client_t * client,
                                    ushort              shred_version );

void
fd_event_client_set_identity( fd_event_client_t * client,
                              uchar const *       identity_pubkey );

void
fd_event_client_poll( fd_event_client_t * client,
                      int *               charge_busy );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_client_h */
