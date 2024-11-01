#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_id_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_id_h

#include "../../util/fd_util_base.h"
#include "../../util/rng/fd_rng.h"
#include <string.h>

/* TODO move this into more reasonable place */
#define FD_QUIC_MAX_CONN_ID_SZ 20

/* Firedancer connection ids will sized thus */
#define FD_QUIC_CONN_ID_SZ 8

/* pad fd_quic_conn_id struct */
#define FD_QUIC_CONN_ID_PAD (24 - 1 - FD_QUIC_MAX_CONN_ID_SZ)

/* fd_quic_conn_id_t contains a QUIC connection ID with size in [0,20]
   bytes.  The unused conn_id high bytes MUST be zeroed. */

struct fd_quic_conn_id {
  uchar sz;
  uchar conn_id[FD_QUIC_MAX_CONN_ID_SZ];

  /* explicitly pad for alignment */
  uchar pad[FD_QUIC_CONN_ID_PAD];
};
typedef struct fd_quic_conn_id fd_quic_conn_id_t;

FD_PROTOTYPES_BEGIN

static inline fd_quic_conn_id_t
fd_quic_conn_id_new( void const * conn_id,
                     ulong        sz /* in [0,20] */ ) {
  /* TODO debug assertion verifying sz */
  fd_quic_conn_id_t id = { .sz = (uchar)sz };
  fd_memcpy( id.conn_id, conn_id, sz );
  return id;
}

/* fd_quic_conn_id_rand creates a new random 8 byte conn ID.  Returns
   conn ID.  Cannot fail. */

static inline fd_quic_conn_id_t *
fd_quic_conn_id_rand( fd_quic_conn_id_t * conn_id,
                      fd_rng_t *          rng ) {

  /* from rfc9000:
     Each endpoint selects connection IDs using an implementation-specific (and
       perhaps deployment-specific) method that will allow packets with that
       connection ID to be routed back to the endpoint and to be identified by
       the endpoint upon receipt. */
  /* this means we can generate a connection id with the property that it can
     be delivered to the same endpoint by flow control */
  /* TODO load balancing / flow steering */

  /* padding must be set to zero also */
  *conn_id = (fd_quic_conn_id_t){ .sz = 8u, .conn_id = {0u}, .pad = {0u} };
  FD_STORE( ulong, conn_id->conn_id, fd_rng_ulong( rng ) );
  return conn_id;
}

FD_PROTOTYPES_END

/* Defines a NULL connection id
   Used as a NULL key in hash maps
   Note that the QUIC protocol supports zero-length connection ids.
   Hence, an all-zero fd_quic_conn_id_t wouldn't work as a NULL key */
#define FD_QUIC_CONN_ID_NULL ((fd_quic_conn_id_t){ .sz = 0xff })

/* define some functions for using fd_quic_conn_id as a key */

/* is this an invalid connection id */
#define FD_QUIC_CONN_ID_INVAL(CONN_ID) ((CONN_ID).sz > FD_QUIC_MAX_CONN_ID_SZ)

/* are these connection ids the same connection id
   for this to work properly, all unused bytes are set to zero */
#define FD_QUIC_CONN_ID_EQUAL(LHS,RHS) \
  (memcmp(&(LHS),&(RHS),sizeof(fd_quic_conn_id_t))==0)

/* fd_quic_net_endpoint_t identifies a UDP/IP network endpoint.
   Stored in host endian.  May change during the lifetime of the conn. */

struct fd_quic_net_endpoint {
  uint   ip_addr;
  ushort udp_port;
};
typedef struct fd_quic_net_endpoint fd_quic_net_endpoint_t;

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_id_h */

