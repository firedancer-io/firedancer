#ifndef HEADER_fd_src_discof_repair_fd_repair_h
#define HEADER_fd_src_discof_repair_fd_repair_h

/* fd_repair implements the Solana Repair protocol.  In a nutshell,
   Repair is a protocol for recovering shreds that the validator is
   expecting but has not received from Turbine.  How a validator detects
   that it should be expecting a shred is not implemented in this file;
   rather, this is an implementation of the protocol itself for
   requesting shreds from other validators.

   The repair protocol supports three different request types:

   - Shred( slot, shred_idx )

     This is a request for a specific shred in the provided slot.  The
     (slot, shred index) generally uniquely identifies a shred except in
     certain exceptional conditions (equivocation).  The responding
     validator will return the shred if it has it.

   - HighestShred( slot, shred_idx )

     This is a request for the highest shred in the provided slot that
     is greater than or equal to shred_idx.  Note this is not
     necessarily the last shred in the slot, as it depends on what the
     responding validator has available.  The responding validator will
     return the highest shred it has that meets the condition.

   - Orphan( slot )

     This is a request for up to 10 shreds, where each shred is the
     prior one's ancestor, beginning from but excluding slot.  For
     example, an orphan request for slot 10 will return a single shred
     for slots 9, 8, 7, 6, 5, 4, 3, 2 and 1 (assuming no skips).  Also,
     the responding validator will return the highest shred index it has
     for every ancestor it knows about.

    All 3 repair request types are prefixed with a common header of from
    pubkey, to pubkey, ulong timestamp and uint nonce.  The timestamp is
    a standard UNIX epoch (milliseconds since 1970-01-01T00:00:00Z) and
    the nonce is echoed back by the responding validator in the repair
    response.  Unlike a typical cryptographic nonce that prevents replay
    attacks, the repair server implementation ignores the nonce and this
    implementation leaves it up to the calling application to manage the
    nonce.  Note the 4 nonce bytes are appended after the end of a shred
    in a repair response.

    The repair protocol also implements a Ping-Pong protocol for address
    validation.  When a validator receives a repair request from another
    validator it does not recognize, it will ignore the request and
    instead respond with its own Ping request to the requesting
    validator.  The Ping contains a hash that the requesting validator
    needs to hash and sign as part of a Pong response.

    All communication across the wire is done with bincode serialization
    encoding. */

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../util/fd_util.h"

/* FD_REPAIR_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_REPAIR_USE_HANDHOLDING
#define FD_REPAIR_USE_HANDHOLDING 1
#endif

/* FD_REPAIR_PREIMAGE_PREFIX is used by Repair's Ping-Pong protocol.
   Both a Ping and Pong contain a hash token, that is generated from a
   preimage prefixed with the below.  */

#define FD_REPAIR_PREIMAGE_PREFIX    "SOLANA_PING_PONG"
#define FD_REPAIR_PREIMAGE_PREFIX_SZ (sizeof(FD_REPAIR_PREIMAGE_PREFIX) - 1)
#define FD_REPAIR_PREIMAGE_SZ        (FD_REPAIR_PREIMAGE_PREFIX_SZ + sizeof(fd_hash_t))

/* FD_REPAIR_KIND_{PONG,SHRED,HIGHEST_SHRED,ORPHAN} specify discriminant
   values the protocol uses to distinguish request types. */

#define FD_REPAIR_KIND_PONG              (7U)
#define FD_REPAIR_KIND_SHRED_REQ         (8U)
#define FD_REPAIR_KIND_HIGHEST_SHRED_REQ (9U)
#define FD_REPAIR_KIND_ORPHAN_REQ        (10U)

typedef struct fd_repair fd_repair_t; /* forward decl */

/* fd_repair_sign_fn is called to sign Repair payloads. */

typedef void (*fd_repair_sign_fn)( uchar * msg, ulong msg_sz, fd_ed25519_sig_t sig_out );

/* fd_repair_pong defines the bincode serialization schema of a Pong. */

struct __attribute__((packed)) fd_repair_pong {
  uint             kind; /* FD_REPAIR_KIND_PONG */
  fd_pubkey_t      from; /* pubkey of the validator responding with the pong */
  fd_hash_t        hash; /* sha-256 hash generated from a ping hash */
  fd_ed25519_sig_t sig;  /* from's signature over the preceding hash field */
};
typedef struct fd_repair_pong fd_repair_pong_t;
FD_STATIC_ASSERT( sizeof(fd_repair_pong_t)==132UL, Pong should be 132 bytes serialized );

/* fd_repair_req defines the bincode serialization schema of all Repair
   request types.  Note they all share a common header, and the three
   different variants are encoded in the nested union. */

struct __attribute__((packed)) fd_repair_req {
  uint             kind;  /* FD_REPAIR_KIND_{SHRED,HIGHEST_SHRED,ORPHAN}_REQ */
  fd_ed25519_sig_t sig;   /* ed25519 signature over all the subsequent fields */
  fd_pubkey_t      from;  /* pubkey of the validator that sent the request */
  fd_pubkey_t      to;    /* pubkey of the validator that is being requested */
  ulong            ts;    /* timestamp in milliseconds since unix epoch */
  uint             nonce; /* nonce to be echoed back by the responding validator */
  union {
    struct {
      ulong slot;      /* slot for which the shred is requested */
      ulong shred_idx; /* shred index for which the shred is requested (if not an orphan request) */
    } shred;

    struct {
      ulong slot;      /* slot for which the shred is requested */
      ulong shred_idx; /* minimum shred index for which the shred is requested (if not an orphan request) */
    } highest_shred;

    struct {
      ulong slot;      /* orphaned slot for which the shreds of ancestor slots are requested  */
    } orphan;
  };
};
typedef struct fd_repair_req fd_repair_req_t;
FD_STATIC_ASSERT( sizeof(fd_repair_req_t)==160UL, Request should be 160 bytes serialized );

/* fd_repair_peer_t is used to track Repair peers.  The map key is the
   last 8 bytes of the validator's identity key. */

struct fd_repair_peer {
  ulong key;
  long  ts;
};
typedef struct fd_repair_peer fd_repair_peer_t;

#define MAP_NAME    fd_repair_peer_map
#define MAP_T       fd_repair_peer_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_repair_sent_t is used to cache already-sent Repair requests.  The
   map key is a concatenation of request kind, slot, and shred_idx (if
   not an orphan request). */

struct fd_repair_sent {
  ulong key;
  long  ts;
};
typedef struct fd_repair_sent fd_repair_sent_t;

#define MAP_NAME    fd_repair_sent_map
#define MAP_T       fd_repair_sent_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_repair {
  fd_pubkey_t       identity_key; /* validator identity key */
  fd_repair_sign_fn sign_fn;      /* function to sign repair payloads */
  fd_repair_pong_t  pong;         /* buffer for outgoing pongs */
  fd_repair_req_t   req;          /* buffer for outgoing repair requests */

  fd_repair_peer_t * peer_map; /* map of repair peers */
  fd_repair_sent_t * sent_map; /* map of repair requests to cache */
};

/* Constructors */

/* fd_repair_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as repair with up to
   ele_max eles and vote_max votes. */

FD_FN_CONST static inline ulong
fd_repair_align( void ) {
  return alignof(fd_repair_t);
}

FD_FN_CONST static inline ulong
fd_repair_footprint( ulong peer_max, ulong sent_max ) {
  int lg_peer_max = fd_ulong_find_msb( fd_ulong_pow2_up( peer_max ) );
  int lg_sent_max = fd_ulong_find_msb( fd_ulong_pow2_up( sent_max ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_repair_t),       sizeof(fd_repair_t)                         ),
      fd_repair_peer_map_align(), fd_repair_peer_map_footprint( lg_peer_max ) ),
      fd_repair_sent_map_align(), fd_repair_sent_map_footprint( lg_sent_max ) ),
    fd_repair_align() );
}

/* fd_repair_new formats an unused memory region for use as a repair.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_repair_new( void * shmem, ulong peer_max, ulong sent_max, fd_repair_sign_fn sign_fn );

/* fd_repair_join joins the caller to the repair.  repair points to the
   first byte of the memory region backing the repair in the caller's
   address space.  Returns a pointer in the local address space to
   repair on success. */

fd_repair_t *
fd_repair_join( void * repair );

/* fd_repair_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include repair is NULL. */

void *
fd_repair_leave( fd_repair_t const * repair );

/* fd_repair_delete unformats a memory region used as a repair.  Assumes
   only the nobody is joined to the region.  Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. repair is obviously not a repair ... logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_repair_delete( void * repair );

/* fd_repair_pong creates and returns a pointer to a Pong message.  The
   Pong's signature is generated from the provided ping_token.  Assumes
   repair->req is not already buffering an existing request and can be
   overwritten.  Returns req_out on success, NULL on failure. */

fd_repair_pong_t *
fd_repair_pong( fd_repair_t * repair, fd_hash_t * ping_hash );

/* fd_repair_{shred,highest_shred,orphan}_req creates and returns a
   pointer to a {Shred,HighestShred,Orphan} request.  Assumes
   repair->req is not already buffering a request and can be
   overwritten.  Returns req_out on success, NULL on failure. */

uchar * fd_repair_shred_req        ( fd_repair_t * repair, ulong slot, ulong shred_idx, uint nonce );
uchar * fd_repair_highest_shred_req( fd_repair_t * repair, ulong slot, ulong shred_idx, uint nonce );
uchar * fd_repair_orphan_req       ( fd_repair_t * repair, ulong slot,                  uint nonce );

/* fd_repair_private expose stateless implementations for creating the
   above Repair messages.  These are exposed for unit tests but are not
   intended to be part of fd_repair's public API. */

/* fd_repair_private_pong is a private helper for fd_repair_pong. */

void
fd_repair_private_pong( fd_pubkey_t *      from,
                        fd_hash_t *        ping_hash,
                        fd_repair_sign_fn  sign_fn,
                        fd_repair_pong_t * pong_out );

/* fd_repair_private_{shred,highest_shred,orphan}_req are private
   helpers for their corresponding public functions. */

void fd_repair_private_shred_req        ( fd_pubkey_t * from, fd_pubkey_t * to, ulong ts, uint nonce, ulong slot, ulong shred_idx, fd_repair_sign_fn sign_fn, fd_repair_req_t * req_out );
void fd_repair_private_highest_shred_req( fd_pubkey_t * from, fd_pubkey_t * to, ulong ts, uint nonce, ulong slot, ulong shred_idx, fd_repair_sign_fn sign_fn, fd_repair_req_t * req_out );
void fd_repair_private_orphan_req       ( fd_pubkey_t * from, fd_pubkey_t * to, ulong ts, uint nonce, ulong slot,                  fd_repair_sign_fn sign_fn, fd_repair_req_t * req_out );

#endif /* HEADER_fd_src_discof_repair_fd_repair_h */
