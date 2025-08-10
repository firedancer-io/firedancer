#ifndef HEADER_fd_src_disco_shred_fd_shred_tile_h
#define HEADER_fd_src_disco_shred_fd_shred_tile_h

#include "../tiles.h"
#include "../../flamenco/types/fd_types_custom.h"

/* FD_REPAIR_PING_SZ is the UDP payload size of a 'ping'-related packet.
   These incoming packets are forwarded to the repair tile. */
#define FD_REPAIR_PING_SZ (132UL)

struct fd_repair_ping_fwd {
  uint   src_ip4;
  uint   dst_ip4;
  ushort src_port;

  /* FIXME: Just have a wire-format struct here for the ping frame.
     This is currently not possible due to use of fd_types, which is not
     guaranteed to have the same in-memory format as the wire format. */
  uchar ping[ FD_REPAIR_PING_SZ ];
};

typedef struct fd_repair_ping_fwd fd_repair_ping_fwd_t;

/* Forward declarations */
typedef struct fd_fec_resolver fd_fec_resolver_t;
typedef struct fd_keyswitch_private fd_keyswitch_t;
typedef struct fd_keyguard_client fd_keyguard_client_t;

/* Part of the shred tile context struct
   FIXME remove this and just use fd_shred_ctx_t everywhere */
typedef struct {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  fd_pubkey_t          identity_key[1]; /* Just the public key */

  ulong                round_robin_id;
  ulong                round_robin_cnt;
  /* Number of batches shredded from PoH during the current slot.
     This should be the same for all the shred tiles. */
  ulong                batch_cnt;
  /* Slot of the most recent microblock we've seen from PoH,
     or 0 if we haven't seen one yet */
  ulong                slot;

  fd_keyswitch_t *     keyswitch;
  fd_keyguard_client_t keyguard_client[1];
  /* ... rest of the structure members ... */
} fd_shred_ctx_hdr_t;

#endif /* HEADER_fd_src_disco_shred_fd_shred_tile_h */
