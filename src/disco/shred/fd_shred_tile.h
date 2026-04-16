#ifndef HEADER_fd_src_disco_shred_fd_shred_tile_h
#define HEADER_fd_src_disco_shred_fd_shred_tile_h

#include "../tiles.h"
#include "../keyguard/fd_keyguard_client.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "fd_fec_resolver.h"

/* Forward declarations */
typedef struct fd_fec_resolver fd_fec_resolver_t;
typedef struct fd_keyswitch_private fd_keyswitch_t;
typedef struct fd_keyguard_client fd_keyguard_client_t;

/* Shred tile context structure */
typedef struct {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  fd_pubkey_t          identity_key[1]; /* Just the public key */
  /* ... rest of the structure members ... */
} fd_shred_shared_ctx_t;

/* shred_out has 3 possible message types, but 8 different message sigs
   to differentiate between different data sources.  All individual
   shred messages
   SHRED_SIG_SRC_{TURBINE,LEADER,RECONSTRUCTED,REPAIR,BAD_REPAIR} have
   the same dcache type fd_shred_base_t.  Only repair/bad_repair shreds
   will populate the rnonce field.

   SHRED_SIG_FEC_{EVICTED,COMPLETE,COMPLETE_LEADER} are not generated on
   every shred, but rather on events where a FEC set is completed by the
   fec_resolver or evicted from the fec_resolver.  In the case that a
   FEC set is completed by the 32nd shred in a FEC set, both a shred
   message and a complete message will be published.  It is convenient
   for downstream consumers to have both messages available.

   The last 32 LSB of sig is the data source of the message, and the
   first 32 MSB is the shred processing result. */

/* shred_base_t sigs */
#define SHRED_SIG_SRC_TURBINE         (0U) /* turbine shred */
#define SHRED_SIG_SRC_LEADER          (1U) /* shred created by leader */
#define SHRED_SIG_SRC_RECONSTRUCTED   (2U) /* reconstructed data shred */
#define SHRED_SIG_SRC_REPAIR          (3U) /* repair shred */
#define SHRED_SIG_SRC_BAD_REPAIR      (4U) /* repair shred with unverifiable nonce */

/* fec_resolver event sigs */
#define SHRED_SIG_FEC_EVICTED         (5UL) /* evicted */
#define SHRED_SIG_FEC_COMPLETE        (6UL) /* FEC set complete */
#define SHRED_SIG_FEC_COMPLETE_LEADER (7UL) /* leader FEC set complete */

/* shred processing result (first 32 bits of sig) */
#define SHRED_SIG_RESULT_COMPLETES     ( 1)
#define SHRED_SIG_RESULT_OKAY          ( 0) /* default */
#define SHRED_SIG_RESULT_DUPLICATE     (-1)
#define SHRED_SIG_RESULT_EQVOC         (-4)

FD_STATIC_ASSERT( SHRED_SIG_RESULT_COMPLETES == FD_FEC_RESOLVER_SHRED_COMPLETES, "shred sig result does not match fec_resolver result" );
FD_STATIC_ASSERT( SHRED_SIG_RESULT_OKAY      == FD_FEC_RESOLVER_SHRED_OKAY,      "shred sig result does not match fec_resolver result" );
FD_STATIC_ASSERT( SHRED_SIG_RESULT_DUPLICATE == FD_FEC_RESOLVER_SHRED_DUPLICATE, "shred sig result does not match fec_resolver result" );
FD_STATIC_ASSERT( SHRED_SIG_RESULT_EQVOC     == FD_FEC_RESOLVER_SHRED_EQUIVOC,   "shred sig result does not match fec_resolver result" );

static inline int  fd_shred_sig_res( ulong sig ) { return (int)(sig >> 32UL); }
static inline uint fd_shred_sig_src( ulong sig ) { return (uint)sig; }

/* For all individual shred messages:
   SHRED_SIG_SRC_{TURBINE,LEADER,RECONSTRUCTED,REPAIR,BAD_REPAIR} */
struct fd_shred_base {
  fd_hash_t merkle_root;
  union {
    uchar        shred_[ FD_SHRED_MAX_SZ ];
    fd_shred_t   shred;
  };
  uint      rnonce;        /* populated only for repair/bad_repair shreds */
};
typedef struct fd_shred_base fd_shred_base_t;

/* For the FEC evicted message: SHRED_SIG_FEC_EVICTED */
struct fd_fec_evicted {
  ulong slot;
  uint  fec_set_idx;
};
typedef struct fd_fec_evicted fd_fec_evicted_t;


/* For an FEC complete message: SHRED_SIG_FEC_COMPLETE or SHRED_SIG_FEC_COMPLETE_LEADER */
struct fd_fec_complete {
  fd_hash_t  merkle_root;    /* placed first to match format of shred base */
  fd_shred_t last_shred_hdr; /* header of last data shred in the FEC set */
  fd_hash_t  chained_merkle_root;
};
typedef struct fd_fec_complete fd_fec_complete_t;

union fd_shred_message {
  fd_shred_base_t   shred;
  fd_fec_evicted_t  evicted;
  fd_fec_complete_t complete;
};
typedef union fd_shred_message fd_shred_message_t;

#endif /* HEADER_fd_src_disco_shred_fd_shred_tile_h */
