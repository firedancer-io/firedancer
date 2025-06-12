#ifndef HEADER_fd_src_flamenco_runtime_fd_types_custom
#define HEADER_fd_src_flamenco_runtime_fd_types_custom

#include "fd_types_meta.h"
#include "fd_bincode.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../util/net/fd_ip4.h"

#define FD_HASH_FOOTPRINT (32UL)
#define FD_HASH_ALIGN (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN FD_HASH_ALIGN
#define FD_SIGNATURE_ALIGN (8UL)

/* TODO this should not have packed alignment, but it's misused everywhere */

union __attribute__((packed)) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangeable

  // Generic type specific accessors
  ulong ul  [ FD_HASH_FOOTPRINT / sizeof(ulong) ];
  uint  ui  [ FD_HASH_FOOTPRINT / sizeof(uint)  ];
  uchar uc  [ FD_HASH_FOOTPRINT ];
};

typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

FD_FN_PURE static inline int
fd_hash_eq( fd_hash_t const * a,
            fd_hash_t const * b ) {
  return 0==memcmp( a, b, sizeof(fd_hash_t) );
}

union fd_signature {
  uchar uc[ 64 ];
  ulong ul[  8 ];
};

typedef union fd_signature fd_signature_t;

FD_PROTOTYPES_BEGIN

#define fd_hash_check_zero(_x) (!((_x)->ul[0] | (_x)->ul[1] | (_x)->ul[2] | (_x)->ul[3]))
#define fd_hash_set_zero(_x)   {((_x)->ul[0] = 0); ((_x)->ul[1] = 0); ((_x)->ul[2] = 0); ((_x)->ul[3] = 0);}

#define fd_pubkey_new                     fd_hash_new
#define fd_pubkey_encode                  fd_hash_encode
#define fd_pubkey_destroy                 fd_hash_destroy
#define fd_pubkey_size                    fd_hash_size
#define fd_pubkey_check_zero              fd_hash_check_zero
#define fd_pubkey_set_zero                fd_hash_set_zero
#define fd_pubkey_walk                    fd_hash_walk
#define fd_pubkey_decode_inner            fd_hash_decode_inner
#define fd_pubkey_decode_footprint        fd_hash_decode_footprint
#define fd_pubkey_decode_footprint_inner  fd_hash_decode_footprint_inner
#define fd_pubkey_decode                  fd_hash_decode
#define fd_pubkey_eq                      fd_hash_eq

struct __attribute__((aligned(8UL))) fd_option_slot {
  uchar is_some;
  ulong slot;
};
typedef struct fd_option_slot fd_option_slot_t;

/* Index structure needed for transaction status (metadata) blocks */
struct fd_txnstatusidx {
    fd_ed25519_sig_t sig;
    ulong offset;
    ulong status_sz;
};
typedef struct fd_txnstatusidx fd_txnstatusidx_t;

/* IPv4 ***************************************************************/

typedef uint fd_gossip_ip4_addr_t;
#define FD_GOSSIP_IP4_ADDR_ALIGN alignof(fd_gossip_ip4_addr_t)

/* IPv6 ***************************************************************/

union fd_gossip_ip6_addr {
  uchar  uc[ 16 ];
  ushort us[  8 ];
  uint   ul[  4 ];
};

typedef union fd_gossip_ip6_addr fd_gossip_ip6_addr_t;
#define FD_GOSSIP_IP6_ADDR_ALIGN alignof(fd_gossip_ip6_addr_t)

int
fd_solana_vote_account_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );

int
fd_solana_vote_account_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );

void *
fd_solana_vote_account_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void
fd_solana_vote_account_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );

/* Transaction wrapper ************************************************/

/* fd_flamenco_txn_t is yet another fd_txn_t wrapper.
   This should die as soon as we have a better stubs generator. */

struct fd_flamenco_txn {
  union {
    uchar                  txn_buf[ FD_TXN_MAX_SZ ];
    __extension__ fd_txn_t txn[0];
  };
  uchar raw[ FD_TXN_MTU ];
  ulong raw_sz;
};

typedef struct fd_flamenco_txn fd_flamenco_txn_t;


static inline void
fd_flamenco_txn_new( fd_flamenco_txn_t * self FD_FN_UNUSED ) {}

static inline void
fd_flamenco_txn_destroy( fd_flamenco_txn_t const * self FD_FN_UNUSED ) {}

FD_FN_CONST static inline ulong
fd_flamenco_txn_size( fd_flamenco_txn_t const * self ) {
  return self->raw_sz;
}

static inline int
fd_flamenco_txn_encode( fd_flamenco_txn_t const * self,
                        fd_bincode_encode_ctx_t * ctx ) {
  return fd_bincode_bytes_encode( self->raw, self->raw_sz, ctx );
}


int FD_FN_UNUSED
fd_flamenco_txn_encode_global( fd_flamenco_txn_t const * self,
                               fd_bincode_encode_ctx_t * ctx );

void * FD_FN_UNUSED
fd_flamenco_txn_decode_global( void *                    mem,
                               fd_bincode_decode_ctx_t * ctx );

static inline void
fd_flamenco_txn_walk( void *                    w,
                      fd_flamenco_txn_t const * self,
                      fd_types_walk_fn_t        fun,
                      char const *              name,
                      uint                      level ) {

  static uchar const zero[ 64 ]={0};
  fd_txn_t const *   txn  = self->txn;
  uchar const *      sig0 = zero;

  if( FD_LIKELY( txn->signature_cnt > 0 ) )
    sig0 = fd_txn_get_signatures( txn, self->raw )[0];

  /* For now, just print the transaction's signature */
  fun( w, sig0, name, FD_FLAMENCO_TYPE_SIG512, "txn", level );
}

static inline ulong
fd_flamenco_txn_align( void ) {
  return alignof(fd_flamenco_txn_t);
}

static inline ulong
fd_flamenco_txn_footprint( void ) {
  return sizeof(fd_flamenco_txn_t);
}

int
fd_flamenco_txn_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );

int
fd_flamenco_txn_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );

void *
fd_flamenco_txn_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void
fd_flamenco_txn_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );

/* Represents the lamport balance associated with an account. */
typedef ulong fd_acc_lamports_t;

typedef struct fd_rust_duration fd_rust_duration_t;

void
fd_rust_duration_normalize ( fd_rust_duration_t * );

int
fd_rust_duration_footprint_validator ( fd_bincode_decode_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_types_custom */
