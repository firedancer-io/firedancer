#ifndef HEADER_fd_src_flamenco_types_fd_types_custom_h
#define HEADER_fd_src_flamenco_types_fd_types_custom_h

#include "../fd_flamenco_base.h"
#include "fd_bincode.h"
#include "../../ballet/bmtree/fd_bmtree.h"

#define FD_SIGNATURE_ALIGN (8UL)

/* TODO this should not have packed alignment, but it's misused everywhere */

#define FD_HASH_FOOTPRINT   (32UL)
#define FD_HASH_ALIGN       (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN     FD_HASH_ALIGN
union __attribute__((packed)) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangeable

  // Generic type specific accessors
  ulong  ul  [ FD_HASH_FOOTPRINT / sizeof(ulong)  ];
  uint   ui  [ FD_HASH_FOOTPRINT / sizeof(uint)   ];
  ushort us  [ FD_HASH_FOOTPRINT / sizeof(ushort) ];
  uchar  uc  [ FD_HASH_FOOTPRINT                  ];
};
typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

FD_STATIC_ASSERT( sizeof(fd_hash_t) == sizeof(fd_bmtree_node_t), hash incompatibility ); /* various areas of Firedancer code use fd_hash_t as the type for merkle roots */

FD_FN_PURE static inline int
fd_hash_eq( fd_hash_t const * a,
            fd_hash_t const * b ) {
  return 0==memcmp( a, b, sizeof(fd_hash_t) );
}

FD_FN_PURE static inline int
fd_hash_eq1( fd_hash_t a,
             fd_hash_t b ) {
  return
    ( a.ul[0]==b.ul[0] ) & ( a.ul[1]==b.ul[1] ) &
    ( a.ul[2]==b.ul[2] ) & ( a.ul[3]==b.ul[3] );
}

union fd_signature {
  uchar uc[ 64 ];
  ulong ul[  8 ];
};
typedef union fd_signature fd_signature_t;


FD_FN_PURE
static inline int
fd_signature_eq( fd_signature_t const * a,
                 fd_signature_t const * b ) {
  return 0==memcmp( a, b, sizeof(fd_signature_t) );
}

FD_PROTOTYPES_BEGIN

#define fd_hash_check_zero(_x) (!((_x)->ul[0] | (_x)->ul[1] | (_x)->ul[2] | (_x)->ul[3]))
#define fd_hash_set_zero(_x)   {((_x)->ul[0] = 0); ((_x)->ul[1] = 0); ((_x)->ul[2] = 0); ((_x)->ul[3] = 0);}

#define fd_pubkey_check_zero              fd_hash_check_zero
#define fd_pubkey_set_zero                fd_hash_set_zero
#define fd_pubkey_eq                      fd_hash_eq

FD_PROTOTYPES_END

#define FD_DUMMY_ACCOUNT { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }
static const fd_pubkey_t FD_DUMMY_ACCOUNT_PUBKEY = { .uc = FD_DUMMY_ACCOUNT };

struct fd_vote_stake_weight {
  fd_pubkey_t vote_key; /* vote account pubkey */
  fd_pubkey_t id_key;   /* validator identity pubkey */
  ulong       stake;    /* total stake by vote account */
};
typedef struct fd_vote_stake_weight fd_vote_stake_weight_t;

#define SORT_NAME sort_vote_weights_by_stake_vote
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).vote_key.uc, (b).vote_key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

struct fd_stake_weight {
  fd_pubkey_t key;      /* validator identity pubkey */
  ulong       stake;    /* total stake by identity */
};
typedef struct fd_stake_weight fd_stake_weight_t;

#define SORT_NAME fd_stake_weight_key_sort
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).key.uc, (b).key.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

struct fd_fee_rate_governor {
  ulong target_lamports_per_signature;
  ulong target_signatures_per_slot;
  ulong min_lamports_per_signature;
  ulong max_lamports_per_signature;
  uchar burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;

struct fd_inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double unused;
};
typedef struct fd_inflation fd_inflation_t;

#endif /* HEADER_fd_src_flamenco_types_fd_types_custom_h */
