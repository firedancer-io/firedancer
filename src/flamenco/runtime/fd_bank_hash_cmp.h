#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_hash_cmp_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_hash_cmp_h

#include "../fd_flamenco_base.h"
#include "fd_blockstore.h"

struct fd_bank_hash_cmp_entry {
  ulong     slot;
  uint      hash;
  fd_hash_t ours;
  fd_hash_t theirs[8];
  ulong     stakes[8];
  ulong     cnt;
  int       overflow;
};
typedef struct fd_bank_hash_cmp_entry fd_bank_hash_cmp_entry_t;
#define MAP_NAME         fd_bank_hash_cmp_map
#define MAP_T            fd_bank_hash_cmp_entry_t
#define MAP_KEY          slot
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==ULONG_MAX)
#define MAP_LG_SLOT_CNT  (16) /* 0.25 fill ratio */
#include "../../util/tmpl/fd_map.c"

struct fd_bank_hash_cmp {
  fd_bank_hash_cmp_entry_t * map;
  ulong                      map_gaddr;
  ulong                      cnt;
  ulong                      watermark; /*  */
  ulong                      total_stake;
  volatile int               lock;
};
typedef struct fd_bank_hash_cmp fd_bank_hash_cmp_t;

FD_PROTOTYPES_BEGIN

static inline ulong
fd_bank_hash_cmp_align( void ) {
  return 128UL;
}

FD_FN_CONST static inline ulong
fd_bank_hash_cmp_footprint( void ) {
  /* clang-format off */
    return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
        fd_bank_hash_cmp_align(), sizeof(fd_bank_hash_cmp_t) ),
        fd_bank_hash_cmp_map_align(), fd_bank_hash_cmp_map_footprint() ),
        fd_bank_hash_cmp_align() );
  /* clang-format on */
}

void *
fd_bank_hash_cmp_new( void * mem );

fd_bank_hash_cmp_t *
fd_bank_hash_cmp_join( void * bank_hash_cmp );

void *
fd_bank_hash_cmp_leave( fd_bank_hash_cmp_t const * bank_hash_cmp );

void *
fd_bank_hash_cmp_delete( void * bank_hash_cmp );

void
fd_bank_hash_cmp_lock( fd_bank_hash_cmp_t * bank_hash_cmp );

void
fd_bank_hash_cmp_unlock( fd_bank_hash_cmp_t * bank_hash_cmp );

void
fd_bank_hash_cmp_insert( fd_bank_hash_cmp_t * bank_hash_cmp,
                         ulong                slot,
                         fd_hash_t const *    hash,
                         int                  ours,
                         ulong                stake );

/* Returns 1 on bank hash match (caller should move watermark forward),
          -1 on mismatch
           0 if we weren't able to compare yet */
int
fd_bank_hash_cmp_check( fd_bank_hash_cmp_t * bank_hash_cmp, ulong slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_hash_cmp_h */
