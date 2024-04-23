#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_hash_cmp_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_hash_cmp_h

#include "../fd_flamenco_base.h"

struct fd_bank_hash_cmp_entry {
  ulong     slot;
  int       rooted;
  uint      hash;
  fd_hash_t ours;
  fd_hash_t theirs;
};
typedef struct fd_bank_hash_cmp_entry fd_bank_hash_cmp_entry_t;
#define MAP_NAME fd_bank_hash_cmp_map
#define MAP_T    fd_bank_hash_cmp_entry_t
#define MAP_KEY  slot
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_bank_hash_cmp {
  fd_bank_hash_cmp_entry_t * map;
  volatile int               lock;
  ulong                      slot; /* slot # of last bank hash we compared */
  ulong                      mismatch_cnt;
};
typedef struct fd_bank_hash_cmp fd_bank_hash_cmp_t;

FD_PROTOTYPES_BEGIN

static inline ulong
fd_bank_hash_cmp_align( void ) {
  return 128UL;
}

static inline ulong
fd_bank_hash_cmp_footprint( int lg_slot_cnt ) {
  /* clang-format off */
    return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
        fd_bank_hash_cmp_align(), sizeof(fd_bank_hash_cmp_t) ),
        fd_bank_hash_cmp_map_align(), fd_bank_hash_cmp_map_footprint( lg_slot_cnt ) ),
        fd_bank_hash_cmp_align() );
  /* clang-format on */
}

void *
fd_bank_hash_cmp_new( void * mem, int lg_slot_cnt );

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
                         int                  ours );

/* Return 1 if it was able to check rooted bank hash, otherwise 0 (still waiting). */
int
fd_bank_hash_cmp_check( fd_bank_hash_cmp_t * bank_hash_cmp, ulong slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_hash_cmp_h */
