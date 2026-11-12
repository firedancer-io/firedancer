#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_jit_heat_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_jit_heat_h

/* fd_jit_heat.h is the shared table the jitmap tile sweeps to find hot
   programs.  It has one row per exec tile.  A row holds, per program
   cache record index, the compute units that tile has spent
   interpreting the record (wrapping), and the feature set of the bank
   the tile last interpreted under, which jitmap needs to compile for
   that record's feature_slot.

   Each exec tile writes only its own row.  jitmap only reads. */

#include "../../features/fd_features.h"

#define FD_JIT_HEAT_MAGIC (0xf17eda2c3e71ea70UL)
#define FD_JIT_HEAT_ALIGN (4096UL)

struct __attribute__((aligned(64))) fd_jit_heat_row {
  ulong         seq;          /* odd while features is being written */
  ulong         feature_slot; /* ULONG_MAX until first written */
  fd_features_t features;
  uint          cu[] __attribute__((aligned(64)));
};

typedef struct fd_jit_heat_row fd_jit_heat_row_t;

struct __attribute__((aligned(FD_JIT_HEAT_ALIGN))) fd_jit_heat {
  ulong magic;
  ulong row_cnt;
  ulong rec_max;
  ulong row_sz;
};

typedef struct fd_jit_heat fd_jit_heat_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_jit_heat_align( void ) {
  return FD_JIT_HEAT_ALIGN;
}

FD_FN_CONST static inline ulong
fd_jit_heat_row_sz( ulong rec_max ) {
  return fd_ulong_align_up( sizeof(fd_jit_heat_row_t) + rec_max*sizeof(uint), FD_JIT_HEAT_ALIGN );
}

FD_FN_CONST static inline ulong
fd_jit_heat_footprint( ulong row_cnt,
                       ulong rec_max ) {
  return sizeof(fd_jit_heat_t) + row_cnt*fd_jit_heat_row_sz( rec_max );
}

FD_FN_PURE static inline fd_jit_heat_row_t *
fd_jit_heat_row( fd_jit_heat_t * heat,
                 ulong           row_idx ) {
  return (fd_jit_heat_row_t *)( (ulong)heat + sizeof(fd_jit_heat_t) + row_idx*heat->row_sz );
}

static inline void *
fd_jit_heat_new( void * mem,
                 ulong  row_cnt,
                 ulong  rec_max ) {
  if( FD_UNLIKELY( !mem || !fd_ulong_is_aligned( (ulong)mem, FD_JIT_HEAT_ALIGN ) ) ) return NULL;
  fd_jit_heat_t * heat = mem;
  memset( heat, 0, fd_jit_heat_footprint( row_cnt, rec_max ) );
  heat->row_cnt = row_cnt;
  heat->rec_max = rec_max;
  heat->row_sz  = fd_jit_heat_row_sz( rec_max );
  for( ulong i=0UL; i<row_cnt; i++ ) fd_jit_heat_row( heat, i )->feature_slot = ULONG_MAX;
  FD_COMPILER_MFENCE();
  heat->magic = FD_JIT_HEAT_MAGIC;
  return mem;
}

static inline fd_jit_heat_t *
fd_jit_heat_join( void * mem ) {
  fd_jit_heat_t * heat = mem;
  if( FD_UNLIKELY( !heat || heat->magic!=FD_JIT_HEAT_MAGIC ) ) return NULL;
  return heat;
}

/* fd_jit_heat_row_features_publish replaces the row's feature set.
   Only the row's owner may call this. */

static inline void
fd_jit_heat_row_features_publish( fd_jit_heat_row_t *   row,
                                  ulong                 feature_slot,
                                  fd_features_t const * features ) {
  ulong seq = row->seq;
  FD_VOLATILE( row->seq ) = seq+1UL;
  FD_COMPILER_MFENCE();
  row->features     = *features;
  row->feature_slot = feature_slot;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( row->seq ) = seq+2UL;
}

/* fd_jit_heat_row_features_query copies the row's feature set into
   features if it was published for feature_slot.  Returns 1 on
   success, 0 if the row holds another feature_slot or was being
   written. */

static inline int
fd_jit_heat_row_features_query( fd_jit_heat_row_t const * row,
                                ulong                     feature_slot,
                                fd_features_t *           features ) {
  ulong seq = FD_VOLATILE_CONST( row->seq );
  if( FD_UNLIKELY( seq&1UL ) ) return 0;
  FD_COMPILER_MFENCE();
  ulong slot = FD_VOLATILE_CONST( row->feature_slot );
  *features  = row->features;
  FD_COMPILER_MFENCE();
  return ( FD_VOLATILE_CONST( row->seq )==seq ) & ( slot==feature_slot );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_jit_heat_h */
