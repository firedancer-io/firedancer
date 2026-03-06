#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h

#include "../../funk/fd_funk_base.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../fd_flamenco_base.h"
#include "../fd_rwlock.h"

/* fd_progcache_t is a join to a fd_progcache_shmem_t. */

struct fd_progcache_join; /* forward declaration */
typedef struct fd_progcache_join fd_progcache_join_t;

/* fd_progcache_rec_t is the fixed size header of a program cache entry
   object.  Entries are either non-executable (e.g. programs that failed
   verification) or executable.  Non-executable entry objects consist
   only of this header struct.  Executable entry objects are variable-
   sized and contain additional structures past this header (rodata/ROM
   segment, control flow metadata, ...). */

struct __attribute__((aligned(64))) fd_progcache_rec {
  /* Slot number at which this cache entry was created.
     Matches the XID's slot number for in-preparation transactions. */
  ulong slot;

  fd_funk_xid_key_pair_t pair;      /* Transaction id and record key pair */
  uint                   map_next;  /* Internal use by map */
  uint                   next_idx;  /* Record map index of next record in its transaction */
  uint                   prev_idx;  /* Record map index of previous record in its transaction */

  uint  data_max;    /* size of allocation */
  ulong data_gaddr;  /* wksp-base relative pointer to data */

  uint entry_pc;
  uint text_cnt;
  uint text_off;
  uint text_sz;

  uint rodata_sz;

  uint calldests_off;  /* offset to sbpf_calldests map */
  uint rodata_off;     /* offset to rodata segment */

  ushort      sbpf_version : 8; /* SBPF version, SIMD-0161 */
  ushort      executable   : 1; /* is this an executable entry? */
  ushort      invalidate   : 1; /* if ==1, limits visibility of this entry to this slot */
  ushort      exists       : 1; /* if ==0, record is dead, no longer in map, and awaiting cleanup */
  fd_rwlock_t lock;
};

typedef struct fd_progcache_rec fd_progcache_rec_t;

FD_STATIC_ASSERT( sizeof(fd_progcache_rec_t)==128, layout );

FD_PROTOTYPES_BEGIN

/* Accessors */

static inline uchar const *
fd_progcache_rec_rodata( fd_progcache_rec_t const * rec,
                         fd_wksp_t *                wksp ) {
  return fd_wksp_laddr_fast( wksp, rec->data_gaddr + rec->rodata_off );
}

static inline fd_sbpf_calldests_t const *
fd_progcache_rec_calldests( fd_progcache_rec_t const * rec,
                            fd_wksp_t *                wksp ) {
  return fd_sbpf_calldests_join( fd_wksp_laddr_fast( wksp, rec->data_gaddr + rec->calldests_off ) );
}

/* Private APIs */

/* fd_progcache_rec_{align,footprint} give the params of backing memory
   of a progcache_rec object for the given ELF info.  If elf_info is
   NULL, implies a non-executable cache entry (sizeof(fd_progcache_rec_t)). */

FD_FN_CONST static inline ulong
fd_progcache_val_align( void ) {
  return fd_sbpf_calldests_align();
}

FD_FN_PURE ulong
fd_progcache_val_footprint( fd_sbpf_elf_info_t const * elf_info );

void *
fd_progcache_val_alloc( fd_progcache_rec_t *  rec,
                        fd_progcache_join_t * join,
                        ulong                 val_align,
                        ulong                 val_footprint );

void
fd_progcache_val_free( fd_progcache_rec_t *  rec,
                       fd_progcache_join_t * join );

fd_progcache_rec_t *
fd_progcache_rec_load( fd_progcache_rec_t *            rec,
                       fd_wksp_t *                     wksp,
                       fd_sbpf_elf_info_t const *      elf_info,
                       fd_sbpf_loader_config_t const * config,
                       ulong                           load_slot,
                       fd_features_t const *           features,
                       void const *                    progdata,
                       ulong                           progdata_sz,
                       void *                          scratch,
                       ulong                           scratch_sz );

fd_progcache_rec_t *
fd_progcache_rec_nx( fd_progcache_rec_t * rec,
                     ulong                load_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h */
