#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h

#include "../fd_flamenco_base.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

/* fd_progcache_rec_t is the fixed size header of a program cache entry
   object.  Entries are either non-executable (e.g. programs that failed
   verification) or executable.  Non-executable entry objects consist
   only of this header struct.  Executable entry objects are variable-
   sized and contain additional structures past this header (rodata/ROM
   segment, control flow metadata, ...). */

struct fd_progcache_rec {
  /* Slot number at which this cache entry was created.
     Matches the XID's slot number for in-preparation transactions. */
  ulong slot;

  uint entry_pc;
  uint text_cnt;
  uint text_off;
  uint text_sz;

  uint rodata_sz;

  uint calldests_off;  /* offset to sbpf_calldests map */
  uint rodata_off;     /* offset to rodata segment */

  /* SBPF version, SIMD-0161 */
  uchar sbpf_version;

  uint executable : 1;  /* is this an executable entry? */
  uint invalidate : 1;  /* if ==1, limits visibility of this entry to this slot */
};

typedef struct fd_progcache_rec fd_progcache_rec_t;

FD_PROTOTYPES_BEGIN

/* Accessors */

static inline uchar const *
fd_progcache_rec_rodata( fd_progcache_rec_t const * rec ) {
  return (uchar const *)rec + rec->rodata_off;
}

static inline fd_sbpf_calldests_t const *
fd_progcache_rec_calldests( fd_progcache_rec_t const * rec ) {
  return fd_sbpf_calldests_join( (void *)( (ulong)rec + rec->calldests_off ) );
}

/* Private APIs */

/* fd_progcache_rec_{align,footprint} give the params of backing memory
   of a progcache_rec object for the given ELF info.  If elf_info is
   NULL, implies a non-executable cache entry (sizeof(fd_progcache_rec_t)). */

FD_FN_CONST static inline ulong
fd_progcache_rec_align( void ) {
  return alignof(fd_progcache_rec_t);
}

FD_FN_PURE FD_FN_UNUSED static ulong
fd_progcache_rec_footprint( fd_sbpf_elf_info_t const * elf_info ) {
  if( !elf_info ) return sizeof(fd_progcache_rec_t); /* non-executable */

  int   has_calldests = !fd_sbpf_enable_stricter_elf_headers_enabled( elf_info->sbpf_version );
  ulong pc_max        = fd_ulong_max( 1UL, elf_info->text_cnt );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t) );
  if( has_calldests ) {
    l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( pc_max ) );
  }
  l = FD_LAYOUT_APPEND( l, 8UL, elf_info->bin_sz );
  return FD_LAYOUT_FINI( l, fd_progcache_rec_align() );
}

/* fd_progcache_rec_new creates a new excutable progcache_rec object.
   mem points to a memory region matching fd_progcache_rec_{align,
   footprint}.   Loads and verifies the given program data and returns
   the newly created executable object on success.  On failure, returns
   NULL (the caller may call fd_progcache_rec_new_nx instead). */

fd_progcache_rec_t *
fd_progcache_rec_new( void *                          mem,
                      fd_sbpf_elf_info_t const *      elf_info,
                      fd_sbpf_loader_config_t const * config,
                      ulong                           load_slot,
                      fd_features_t const *           features,
                      void const *                    progdata,
                      ulong                           progdata_sz,
                      void *                          scratch,
                      ulong                           scratch_sz );

/* fd_progcache_rec_new_nx creates a non-executable program_cache
   object.  fd_progcache_rec_t[1] is suitable for mem. */

fd_progcache_rec_t *
fd_progcache_rec_new_nx( void * mem,
                         ulong  load_slot );

/* fd_progcache_rec_delete destroys a progcache_rec object and returns
   the backing memory region to the caller. */

static inline void *
fd_progcache_rec_delete( fd_progcache_rec_t * rec ) {
  return rec;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_rec_h */
