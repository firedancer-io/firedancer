#include "fd_alloc.h"
#include "fd_alloc_cfg.h"
#include "../tile/fd_tile.h"
#include "../sanitize/fd_asan.h"
/* Note: this will still compile on platforms without FD_HAS_ATOMIC.  It
   should only be used single threaded in those use cases.  (The code
   does imitate at a very low level the operations required by
   FD_HAS_ATOMIC but this is to minimize amount of code differences to
   test.) */

/* sizeclass APIs *****************************************************/

/* fd_alloc_preferred_sizeclass returns the tightest fitting sizeclass
   for the given footprint.  The caller promises there is at least one
   possible size class (i.e. that footprint is in
   [0,FD_ALLOC_FOOTPRINT_SMALL_THRESH].  The return will be in
   [0,FD_ALLOC_SIZECLASS_CNT). */

FD_STATIC_ASSERT( 64UL<FD_ALLOC_SIZECLASS_CNT && FD_ALLOC_SIZECLASS_CNT<=128UL, limits );

static inline ulong
fd_alloc_preferred_sizeclass( ulong footprint ) {
  ulong l = 0UL;
  ulong h = FD_ALLOC_SIZECLASS_CNT-1UL;

  /* Fixed count loop without early exit to make it easy for compiler to
     unroll and nominally eliminate all branches for fast, highly
     deterministic performance with no consumption of BTB resources.
     Note that 7 assumes 64<=FD_ALLOC_SIZECLASS_CNT-1<128.  FIXME: check
     the compiler is doing the right thing here with unrolling and
     branch elimination. */

  for( ulong r=0UL; r<7UL; r++ ) {

    /* At this point sizeclasses<l are known to be inadequate and
       sizeclasses>=h are known to be suitable.  Sizeclasses in [l,h)
       have not been tested. */

    ulong m = (l+h)>>1; /* Note: no overflow for reasonable sizeclass_cnt and l<=m<=h */
    int   c = (((ulong)fd_alloc_sizeclass_cfg[ m ].block_footprint)>=footprint);
    l = fd_ulong_if( c, l, m+1UL ); /* cmov */
    h = fd_ulong_if( c, m, h     ); /* cmov */
  }

  return h;
}

/* fd_alloc_preferred_sizeclass_cgroup returns preferred sizeclass
   concurrency group for a join with the given cgroup_idx.  The caller
   promises sizeclass is in [0,FD_ALLOC_SIZECLASS_CNT). */

static inline ulong
fd_alloc_preferred_sizeclass_cgroup( ulong sizeclass,
                                     ulong cgroup_idx ) {
  return cgroup_idx & (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask;
}

/* fd_alloc_block_set *************************************************/

/* A fd_alloc_block_set specifies a set of blocks in a superblock. */

#define SET_NAME fd_alloc_block_set
#define SET_TYPE ulong
#define SET_MAX  64
#include "../tmpl/fd_smallset.c"

/* fd_alloc_block_set_{add,sub} inserts / removes blocks to / from
   block set pointed to by set.  The caller promises that blocks are not
   / are already in the block set.  This operation is a compiler fence.
   Further, if FD_HAS_ATOMIC, this operation is done atomically.
   Returns the value of the block_set just before the operation.  Note:
   atomic add/sub has slightly better asm on x86 than atomic or/and/nand
   (compiler quality issue, not an architecture issue) and generates the
   same results provided the caller promises are met. */

#if FD_HAS_ATOMIC

static inline fd_alloc_block_set_t
fd_alloc_block_set_add( fd_alloc_block_set_t * set,
                        fd_alloc_block_set_t   blocks ) {
  fd_alloc_block_set_t ret;
  FD_COMPILER_MFENCE();
  ret = FD_ATOMIC_FETCH_AND_ADD( set, blocks );
  FD_COMPILER_MFENCE();
  return ret;
}

static inline fd_alloc_block_set_t
fd_alloc_block_set_sub( fd_alloc_block_set_t * set,
                        fd_alloc_block_set_t   blocks ) {
  fd_alloc_block_set_t ret;
  FD_COMPILER_MFENCE();
  ret = FD_ATOMIC_FETCH_AND_SUB( set, blocks );
  FD_COMPILER_MFENCE();
  return ret;
}

#else

static inline fd_alloc_block_set_t
fd_alloc_block_set_add( fd_alloc_block_set_t * set,
                        fd_alloc_block_set_t   blocks ) {
  fd_alloc_block_set_t ret;
  FD_COMPILER_MFENCE();
  ret = FD_VOLATILE_CONST( *set );
  FD_VOLATILE( *set ) = ret + blocks;
  FD_COMPILER_MFENCE();
  return ret;
}

static inline fd_alloc_block_set_t
fd_alloc_block_set_sub( fd_alloc_block_set_t * set,
                        fd_alloc_block_set_t   blocks ) {
  fd_alloc_block_set_t ret;
  FD_COMPILER_MFENCE();
  ret = FD_VOLATILE_CONST( *set );
  FD_VOLATILE( *set ) = ret - blocks;
  FD_COMPILER_MFENCE();
  return ret;
}

#endif

/* fd_alloc_superblock ************************************************/

#define FD_ALLOC_SUPERBLOCK_ALIGN (16UL) /* Guarantees free_blocks and next_gaddr aligned are on the same cache line */

struct __attribute__((aligned(FD_ALLOC_SUPERBLOCK_ALIGN))) fd_alloc_superblock {
  fd_alloc_block_set_t free_blocks; /* which blocks in this superblock are allocated */
  ulong                next_gaddr;  /* if on the inactive superblock stack, next inactive superblock or NULL, ignored o.w. */
  /* FIXME: could put a cgroup hint in the lsb of next gaddr given
     it is already aligned 16. */
  /* Storage for blocks follows */
};

typedef struct fd_alloc_superblock fd_alloc_superblock_t;

/* fd_alloc ***********************************************************/

/* FD_ALLOC_MAGIC is an ideally unique number that specifies the precise
   memory layout of a fd_alloc */

#if FD_HAS_X86 /* Technically platforms with 16B compare-exchange */

#define FD_ALLOC_MAGIC (0xF17EDA2C37A110C1UL) /* FIRE DANCER ALLOC version 1 */

#define VOFF_NAME      fd_alloc_vgaddr
#define VOFF_TYPE      uint128
#define VOFF_VER_WIDTH 64
#include "../tmpl/fd_voff.c"

#else /* Platforms without 16B compare-exchange */

#define FD_ALLOC_MAGIC (0xF17EDA2C37A110C0UL) /* FIRE DANCER ALLOC version 0 */

/* TODO: Overaligning superblocks on these targets to get a wider
   version width */

#define VOFF_NAME      fd_alloc_vgaddr
#define VOFF_TYPE      ulong
#define VOFF_VER_WIDTH 4
#include "../tmpl/fd_voff.c"

#endif

struct __attribute__((aligned(FD_ALLOC_ALIGN))) fd_alloc {
  ulong magic;    /* ==FD_ALLOC_MAGIC */
  ulong wksp_off; /* Offset of the first byte of this structure from the start of the wksp */
  ulong tag;      /* tag that will be used by this allocator.  Positive. */

  /* Padding to 128 byte alignment here */

  /* active_slot[ sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup ] is the
     gaddr of the active superblock for sizeclass allocations done by a
     member of concurrency group cgroup or 0 if there is no active
     superblock currently for that sizeclass,cgroup pair.

     inactive_stack[ sizeclass ] is top of inactive stack for sizeclass
     or 0 if the stack is empty.  This is versioned offset with a 64-bit
     version number in the least significant bits and a 64-bit gaddr in
     the upper bits.  At 64-bits wide, note that version number reuse
     will not occur on any human timescales.  (FIXME: consider using a
     ulong to be more portable to platforms without 128-bit CAS support.
     E.g. 20-bit version and a 44-bit gaddr and restricting maximum
     supported workspace to ~16 TiB.)

     Note that this is compact but organized such that concurrent
     operations from different cgroups are unlikely to create false
     sharing. */

  ulong active_slot[ FD_ALLOC_SIZECLASS_CNT*(FD_ALLOC_JOIN_CGROUP_HINT_MAX+1UL) ] __attribute__((aligned(128UL)));

  /* Padding to 128 byte alignment here */

  fd_alloc_vgaddr_t inactive_stack[ FD_ALLOC_SIZECLASS_CNT ] __attribute__((aligned(128UL)));
};

/* fd_alloc_private_wksp returns the wksp backing alloc.  Assumes alloc
   is a non-NULL pointer in the caller's address space to the fd_alloc
   (not a join handle). */

FD_FN_PURE static inline fd_wksp_t *
fd_alloc_private_wksp( fd_alloc_t * alloc ) {
  return (fd_wksp_t *)(((ulong)alloc) - alloc->wksp_off);
}

/* fd_alloc_private_active_slot_replace replaces the value currently in
   the slot pointed to by active_slot with new_superblock_gaddr and
   returns the superblock_gaddr previously in there.  This is a compiler
   fence.  If FD_HAS_ATOMIC, this will be done atomically. */

static inline ulong
fd_alloc_private_active_slot_replace( ulong * active_slot,
                                      ulong   new_superblock_gaddr ) {
  ulong old_superblock_gaddr;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  old_superblock_gaddr = FD_ATOMIC_XCHG( active_slot, new_superblock_gaddr );
# else
  old_superblock_gaddr = FD_VOLATILE_CONST( *active_slot );
  FD_VOLATILE( *active_slot ) = new_superblock_gaddr;
# endif
  FD_COMPILER_MFENCE();
  return old_superblock_gaddr;
}

/* fd_alloc_private_inactive_stack_push pushes superblock at the
   workspace global address superblock_gaddr in workspace wksp onto the
   stack inactive stack.  This is a compiler fence.  If FD_HAS_ATOMIC,
   this will be done atomically. */

static inline void
fd_alloc_private_inactive_stack_push( fd_alloc_vgaddr_t * inactive_stack,
                                      fd_wksp_t *         wksp,
                                      ulong               superblock_gaddr ) {
  fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

  for(;;) {

    /* Read the top of the inactive stack. */

    fd_alloc_vgaddr_t old;
    FD_COMPILER_MFENCE();
    old = FD_VOLATILE_CONST( *inactive_stack );
    FD_COMPILER_MFENCE();

    ulong top_ver   = (ulong)fd_alloc_vgaddr_ver( old );
    ulong top_gaddr = (ulong)fd_alloc_vgaddr_off( old );

    /* Try to push the top of the inactive stack */

    fd_alloc_vgaddr_t new = fd_alloc_vgaddr( top_ver+1UL, superblock_gaddr );

    FD_COMPILER_MFENCE();
    FD_VOLATILE( superblock->next_gaddr ) = top_gaddr;
    FD_COMPILER_MFENCE();

#   if FD_HAS_ATOMIC
    if( FD_LIKELY( FD_ATOMIC_CAS( inactive_stack, old, new )==old ) ) break;
#   else
    if( FD_LIKELY( FD_VOLATILE_CONST( *inactive_stack )==old ) ) { FD_VOLATILE( *inactive_stack ) = new; break; }
#   endif

    /* Hmmm ... that failed ... try again */

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();
}

/* fd_alloc_private_inactive_stack_pop pops superblock off the top of
   the inactive stack.  Returns the non-zero wksp superblock gaddr of
   the popped stack top on success or 0 on failure (i.e. inactive stack
   is empty).  This is a compiler fence.  If FD_HAS_ATOMIC, this will be
   done atomically. */

static inline ulong
fd_alloc_private_inactive_stack_pop( fd_alloc_vgaddr_t * inactive_stack,
                                     fd_wksp_t *         wksp ) {
  ulong top_gaddr;

  for(;;) {

    /* Read the top of the inactive stack.  Return if the inactive stack
       is empty. */

    fd_alloc_vgaddr_t old;
    FD_COMPILER_MFENCE();
    old = FD_VOLATILE_CONST( *inactive_stack );
    FD_COMPILER_MFENCE();

    /**/  top_gaddr = (ulong)fd_alloc_vgaddr_off( old );
    ulong top_ver   = (ulong)fd_alloc_vgaddr_ver( old );
    if( FD_UNLIKELY( !top_gaddr ) ) break;

    /* Try to pop the top of the inactive stack. */

    fd_alloc_superblock_t * top = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, top_gaddr );

    ulong next_gaddr;
    FD_COMPILER_MFENCE();
    next_gaddr = FD_VOLATILE_CONST( top->next_gaddr );
    FD_COMPILER_MFENCE();

    fd_alloc_vgaddr_t new = fd_alloc_vgaddr( top_ver+1UL, next_gaddr );

#   if FD_HAS_ATOMIC
    if( FD_LIKELY( FD_ATOMIC_CAS( inactive_stack, old, new )==old ) ) break;
#   else
    if( FD_LIKELY( FD_VOLATILE_CONST( *inactive_stack )==old ) ) { FD_VOLATILE( *inactive_stack ) = new; break; }
#   endif

    /* Hmmm ... that failed ... try again */

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  return top_gaddr;
}

/* fd_alloc_hdr_t *****************************************************/

/* An fd_alloc_hdr_t is a small header prepended to an allocation that
   describes the allocation.  Because fd_alloc supports arbitrary
   allocation alignments, these headers might be stored at unaligned
   positions. */

typedef uint fd_alloc_hdr_t;

/* FD_ALLOC_HDR_LARGE_* give the fd_alloc_hdr_t used for mallocs done by
   the allocator of last resort (i.e. fd_wksp_alloc).  The least
   significant 7 bits must be FD_ALLOC_SIZECLASS_LARGE so that free can
   detect an allocation is done by that allocator.  The most significant
   24 bits are a magic number to help with analytics.  Bit 7 indicates
   whether this allocation is direct user allocation or holds a
   superblock that aggregates many small allocations together. */

#define FD_ALLOC_HDR_LARGE_DIRECT     ((fd_alloc_hdr_t)(0xFDA11C00U | (fd_alloc_hdr_t)FD_ALLOC_SIZECLASS_LARGE))
#define FD_ALLOC_HDR_LARGE_SUPERBLOCK ((fd_alloc_hdr_t)(0xFDA11C80U | (fd_alloc_hdr_t)FD_ALLOC_SIZECLASS_LARGE))

/* fd_alloc_hdr_load loads the header for the allocation whose first
   byte is at laddr in the caller's address space.  The header will be
   observed at some point of time between when this call was made and
   returned and this implies that the allocation at laddr must be at
   least until the caller stops using the header. */

FD_FN_PURE static inline fd_alloc_hdr_t
fd_alloc_hdr_load( void const * laddr ) {
  return FD_LOAD( fd_alloc_hdr_t, ((ulong)laddr) - sizeof(fd_alloc_hdr_t) );
}

/* fd_alloc_hdr_sizeclass returns the sizeclass of an allocation
   described by hdr.  This will be in [0,FD_ALLOC_SIZECLASS_CNT) or
   FD_ALLOC_SIZECLASS_LARGE.  sizeclass==FD_ALLOC_SIZECLASS_LARGE
   indicates that the allocation was done via fd_wksp_alloc directly.
   Small allocations are clustered into superblocks for performance and
   packing efficiency.  All allocations in a superblock are from the
   same sizeclass. */

FD_FN_CONST static inline ulong fd_alloc_hdr_sizeclass( fd_alloc_hdr_t hdr ) { return (ulong)(hdr & 127U); }

/* fd_alloc_hdr_{superblock,block} return details about a small
   allocation whose first byte is at laddr in the caller's address space
   and is described by hdr.  In particular:

   fd_alloc_hdr_superblock( hdr, laddr ) returns the location in the
   caller's address space of the superblock containing the allocation.
   The lifetime of a superblock is at least as long as the allocation at
   laddr.

   fd_alloc_hdr_block_idx( hdr ) returns the superblock block index of the
   block containing the allocation.  Note that this will be in:
     [0,fd_alloc_sizeclass_block_cnt(sizeclass))
   and that:
     fd_alloc_sizeclass_block_cnt(sizeclass)<=fd_alloc_block_set_max()<=64. */

FD_FN_CONST static inline fd_alloc_superblock_t *
fd_alloc_hdr_superblock( fd_alloc_hdr_t hdr,
                         void *         laddr ) {
  return (fd_alloc_superblock_t *)(((ulong)laddr) - ((ulong)(hdr >> 13)));
}

FD_FN_CONST static inline ulong fd_alloc_hdr_block_idx( fd_alloc_hdr_t hdr ) { return (ulong)((hdr >> 7) & 63U); }

/* fd_alloc_hdr_is_large returns 1 if hdr is for a large allocation and
   0 if not.  fd_alloc_hdr_sizeclass( hdr )==FD_ALLOC_SIZECLASS_LARGE
   also works but does not test the magic number in the most significant
   bits. */

FD_FN_CONST static inline int
fd_alloc_hdr_is_large( fd_alloc_hdr_t hdr ) {
  return fd_uint_clear_bit( hdr, 7 )==FD_ALLOC_HDR_LARGE_DIRECT;
}

/* fd_alloc_hdr_large_is_superblock returns 1 if hdr (which is assumed
   to be for a large allocation) is for a large allocation that holds a
   superblock. */

FD_FN_CONST static inline int
fd_alloc_hdr_large_is_superblock( fd_alloc_hdr_t hdr ) {
  return fd_uint_extract_bit( hdr, 7 );
}

/* fd_alloc_hdr_store stores a fd_alloc_hdr_t describing a small
   sizeclass allocation contained within block of superblock in the
   sizeof(fd_alloc_hdr_t) bytes immediately preceding the byte pointed
   to by laddr in the caller's address space.  The caller promises that
   these bytes are somewhere within the block.

   fd_alloc_hdr_store_large similarly stores a fd_alloc_hdr_t describing
   a large allocation. */

static inline void *
fd_alloc_hdr_store( void *                  laddr,
                    fd_alloc_superblock_t * superblock,
                    ulong                   block_idx,
                    ulong                   sizeclass ) {
  FD_STORE( fd_alloc_hdr_t, ((ulong)laddr) - sizeof(fd_alloc_hdr_t),
            (fd_alloc_hdr_t)( ((((ulong)laddr) - ((ulong)superblock)) << 13) |    /* Bits 31:13 - 19 bit: superblock offset */
                              (block_idx                              <<  7) |    /* Bits 12: 7 -  6 bit: block */
                              sizeclass                                      ) ); /* Bits  6: 0 -  7 bit: sizeclass */
  return laddr;
}

static inline void *
fd_alloc_hdr_store_large( void * laddr,
                          int    is_superblock ) { /* in [0,1] */
  FD_STORE( fd_alloc_hdr_t, ((ulong)laddr) - sizeof(fd_alloc_hdr_t),
            FD_ALLOC_HDR_LARGE_DIRECT | (((fd_alloc_hdr_t)is_superblock) << 7) );
  return laddr;
}

/* Misc ***************************************************************/

/* fd_alloc_private_join_alloc returns the local address of the alloc
   for a join. */

FD_FN_CONST fd_alloc_t *
fd_alloc_private_join_alloc( fd_alloc_t * join ) {
  return (fd_alloc_t *)(((ulong)join) & ~FD_ALLOC_JOIN_CGROUP_HINT_MAX);
}

/* Constructors *******************************************************/

ulong
fd_alloc_align( void ) {
  return alignof(fd_alloc_t);
}

ulong
fd_alloc_footprint( void ) {
  return sizeof(fd_alloc_t);
}

ulong
fd_alloc_superblock_footprint(void){
  return sizeof(fd_alloc_superblock_t);
}

void *
fd_alloc_new( void * shmem,
              ulong  tag ) {

  /* Check input arguments */

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, alignof(fd_alloc_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be in a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( !tag ) ) {
    FD_LOG_WARNING(( "bad tag" ));
    return NULL;
  }

  fd_alloc_t * alloc = (fd_alloc_t *)shmem;
  fd_memset( alloc, 0, sizeof(fd_alloc_t) );

  alloc->wksp_off = (ulong)alloc - (ulong)wksp;
  alloc->tag      = tag;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( alloc->magic ) = FD_ALLOC_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_alloc_t *
fd_alloc_join( void * shalloc,
               ulong  cgroup_hint ) {
  fd_alloc_t * alloc = shalloc;

  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_WARNING(( "NULL shalloc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)alloc, alignof(fd_alloc_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shalloc" ));
    return NULL;
  }

  if( FD_UNLIKELY( alloc->magic!=FD_ALLOC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  #ifdef FD_WKSP_ASAN
    fd_asan_poison(alloc, fd_alloc_footprint());
  #endif
  return fd_alloc_join_cgroup_hint_set( alloc, cgroup_hint );
}

void *
fd_alloc_leave( fd_alloc_t * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }
  #ifdef FD_WKSP_ASAN
   fd_asan_unpoison(join, fd_alloc_footprint());
  #endif
  return fd_alloc_private_join_alloc( join );
}

void *
fd_alloc_delete( void * shalloc ) {

  if( FD_UNLIKELY( !shalloc ) ) {
    FD_LOG_WARNING(( "NULL shalloc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shalloc, alignof(fd_alloc_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shalloc" ));
    return NULL;
  }

  fd_alloc_t * alloc = (fd_alloc_t *)shalloc;

  if( FD_UNLIKELY( alloc->magic!=FD_ALLOC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( alloc->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  /* Clean up as much as we can.  For each sizeclass, delete all active
     superblocks and all inactive superblocks.  We will not be able
     cleanup any superblocks that are fully allocated (and any
     outstanding large allocations) as we rely on the application to
     implicitly track them (because they nominally will eventually call
     free on them).  So hopefully the application did a good job and
     cleaned up all their outstanding stuff before calling delete. */

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {

    ulong cgroup_cnt = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask + 1UL;
    for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
      ulong superblock_gaddr =
        fd_alloc_private_active_slot_replace( alloc->active_slot + sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup_idx, 0UL );
      if( FD_UNLIKELY( superblock_gaddr ) )
        fd_alloc_free( alloc, (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr ) );
    }

    fd_alloc_vgaddr_t * inactive_stack = alloc->inactive_stack + sizeclass;
    for(;;) {
      ulong superblock_gaddr = fd_alloc_private_inactive_stack_pop( inactive_stack, wksp );
      if( FD_LIKELY( !superblock_gaddr ) ) break;
      fd_alloc_free( alloc, (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr ) );
    }

  }

  return shalloc;
}

fd_wksp_t *
fd_alloc_wksp( fd_alloc_t * join ) {
  return FD_LIKELY( join ) ? fd_alloc_private_wksp( fd_alloc_private_join_alloc( join ) ) : NULL;
}

ulong
fd_alloc_tag( fd_alloc_t * join ) {
  return FD_LIKELY( join ) ? fd_alloc_private_join_alloc( join )->tag : 0UL;
}

void *
fd_alloc_malloc_at_least( fd_alloc_t * join,
                          ulong        align,
                          ulong        sz,
                          ulong *      max ) {

  if( FD_UNLIKELY( !max ) ) return NULL;

  /* Handle default align, NULL alloc, 0 size, non-power-of-two align
     and unreasonably large sz.  footprint has room for fd_alloc_hdr_t,
     sz bytes with enough padding to allow for the arbitrary alignment
     of blocks in a superblock.  Note that footprint is guaranteed not
     to overflow if align is a power of 2 as align at most 2^63 and
     sizeof is 4 and we abort is align is not a power of 2.  So we don't
     need to do elaborate overflow checking. */

  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );
 
  align = fd_ulong_if( !align, FD_ALLOC_MALLOC_ALIGN_DEFAULT, align );

  ulong footprint = sz + sizeof(fd_alloc_hdr_t) + align - 1UL;

  if( FD_UNLIKELY( (!alloc) | (!fd_ulong_is_pow2( align )) | (!sz) | (footprint<=sz) ) ) {
    *max = 0UL;
    return NULL;
  }
  #ifdef FD_WKSP_ASAN
   fd_asan_unpoison(alloc,footprint);
  #endif
  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  /* At this point, alloc is non-NULL and backed by wksp, align is a
     power-of-2, footprint is a reasonable non-zero value.  If the
     footprint is large, just allocate the memory directly, prepend the
     appropriate header and return.  TODO: consider clearing alignment
     padding for better alloc parameter recovery in diagnostics here? */

  if( FD_UNLIKELY( footprint > FD_ALLOC_FOOTPRINT_SMALL_THRESH ) ) {

    ulong glo;
    ulong ghi;
    ulong wksp_gaddr = fd_wksp_alloc_at_least( wksp, 1UL, footprint, alloc->tag, &glo, &ghi );
    if( FD_UNLIKELY( !wksp_gaddr ) ) {
      *max = 0UL;
      return NULL;
    }

    ulong alloc_gaddr = fd_ulong_align_up( wksp_gaddr + sizeof(fd_alloc_hdr_t), align );
    *max = (ghi - glo) - (alloc_gaddr - wksp_gaddr);
    return fd_alloc_hdr_store_large( fd_wksp_laddr_fast( wksp, alloc_gaddr ), 0 /* !sb */ );
  }

  /* At this point, the footprint is small.  Determine the preferred
     sizeclass for this allocation and the preferred active superblock
     to use for this sizeclass and join. */

  ulong sizeclass = fd_alloc_preferred_sizeclass( footprint );
  ulong cgroup    = fd_alloc_preferred_sizeclass_cgroup( sizeclass, fd_alloc_join_cgroup_hint( join ) );

  ulong * active_slot = alloc->active_slot + sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup;

  /* Try to get exclusive access to the preferred active superblock.
     Note that all all active superblocks have at least one free block.

     TODO: consider doing something test-and_test-and-set?  E.g.:
       superblock_gaddr = FD_VOLATILE_CONST( *active_slot );
       if( FD_LIKELY( superblock_gaddr ) ) superblock_gaddr = fd_alloc_replace_active( active_slot, 0UL );
     This would avoid an atomic operation if there currently isn't an
     active superblock for this sizeclass and cgroup. */

  ulong superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, 0UL );

  /* At this point, if superblock_gaddr is non-zero, we have exclusive
     access to the superblock and only we can allocate blocks from it.
     (Other threads could free blocks to it concurrently though.)

     If superblock_gaddr is zero, there was no preferred active
     superblock for this sizeclass,cgroup pair when we looked.  So, we
     try to pop the inactive superblock stack for this sizeclass.  Note
     that all inactive superblocks also have at least one free block.

     If that fails, we try to allocate a new superblock to hold this
     allocation.  If we are able to do so, obviously the new superblock
     would have at least one free block for this allocation.  (Yes,
     malloc calls itself recursively.  The base case is the large
     allocation above.  Note that we expand out the base case explicitly
     here so we can distinguish user large allocations from gigantic
     superblock allocations in analytics without having to change the
     APIs or use the public API as a wrapper.)

     If that fails, we are in trouble and fail (we are either out of
     memory or have too much wksp fragmentation). */
  // FD_LOG_WARNING(("Y: %lu %lu | %lu %lu %lu %lu", align, sz, footprint, sizeclass, cgroup, superblock_gaddr ));

  if( FD_UNLIKELY( !superblock_gaddr ) ) {

    superblock_gaddr = fd_alloc_private_inactive_stack_pop( alloc->inactive_stack + sizeclass, wksp );

    // FD_LOG_WARNING(("X: %lu %lu | %lu %lu %lu %lu", align, sz, footprint, sizeclass, cgroup, superblock_gaddr ));
    if( FD_UNLIKELY( !superblock_gaddr ) ) {

      fd_alloc_superblock_t * superblock;

      ulong superblock_footprint = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].superblock_footprint;
      if( FD_UNLIKELY( superblock_footprint > FD_ALLOC_FOOTPRINT_SMALL_THRESH ) ) {

        ulong wksp_footprint = superblock_footprint + sizeof(fd_alloc_hdr_t) + FD_ALLOC_SUPERBLOCK_ALIGN - 1UL;
        ulong wksp_gaddr     = fd_wksp_alloc( wksp, 1UL, wksp_footprint, alloc->tag );
        if( FD_UNLIKELY( !wksp_gaddr ) ) {
          *max = 0UL;
          return NULL;
        }
        superblock_gaddr = fd_ulong_align_up( wksp_gaddr + sizeof(fd_alloc_hdr_t), FD_ALLOC_SUPERBLOCK_ALIGN );
        superblock       = (fd_alloc_superblock_t *)
          fd_alloc_hdr_store_large( fd_wksp_laddr_fast( wksp, superblock_gaddr ), 1 /* sb */ );
        #ifdef FD_WKSP_ASAN
          fd_asan_unpoison(superblock,superblock_footprint);
        #endif

      } else {

        /* TODO: consider having user facing API wrap an internal API so
           that recursive calls don't have to do redundant error
           trapping?

           TODO: consider using at_least semantics to adapt the actual
           size of the superblock to the location it is stored
           (currently should be irrelevant as the sizeclasses are
           designed to tightly nest). */

        superblock = fd_alloc_malloc( join, FD_ALLOC_SUPERBLOCK_ALIGN, superblock_footprint );
        if( FD_UNLIKELY( !superblock ) ) {
          *max = 0UL;
          return NULL;
        }
        superblock_gaddr = fd_wksp_gaddr_fast( wksp, superblock );

      }

      FD_COMPILER_MFENCE();
      FD_VOLATILE( superblock->free_blocks ) = fd_ulong_mask_lsb( (int)(uint)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt );
      FD_VOLATILE( superblock->next_gaddr  ) = 0UL;
      FD_COMPILER_MFENCE();

    }
  }

  /* At this point, we have a superblock with space for at least one
     allocation and only we can allocate blocks from it.  Other threads
     could free blocks in this superblock concurrently though.  As such,
     we can non-atomically find a set bit in free_blocks (there will be
     at least one and no other thread will clear it behind our back) but
     we must atomically clear the bit we found so we don't mess up the
     other bits that might be concurrently set by free. */

  fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

  fd_alloc_block_set_t free_blocks;
  FD_COMPILER_MFENCE();
  free_blocks = FD_VOLATILE_CONST( superblock->free_blocks );
  FD_COMPILER_MFENCE();

  ulong                block_idx = fd_alloc_block_set_first( free_blocks );
  fd_alloc_block_set_t block     = fd_alloc_block_set_ele( block_idx );

  free_blocks = fd_alloc_block_set_sub( &superblock->free_blocks, block );

  /* At this point, free_blocks gives the set of free blocks in the
     superblock immediately before the allocation occurred. */

  if( FD_LIKELY( free_blocks!=block ) ) {

    /* At this point, we know the superblock has at least one
       allocated block in it (the one we just allocated) and one free
       block in it.  And this will hold true until we put this
       superblock back into circulation.  Specifically, nobody can free
       the block we just allocated until we return to tell them about it
       and nobody can allocate any remaining free blocks until we get
       this superblock back into circulation.  To get this superblock
       back into circulation, we make it the active superblock for this
       sizeclass,cgroup pair. */

    ulong displaced_superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, superblock_gaddr );

    /* And if this displaced a previously active superblock (e.g.
       another thread made an different superblock the active one while
       we were doing the above), we add the displaced superblock to the
       sizeclass's inactive superblocks.  Note that any such displaced
       superblock also has at least one free block in it (the active
       superblock always has at least one free block) that nobody can
       allocate from as, at this point, it is not in circulation.  Thus,
       pushing it onto the superblock's inactive stack will preserve the
       invariant that all inactive superblocks have at least one free
       block. */

    if( FD_UNLIKELY( displaced_superblock_gaddr ) )
      fd_alloc_private_inactive_stack_push( alloc->inactive_stack + sizeclass, wksp, displaced_superblock_gaddr );

  } //else {

    /* The superblock had no more free blocks immediately after the
       allocation occurred.  We should not make this superblock the
       preferred superblock or push it onto the sizeclass's nonfull
       superblock stack; it would break the invariants that all
       superblocks in circulation for a sizeclass have at least one
       free block.

       And, as this superblock had no free blocks, we don't need to
       track the superblock anyway as malloc can't use the superblock
       until some of the blocks in it have been freed.  As such, this
       superblock will not be used in a malloc until after the next call
       to free on a block in this superblock returns this superblock to
       circulation.  Note that this superblock will have at least one
       allocated block until after this function returns (the block we
       just allocated) and thus cannot ever be considered as a deletion
       candidate until after this function returns and this allocation
       is freed.

       As discussed in free below, we could update a superblock cgroup
       hint here (such that the when the superblock goes back into
       circulation, it will be put into circulation as the active
       superblock for this cgroup to encourage for additional mallocs
       from this thread for good spatial locality).  This doesn't need
       to be atomic.  Even though a concurrent free on another thread
       might get this into superblock into circulation before this
       executes (and thus also have other mallocs occurred that changed
       the active_hint), it doesn't matter.  So long as the hint is a
       sane value at all points in time, free will work fine. */

  //}

  /* Carve the requested allocation out of the newly allocated block,
     prepend the allocation header for use by free and return.  TODO:
     considering clearing alignment padding for better alloc parameter
     recovery in diagnostics here? */

  ulong block_footprint = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;
  ulong block_laddr     = (ulong)superblock + sizeof(fd_alloc_superblock_t) + block_idx*block_footprint;
  ulong alloc_laddr     = fd_ulong_align_up( block_laddr + sizeof(fd_alloc_hdr_t), align );

  *max = block_footprint - (alloc_laddr - block_laddr);
  #ifdef FD_WKSP_ASAN
   fd_asan_poison(superblock,fd_alloc_superblock_footprint());
  #endif
  return fd_alloc_hdr_store( (void *)alloc_laddr, superblock, block_idx, sizeclass );
}

void
fd_alloc_free( fd_alloc_t * join,
               void *       laddr ) {

  /* Handle NULL alloc and/or NULL laddr */

  fd_alloc_t * alloc  = fd_alloc_private_join_alloc( join );
  if( FD_UNLIKELY( (!alloc) | (!laddr) ) ) return;

  /* At this point, we have a non-NULL alloc and a pointer to the first
     byte to an allocation done by it.  Load the allocation header and
     extract the sizeclass.  If the sizeclass indicates this is a large
     allocation, use fd_wksp_free to free this allocation (note that
     fd_wksp_free works for any byte within the wksp allocation). */

  fd_alloc_hdr_t hdr       = fd_alloc_hdr_load( laddr );
  ulong          sizeclass = fd_alloc_hdr_sizeclass( hdr );

  if( FD_UNLIKELY( sizeclass==FD_ALLOC_SIZECLASS_LARGE ) ) {
    fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );
    fd_wksp_free( wksp, fd_wksp_gaddr_fast( wksp, laddr ) );
    #ifdef FD_WKSP_ASAN
     fd_asan_poison(alloc,fd_alloc_footprint());
    #endif
    return;
  }

  /* At this point, we have a small allocation.  Determine the
     superblock and block index from the header and then free the block. */

  fd_alloc_superblock_t * superblock  = fd_alloc_hdr_superblock( hdr, laddr );
  ulong                   block_idx   = fd_alloc_hdr_block_idx( hdr );
  fd_alloc_block_set_t    block       = fd_alloc_block_set_ele( block_idx );
  fd_alloc_block_set_t    free_blocks = fd_alloc_block_set_add( &superblock->free_blocks, block );
  
  #ifdef FD_WKSP_ASAN
   fd_asan_unpoison(superblock,fd_alloc_superblock_footprint());
  #endif

  /* At this point, free_blocks is the set of free blocks just before
     the free. */

  ulong free_cnt = fd_alloc_block_set_cnt( free_blocks );
  if( FD_UNLIKELY( !free_cnt ) ) {

    /* The superblock containing this block had no free blocks
       immediately before we freed the allocation.  Thus, at this point,
       nobody can allocate any blocks from this superblock (the
       superblock is neither an active superblock nor on the inactive
       stack as per the note in malloc above) and we need to get the
       superblock back into circulation for reuse.  It is okay if other
       threads concurrently free other blocks in this superblock while
       we are doing this (they know the superblock is either in
       circulation or is being put into circulation).

       Since there is at least one free block in the superblock and
       nobody can allocate from it until it is circulation, putting it
       into circulation preserves the invariant that all superblocks in
       circulation have at least one free block.

       We have a bunch of options for putting this superblock back into
       circulation:

       - By pushing it onto the inactive stack
       - By making it the active superblock of the caller's cgroup
       - By making it the active superblock of the cgroup that most did
         the most recent malloc from it.
       - By making it the active superblock based on explicitly provided
         hint.
       - ...

       The first option is simplest to implement and balanced between
       common use cases single threaded, malloc/free pairs have thread
       affinity, and pipelined use cases.  (E.g. single threaded will
       take an extra time to hop from inactive and active and potential
       has slightly worse overallocation, similar story for paired.
       Cache affinity in these two cases might be slightly degraded from
       empty superblocks hopping between concurrency groups via the
       inactive stack, pipelined naturally gets the page back to the
       malloc-ing thread albeit with a brief hop through the inactive
       stack though).

       The second option is about as simple and optimizes the
       single/threaded and paired use cases as this thread is also the
       thread likely the same thread that malloc'd this.  Pipelined is
       marginally worse as the superblock will have to take two hops
       before it gets reused again (from the free-ing thread active
       superblock to the inactive stack to the malloc-ing active
       superblock).

       The third and fourth options can simultaneously get all options
       optimized but they require extra plumbing (either under the hood
       as per the note in malloc above from to the caller to get the
       extra context).

       Currently we do the second option for simplicity and optimal
       behaviors in the single threaded and paired use cases. */

    fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

    ulong   cgroup      = fd_alloc_preferred_sizeclass_cgroup( sizeclass, fd_alloc_join_cgroup_hint( join ) );
    ulong * active_slot = alloc->active_slot + sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup;

    ulong displaced_superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, fd_wksp_gaddr_fast( wksp, superblock ) );

    /* If this displaced an already active superblock, we need to push
       the displaced superblock onto the inactive stack (note that the
       superblock cannot be the same as the currently active superblock
       because the superblock was not in circulation before). */

    if( FD_UNLIKELY( displaced_superblock_gaddr ) )
      fd_alloc_private_inactive_stack_push( alloc->inactive_stack + sizeclass, wksp, displaced_superblock_gaddr );

    #ifdef FD_WKSP_ASAN
      fd_asan_poison(alloc,fd_alloc_footprint());
      fd_asan_poison(superblock,fd_alloc_superblock_footprint()); 
    #endif
    return;
  }

  /* This point, we know the superblock had some free blocks before our
     free and thus is currently in circulation. */

  free_cnt++; /* Number of free blocks immediately after above free */

  ulong block_cnt = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt;
  if( FD_UNLIKELY( free_cnt==block_cnt ) ) {

    /* None of the blocks were in use after the above free.  We might
       consider freeing it to reclaim space for other sizeclasses or
       large allocations.  But we don't mind having a few totally empty
       superblocks in circulation for a sizeclass as this prevents
       things like:

         addr = malloc(sz);
         free(addr);
         addr = malloc(sz);
         free(addr)
         ...
         addr = malloc(sz);
         free(addr)

       from repeatedly needing to invoke malloc recursively to recreate
       superblock hierarchies that were prematurely freed.

       Regardless, since this superblock is in circulation, we can't be
       sure it is safe to delete because something might be malloc-ing
       from it concurrently.  Thus, we are going to keep this superblock
       in circulation as is.

       But, since we know we have at least 1 completely empty superblock
       in circulation now, to prevent the unbounded accumulation of
       completely empty superblocks, we will try to get an inactive
       superblock and, if that is empty, delete that.

       This is pretty tricky as it is possible other threads are
       concurrently trying to pop the inactive stack to do a malloc.  If
       we actually unmapped the memory here, such a thread could seg
       fault if it stalls after it reads the top of the stack but before
       it queries the top for the next_gaddr (and we'd have to use
       another strategy).  But that is not an issue here as the
       underlying wksp memory is still mapped post-deletion regardless.

       Likewise, though the post deletion top->next_gaddr read will get
       a stale value in this scenario, it highly likely will not be
       injected into the inactive_stack because the CAS will detect that
       inactive_stack top has changed and fail.

       And, lastly, we version inactive_stack top such that, even if
       somehow we had a thread stall in pop after reading
       top->next_gaddr / other threads do other operations that
       ultimately keep top the same change the value of top->next_gaddr
       / stalled thread resumes, the version number on the stalled
       thread will be wrong cause the CAS to fail.  (There is a
       theoretical risk of version number reuse but the version number
       is wide enough to make that risk zero on any practical
       timescale.) */

    #ifdef FD_WKSP_ASAN
      fd_asan_poison(alloc,fd_alloc_footprint());
      fd_asan_poison(superblock,fd_alloc_superblock_footprint());
    #endif
    fd_wksp_t * wksp                     = fd_alloc_private_wksp( alloc );
    ulong       deletion_candidate_gaddr = fd_alloc_private_inactive_stack_pop( alloc->inactive_stack + sizeclass, wksp );

    if( FD_UNLIKELY( !deletion_candidate_gaddr ) ) return; /* No deletion_candidate, unclear branch prob */

    fd_alloc_superblock_t * deletion_candidate = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, deletion_candidate_gaddr );

    ulong deletion_candidate_free_blocks;
    FD_COMPILER_MFENCE();
    deletion_candidate_free_blocks = FD_VOLATILE_CONST( deletion_candidate->free_blocks );
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( fd_alloc_block_set_cnt( deletion_candidate_free_blocks )==block_cnt ) ) /* Candidate empty -> delete it */
      fd_alloc_free( join, deletion_candidate );
    else /* Candidate not empty -> return it to circulation */
      fd_alloc_private_inactive_stack_push( alloc->inactive_stack + sizeclass, wksp, deletion_candidate_gaddr );

    return;
  }
}

void
fd_alloc_compact( fd_alloc_t * join ) {
  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_WARNING(( "bad join" ));
    return;
  }

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  /* We scan each sizeclass (in monotonically increasing order) for
     completely empty superblocks that thus can be freed.  This has the
     pleasant side effect that, as smaller empty superblocks get freed,
     it can potentially allow for any larger superblocks in which they
     are nested to be subsequently freed.  If no other operations are
     running concurrently, any remaining gigantic superblocks should
     contain at least one application allocation somewhere in them. */

  for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {
    ulong               block_cnt      = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt;
    ulong               cgroup_cnt     = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask + 1UL;
    fd_alloc_vgaddr_t * inactive_stack = alloc->inactive_stack + sizeclass;

    /* For each active superblock in this sizeclass */

    for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
      ulong * active_slot      = alloc->active_slot + sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup_idx;
      ulong   superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, 0UL );
      if( !superblock_gaddr ) continue; /* application dependent branch prob */

      fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

      /* At this point, we have atomically acquired the cgroup_idx's
         active superblock, there is no active superblock for
         cgroup_idx, and it has at least one free block.  Since the
         superblock is out of circulation for malloc, nobody will malloc
         anything from this superblock behind our back.  And if this
         superblock is completely empty, nobody will call free on any
         blocks in this superblock behind our back.  Thus we can free
         this superblock safely.

         If there are some blocks still allocated, we put the superblock
         back into circulation (we know from the above it still has at
         least one free block, preserving the invariant).  This might
         displace a superblock that another thread made active behind
         our back.  We push any such superblock block onto the inactive
         stack (it also will have at least one free block for the same
         reasons). */

      if( fd_alloc_block_set_cnt( superblock->free_blocks )==block_cnt ) fd_alloc_free( join, superblock );
      else {
        ulong displaced_superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, superblock_gaddr );
        if( FD_UNLIKELY( displaced_superblock_gaddr ) )
          fd_alloc_private_inactive_stack_push( inactive_stack, wksp, displaced_superblock_gaddr );
      }
    }

    /* Drain the inactive stack for this sizeclass.  All empty
       superblocks found will be freed (safe for the same reasons as
       above).  All remaining superblocks will be pushed onto a local
       stack (and every one will have at least one free block it while
       there for the same reasons).  After the inactive stack drain, we
       drain the local stack back into the inactive stack to get all
       these remaining superblocks back into circulation (also safe for
       the same reasons) and with same relative ordering (not required).
       We technically don't need to use a lockfree push / pop for the
       local stack but no sense in implementing a second version for
       this mostly diagnostic / teardown oriented use case. */

    fd_alloc_vgaddr_t local_stack[1];

    local_stack[0] = fd_alloc_vgaddr( 0UL, 0UL );

    for(;;) {
      ulong superblock_gaddr = fd_alloc_private_inactive_stack_pop( inactive_stack, wksp );
      if( !superblock_gaddr ) break; /* application dependent branch prob */
      fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

      if( fd_alloc_block_set_cnt( superblock->free_blocks )==block_cnt ) fd_alloc_free( join, superblock );
      else fd_alloc_private_inactive_stack_push( local_stack, wksp, superblock_gaddr );
    }

    for(;;) {
      ulong superblock_gaddr = fd_alloc_private_inactive_stack_pop( local_stack, wksp );
      if( !superblock_gaddr ) break; /* application dependent branch prob */

      fd_alloc_private_inactive_stack_push( inactive_stack, wksp, superblock_gaddr );
    }
  }
}

#include "../wksp/fd_wksp_private.h"

int
fd_alloc_is_empty( fd_alloc_t * join ) {
  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );
  if( FD_UNLIKELY( !alloc ) ) return 0;

  fd_alloc_compact( join );

  /* At this point (assuming no concurrent operations on this alloc),
     all remaining large allocations contain at least one user
     allocation.  Thus if there are any large allocs remaining for this
     alloc, we know the alloc is not empty.  Since the wksp alloc that
     holds the alloc itself might use the tag the used for large
     allocations, we handle that as well.  We do this in a brute force
     way to avoid taking a lock (note that this calculation should
     really only be done as non-performance critical diagnostic and then
     on a quiescent system). */

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  ulong alloc_lo  = fd_wksp_gaddr_fast( wksp, alloc );
  ulong alloc_hi  = alloc_lo + FD_ALLOC_FOOTPRINT;
  ulong alloc_tag = alloc->tag;

  ulong                     part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

  ulong i;
  for( i=0UL; i<part_max; i++ ) {
    if( FD_LIKELY( pinfo[ i ].tag!=alloc_tag ) ) continue; /* optimize for no leak case */
    ulong gaddr_lo = pinfo[ i ].gaddr_lo;
    ulong gaddr_hi = pinfo[ i ].gaddr_hi;
    if( FD_UNLIKELY( !((gaddr_lo<=alloc_lo) & (alloc_hi<=gaddr_hi)) ) ) break; /* optimize for no leak case */
  }

  return i==part_max;
}

/**********************************************************************/

#include <stdio.h>

#define TRAP(x) do { int _cnt = (x); if( _cnt<0 ) { return _cnt; } cnt += _cnt; } while(0)

/* fd_alloc_superblock_fprintf pretty prints to the given stream
   exhaustive details about the current state of the given superblock in
   wksp at superblock_gaddr.  The superblock's parameters are given by
   sizeclass, block_cnt, block_footprint.  Diagnostics will be accumulated
   ctr.  Returns behavior matches fprintf return behavior (i.e. the
   number of characters output to stream or a negative error code).
   This is meant to be called exclusively from fd_alloc_fprintf and does
   no error trapping of its inputs. */

static int
fd_alloc_superblock_fprintf( fd_wksp_t * wksp,             /* non-NULL */
                             ulong       superblock_gaddr, /* valid gaddr for wksp */
                             ulong       sizeclass,        /* valid sizeclass */
                             ulong       block_cnt,        /* matches sizeclass cfg */
                             ulong       block_footprint,  /* matches sizeclass cfg */
                             FILE *      stream,           /* non-NULL */
                             ulong *     ctr ) {           /* non-NULL, room for 2 */
  int cnt = 0;

  /* Print the block header */

  fd_alloc_superblock_t * superblock = fd_wksp_laddr_fast( wksp, superblock_gaddr );

  fd_alloc_block_set_t free_blocks = superblock->free_blocks;

  ulong msb = fd_ulong_shift_right( free_blocks, (int)block_cnt ); /* Note: block_cnt==64 possible */
  if( FD_UNLIKELY( msb ) ) ctr[0]++;
  TRAP( fprintf( stream, "free_blocks 0x%lx (%s)\n", free_blocks, msb==0UL ? "good" : "bad" ) );

  /* For each block */

  for( ulong block_idx=0UL; block_idx<block_cnt; block_idx++ ) {
    ulong gaddr_lo = superblock_gaddr + sizeof(fd_alloc_superblock_t) + block_idx*block_footprint;
    ulong gaddr_hi = gaddr_lo + block_footprint;

    if( fd_alloc_block_set_test( free_blocks, block_idx ) ) { /* Free block */

    //TRAP( fprintf( stream, "\t\t\tblock %2lu: gaddr %s:%lu-%s:%lu, malloc_est -, align_est -, sz_est - (free)\n",
    //               block_idx, wksp->name, gaddr_lo, wksp->name, gaddr_hi-1UL ) );

    } else { /* Used block */

      /* Search the partition for a plausible fd_alloc_hdr_t.  This
         process nearly identical to the one described for large
         allocations below. */

      for( ulong align_est = 1UL << fd_ulong_find_msb( block_footprint - sizeof(fd_alloc_hdr_t) );;) {
        ulong   gaddr_est = fd_ulong_align_up( gaddr_lo + sizeof(fd_alloc_hdr_t), align_est );
        uchar * laddr_est = (uchar *)fd_wksp_laddr_fast( wksp, gaddr_est );
        fd_alloc_hdr_t hdr = FD_LOAD( fd_alloc_hdr_t, laddr_est - sizeof(fd_alloc_hdr_t) );

        if( fd_alloc_hdr_sizeclass ( hdr )           ==sizeclass &&
            fd_alloc_hdr_block_idx ( hdr )           ==block_idx &&
            fd_alloc_hdr_superblock( hdr, laddr_est )==superblock ) {
          ulong sz_est = block_footprint - sizeof(fd_alloc_hdr_t) - align_est + 1UL;
          TRAP( fprintf( stream, "\t\t\tblock %2lu: gaddr %s:%lu-%s:%lu, malloc_est %s:%lu, align_est %lu, sz_est %lu\n",
                         block_idx, wksp->name, gaddr_lo, wksp->name, gaddr_hi-1UL, wksp->name, gaddr_est, align_est, sz_est ) );
          ctr[1]++;
          break;
        }

        align_est >>= 1;
        if( FD_UNLIKELY( !align_est ) ) {
          TRAP( fprintf( stream, "\t\t\tblock %2lu: gaddr %s:%lu-%s:%lu, malloc_est -, align est -, sz_est - (bad)\n",
                         block_idx, wksp->name, gaddr_lo, wksp->name, gaddr_hi-1UL ) );
          ctr[0]++;
          break;
        }
      }
    }
  }

  return cnt;
}

/* fd_alloc_fprintf pretty prints to the given stream exhaustive details
   about the current state of the fd_alloc corresponding to the current
   local join.  As this function is typically for debugging,
   end-of-program diagnostics, etc, this function assumes there are no
   concurrent operations on the fd_alloc while running.  Note also it
   might not be able to find all small allocations and determine precise
   details about allocations in general.  It will however be able to
   find all large allocations assuming the user tagged the structure
   properly (and that includes finding all the gigantic superblocks in
   which all individual small allocations are contained).  Return
   behavior matches fprintf return behavior (i.e. the number of
   characters printed to stream or a negative error code). */

int
fd_alloc_fprintf( fd_alloc_t * join,
                  FILE *       stream ) {
  if( FD_UNLIKELY( !stream ) ) return 0; /* NULL stream, can't print anything */

  int cnt = 0;

  ulong ctr[6];
  ctr[0] = 0UL; /* errors detected */
  ctr[1] = 0UL; /* small alloc found */
  ctr[2] = 0UL; /* wksp partitions used */
  ctr[3] = 0UL; /* wksp bytes used */
  ctr[4] = 0UL; /* wksp partitions used for large alloc */
  ctr[5] = 0UL; /* wksp bytes used for large alloc */

  fd_alloc_t * alloc       = fd_alloc_private_join_alloc( join );
  ulong        cgroup_hint = fd_alloc_join_cgroup_hint  ( join );

  if( FD_UNLIKELY( !alloc ) ) { /* NULL join passed */

    TRAP( fprintf( stream, "alloc: gaddr -, join_cgroup_hint %lu, magic 0x0 (bad)\n", cgroup_hint ) );
    ctr[0]++;

  } else { /* Normal join */

    /* Count the space used by alloc metadata. */

    ctr[2] += 1UL;
    ctr[3] += FD_ALLOC_FOOTPRINT;

    fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

    /* Print the summary header */

    TRAP( fprintf( stream, "alloc: gaddr %s:%lu, join_cgroup_hint %lu, magic 0x%lx (%s)\n",
                   wksp->name, fd_wksp_gaddr_fast( wksp, alloc ), cgroup_hint,
                   alloc->magic, alloc->magic==FD_ALLOC_MAGIC ? "good" : "bad" ) );
    if( FD_UNLIKELY( alloc->magic!=FD_ALLOC_MAGIC ) ) ctr[0]++;

    /* Print known details about each sizeclass */

    ulong block_footprint = 0UL;
    for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {
      ulong block_footprint_prev = block_footprint;
      /**/  block_footprint      = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;

      ulong superblock_footprint = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].superblock_footprint;
      ulong block_cnt            = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt;
      ulong cgroup_cnt           = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask + 1UL;

      fd_alloc_vgaddr_t inactive_stack = alloc->inactive_stack[ sizeclass ];

      ulong inactive_stack_ver   = (ulong)fd_alloc_vgaddr_ver( inactive_stack );
      ulong inactive_stack_gaddr = (ulong)fd_alloc_vgaddr_off( inactive_stack );

      /* Omit sizeclasses that have no superblocks in circulation */

      int do_print = !!inactive_stack_gaddr;
      if( !do_print ) {
        for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
          if( alloc->active_slot[ sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup_idx ] ) {
            do_print = 1;
            break;
          }
        }
        if( !do_print ) continue;
      }

      /* Print size class header */

      TRAP( fprintf( stream,
                     "\tsizeclass %lu: superblock_footprint %lu, block_footprint %lu-%lu, block_cnt %lu, cgroup_cnt %lu\n",
                     sizeclass, superblock_footprint, block_footprint_prev+1UL, block_footprint, block_cnt, cgroup_cnt ) );

      /* Print inactive stack top */

      TRAP( fprintf( stream, "\t\tinactive_stack: gaddr %s:%lu, version %lu\n",
                     wksp->name, inactive_stack_gaddr, inactive_stack_ver ) );

      /* Print active superblock details */

      ulong superblock_gaddr;

      for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
        superblock_gaddr = alloc->active_slot[ sizeclass + FD_ALLOC_SIZECLASS_CNT*cgroup_idx ];
        if( !superblock_gaddr ) {
        //TRAP( fprintf( stream, "\t\tcgroup 2lu active superblock -, next -\n", cgroup_idx ) );
          continue;
        }
        ulong next_gaddr = ((fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr))->next_gaddr;
        TRAP( fprintf( stream, "\t\tsuperblock: cgroup_idx %lu, gaddr %s:%lu, next %s:%lu (ignored), ",
                       cgroup_idx, wksp->name, superblock_gaddr, wksp->name, next_gaddr ) );
        TRAP( fd_alloc_superblock_fprintf( wksp, superblock_gaddr, sizeclass, block_cnt, block_footprint, stream, ctr ) );
      }

      /* Print inactive superblock details */

      superblock_gaddr = inactive_stack_gaddr;
      while( superblock_gaddr ) {
        ulong next_gaddr = ((fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr))->next_gaddr;
        TRAP( fprintf( stream, "\t\tsuperblock: cgroup_idx -, gaddr %s:%lu, next %s:%lu, ",
                       wksp->name, superblock_gaddr, wksp->name, next_gaddr ) );
        TRAP( fd_alloc_superblock_fprintf( wksp, superblock_gaddr, sizeclass, block_cnt, block_footprint, stream, ctr ) );
        superblock_gaddr = next_gaddr;
      }
    }

    /* Scan the wksp partition table for partitions that match this
       allocation tag.  Like the is_empty diagnostic, we do this in a
       brute force way that is not algo efficient to avoid taking a
       lock. */

    ulong wksp_lo   = wksp->gaddr_lo;
    ulong wksp_hi   = wksp->gaddr_hi;

    ulong alloc_lo  = fd_wksp_gaddr_fast( wksp, alloc );
    ulong alloc_hi  = alloc_lo + FD_ALLOC_FOOTPRINT;
    ulong alloc_tag = alloc->tag;

    ulong                     part_max = wksp->part_max;
    fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

    ulong i;
    for( i=0UL; i<part_max; i++ ) {
      if( pinfo[ i ].tag!=alloc_tag ) continue; /* skip ones that don't match */
      ulong gaddr_lo = pinfo[ i ].gaddr_lo;
      ulong gaddr_hi = pinfo[ i ].gaddr_hi;
      if( FD_UNLIKELY( (wksp_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=wksp_hi) ) ) break; /* malformed */

      /* If the user used the same tag for both the alloc metadata and the
         alloc allocations, skip the metadata partition */

      if( FD_UNLIKELY( (gaddr_lo<=alloc_lo) & (alloc_hi<=gaddr_lo) ) ) continue; /* skip partition containing metadata */

      ulong part_footprint = gaddr_hi - gaddr_lo;

      if( FD_UNLIKELY( part_footprint<=sizeof(fd_alloc_hdr_t) ) ) continue; /* skip obviously not an allocation */

      /* Search the partition for a plausible fd_alloc_hdr_t.  There
         will be at least one if the partition isn't bad.  We scan
         potential alignments in reverse order such that noise in the
         alignment padding from older and less aligned large allocs will
         not trigger the detection logic.  It is still possible for this
         logic to spuriously fire if the user just happened to have some
         data that looked like a suitable header (hence these are
         estimates).  The estimates could be improved if we clear zero
         padding before the headers as noted above at a greater time
         overhead in fd_alloc and scanned alignments forward.  Once we
         have a plausible location and alignment, we can compute bounds
         to how large a size was used.  We use the upper bound the size
         estimate for simplicity (it would take a lot more space and
         time overhead in normal operation to track this explicitly). */

      for( ulong align_est = 1UL << fd_ulong_find_msb( part_footprint-sizeof(fd_alloc_hdr_t) );;) {

        /* Look at a potential header location */

        ulong   gaddr_est = fd_ulong_align_up( gaddr_lo + sizeof(fd_alloc_hdr_t), align_est );
        uchar * laddr_est = (uchar *)fd_wksp_laddr_fast( wksp, gaddr_est );
        fd_alloc_hdr_t hdr = FD_LOAD( fd_alloc_hdr_t, laddr_est - sizeof(fd_alloc_hdr_t) );

        /* If it matches what a header at this location should be,
           print out the estimated allocation details. */

        if( fd_alloc_hdr_is_large( hdr ) ) {
          int is_superblock = fd_alloc_hdr_large_is_superblock( hdr );

          ulong sz_est = part_footprint - sizeof(fd_alloc_hdr_t) - align_est + 1UL;
          TRAP( fprintf( stream, "\tlarge: gaddr %s:%lu-%s:%lu, malloc_est %s:%lu, align_est %lu, sz_est %lu %s\n",
                         wksp->name, gaddr_lo, wksp->name, gaddr_hi-1UL, wksp->name, gaddr_est, align_est, sz_est,
                         is_superblock ? "(superblock)" : "(large)" ) );
          ctr[2]++;
          ctr[3] += part_footprint;
          ctr[4] += fd_ulong_if( is_superblock, 0UL, 1UL            );
          ctr[5] += fd_ulong_if( is_superblock, 0UL, part_footprint );

          break;
        }

        /* Nope ... try the next.  If no more potential locations, the
           partition is corrupt. */

        align_est >>= 1;
        if( FD_UNLIKELY( !align_est ) ) {
          TRAP( fprintf( stream, "\tlarge: gaddr %s:%lu-%s:%lu, malloc_est -, align_est -, sz_est - (bad)\n",
                         wksp->name, gaddr_lo, wksp->name, gaddr_hi-1UL ) );
          ctr[0]++;
          break;
        }
      }
    }
  }

  /* Print summary statistics */

  TRAP( fprintf( stream,
                 "\terrors detected       %21lu\n"
                 "\tsmall alloc found     %21lu\n"
                 "\twksp part cnt         %21lu\n"
                 "\twksp used             %21lu\n"
                 "\tlarge alloc cnt       %21lu\n"
                 "\tlarge alloc wksp used %21lu\n",
                 ctr[0], ctr[1], ctr[2], ctr[3], ctr[4], ctr[5] ) );

  return cnt;
}

/* Virtual function table
   TODO type pun functions instead of using virtual wrappers? */

static void *
fd_alloc_malloc_virtual( void * self,
                         ulong  align,
                         ulong  sz ) {
  return fd_alloc_malloc( fd_alloc_join_cgroup_hint_set( (fd_alloc_t *)self, fd_tile_idx() ), align, sz );
}

static void
fd_alloc_free_virtual( void * self,
                       void * addr ) {
  fd_alloc_free( fd_alloc_join_cgroup_hint_set( (fd_alloc_t *)self, fd_tile_idx() ), addr );
}

const fd_valloc_vtable_t
fd_alloc_vtable = {
  .malloc = fd_alloc_malloc_virtual,
  .free   = fd_alloc_free_virtual
};

#undef TRAP
