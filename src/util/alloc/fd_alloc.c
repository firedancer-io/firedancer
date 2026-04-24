#include "fd_alloc.h"
#include "fd_alloc_cfg.h"
#include "../sanitize/fd_sanitize.h"

/* Note: this will still compile on platforms without FD_HAS_ATOMIC.  It
   should only be used single threaded in those use cases.  (The code
   does imitate at a very low level the operations required by
   FD_HAS_ATOMIC but this is to minimize amount of code differences to
   test.) */

/* If FD_ALLOC_STYLE is non-zero, this will clear any padding needed to
   align a user allocation.  This is not strictly necessary and can slow
   down fd_alloc_malloc.  But it does make diagnostics like
   fd_alloc_fprintf more accurate. */

#ifndef FD_ALLOC_STYLE
#define FD_ALLOC_STYLE 0
#endif

/* sizeclass APIs *****************************************************/

/* fd_alloc_preferred_sizeclass returns the tightest fitting sizeclass
   for the given footprint.  The caller promises there is at least one
   possible size class (i.e. that footprint is in
   [0,FD_ALLOC_FOOTPRINT_SMALL_THRESH]).  The return will be in
   [0,FD_ALLOC_SIZECLASS_CNT). */

static inline ulong
fd_alloc_preferred_sizeclass( ulong footprint ) {
  ulong l = 0UL;
  ulong h = FD_ALLOC_SIZECLASS_CNT-1UL;

  /* Fixed count loop without early exit to make it easy for compiler to
     unroll and nominally eliminate all branches for fast, highly
     deterministic performance with no consumption of BTB resources.
     FIXME: check the compiler is doing the right thing here with
     unrolling and branch elimination. */

  for( ulong r=0UL; r<FD_ALLOC_SIZECLASS_ITER_MAX; r++ ) {

    /* At this point sizeclasses in [0,l) are known to be inadequate and
       sizeclasses in [h,SIZECLASS_CNT) are known to be suitable.
       Sizeclasses in [l,h) have not been tested. */

    ulong m = (l+h)>>1; /* Note: no overflow for reasonable sizeclass_cnt and l<=m<=h */
    int   c = (((ulong)fd_alloc_sizeclass_cfg[ m ].block_footprint)>=footprint);
    l = fd_ulong_if( c, l, m+1UL ); /* cmov */
    h = fd_ulong_if( c, m, h     ); /* cmov */

  }

  return h;
}

/* fd_alloc_block_set *************************************************/

/* A fd_alloc_block_set specifies a set of blocks in a superblock. */

#define SET_NAME fd_alloc_block_set
#define SET_TYPE ulong
#define SET_MAX  64
#include "../tmpl/fd_smallset.c"

/* fd_alloc_block_set_all returns the set { 0,1,2, ... block_cnt-1 }.
   Assumes block_cnt is in [0,64]. */

FD_FN_CONST static inline fd_alloc_block_set_t
fd_alloc_block_set_all( ulong block_cnt ) {
  return (((ulong)(block_cnt<=63UL)) << (block_cnt & 63UL)) - 1UL; /* Handle wide shifts */
}

/* fd_alloc_block_set_{add,sub}_then_fetch inserts / removes blocks to /
   from block set pointed to by set.  The caller promises that blocks
   are not / are already in the block set.  This operation is a compiler
   fence.  Further, if FD_HAS_ATOMIC, this operation is done atomically.
   Returns the value of the block_set just after the operation.  Note:
   atomic add/sub has slightly better asm on x86 than atomic or/and/nand
   (compiler quality issue, not an architecture issue) and generates the
   same results provided the caller promises are met. */

#if FD_HAS_ATOMIC

static inline fd_alloc_block_set_t
fd_alloc_block_set_add_then_fetch( fd_alloc_block_set_t * _set,
                                   fd_alloc_block_set_t   blocks ) {
  FD_COMPILER_MFENCE();
  fd_alloc_block_set_t ret = FD_ATOMIC_ADD_AND_FETCH( _set, blocks );
  FD_COMPILER_MFENCE();
  return ret;
}

static inline fd_alloc_block_set_t
fd_alloc_block_set_sub_then_fetch( fd_alloc_block_set_t * _set,
                                   fd_alloc_block_set_t   blocks ) {
  FD_COMPILER_MFENCE();
  fd_alloc_block_set_t ret = FD_ATOMIC_SUB_AND_FETCH( _set, blocks );
  FD_COMPILER_MFENCE();
  return ret;
}

#else

static inline fd_alloc_block_set_t
fd_alloc_block_set_add_then_fetch( fd_alloc_block_set_t * _set,
                                   fd_alloc_block_set_t   blocks ) {
  FD_COMPILER_MFENCE();
  fd_alloc_block_set_t ret = (*_set) + blocks;
  *_set = ret;
  FD_COMPILER_MFENCE();
  return ret;
}

static inline fd_alloc_block_set_t
fd_alloc_block_set_sub_then_fetch( fd_alloc_block_set_t * _set,
                                   fd_alloc_block_set_t   blocks ) {
  FD_COMPILER_MFENCE();
  fd_alloc_block_set_t ret = (*_set) - blocks;
  *_set = ret;
  FD_COMPILER_MFENCE();
  return ret;
}

#endif

/* fd_alloc_hdr_t *****************************************************/

/* A fd_alloc_hdr_t is a small header prepended to an allocation that
   describes how to free the allocation. */

typedef uint fd_alloc_hdr_t;

/* FD_ALLOC_HDR_TYPE_* enumerate fd_alloc_hdr_t types */

#define FD_ALLOC_HDR_TYPE_USER_SMALL      (0) /* This is a (small) user alloc contained in a superblock */
#define FD_ALLOC_HDR_TYPE_USER_LARGE      (1) /* This is a (large) user alloc contained in a workspace partition */
#define FD_ALLOC_HDR_TYPE_NEST_SUPERBLOCK (2) /* This is a superblock contained in a (larger) superblock */
#define FD_ALLOC_HDR_TYPE_ROOT_SUPERBLOCK (3) /* This is a superblock contained in a workspace partition */

/* fd_alloc_hdr pack a (type,idx,off) tuple into a fd_alloc_hdr_t.
   fd_alloc_hdr_{type,idx,off} unpack the corresponding field from a
   fd_alloc_hdr_t. */

FD_FN_CONST static inline fd_alloc_hdr_t
fd_alloc_hdr( int   type,   /* FD_ALLOC_HDR_TYPE_USER_SMALL or FD_ALLOC_HDR_TYPE_NEST_SUPERBLOCK */
              ulong idx,    /* in [0,64), containing superblock block block_idx */
              ulong off ) { /* in [0,2^26), aligned 4, byte offset of alloc/superblock in containing superblock */
  return (fd_alloc_hdr_t)((off<<6) | (idx<<2) | (ulong)type);
}

FD_FN_CONST static inline int   fd_alloc_hdr_type( fd_alloc_hdr_t hdr ) { return (int)  ( hdr     &  3U); } /* FD_ALLOC_HDR_TYPE */
FD_FN_CONST static inline ulong fd_alloc_hdr_idx ( fd_alloc_hdr_t hdr ) { return (ulong)((hdr>>2) & 63U); } /* in [0,64) */
FD_FN_CONST static inline ulong fd_alloc_hdr_off ( fd_alloc_hdr_t hdr ) { return (ulong)((hdr>>8) << 2);  } /* in [0,2^26), aligned 4 */

/* FD_ALLOC_HDR_{USER_LARGE,ROOT_SUPERBLOCK} allocations do not need the
   fd_alloc_hdr_t idx and off fields.  These fields are replaced by
   magic numbers to help with various allocation diagnostics. */

#define FD_ALLOC_HDR_USER_LARGE      (0xfdac5e70U | (uint)FD_ALLOC_HDR_TYPE_USER_LARGE     )
#define FD_ALLOC_HDR_ROOT_SUPERBLOCK (0xfda70010U | (uint)FD_ALLOC_HDR_TYPE_ROOT_SUPERBLOCK)

/* fd_alloc_hdr_load loads the header for the allocation whose first
   byte is at laddr in the caller's address space.  The header will be
   observed at some point of time between when this call was made and
   returned.  This implies that the allocation at laddr must be valid at
   least until the caller stops using the hdr.

   fd_alloc_hdr_store stores a fd_alloc_hdr_t to the
   sizeof(fd_alloc_hdr_t) bytes immediately preceding the byte pointed
   to by laddr in the caller's address space.  The caller promises that
   these bytes are somewhere within the containing block or wksp
   allocation.

   Note that superblocks are aligned FD_ALLOC_SUPERBLOCK_ALIGN.
   Further, to support superblock nesting, the blocks in a superblock
   are similarly aligned.  As such, fd_alloc_hdr_t (which need an
   alignment less than this) are guaranteed to be loaded/stored at
   alignof(fd_alloc_hdr_t) aligned locations. */

FD_FN_PURE static inline fd_alloc_hdr_t
fd_alloc_hdr_load( void const * laddr ) { /* Aligned at least alignof(fd_alloc_hdr_t) */
  return *(fd_alloc_hdr_t const *)((ulong)laddr - sizeof(fd_alloc_hdr_t));
}

static inline void *
fd_alloc_hdr_store( void *         laddr,  /* Aligned at least alignof(fd_alloc_hdr_t) */
                    fd_alloc_hdr_t hdr ) {
  *(fd_alloc_hdr_t *)((ulong)laddr - sizeof(fd_alloc_hdr_t)) = hdr;
  return laddr;
}

/* fd_alloc_superblock ************************************************/

struct __attribute__((aligned(FD_ALLOC_SUPERBLOCK_ALIGN))) fd_alloc_superblock {
  fd_alloc_hdr_t       hdr;         /* ==FD_ALLOC_HDR_ROOT_SUPERBLOCK or (FD_ALLOC_HDR_TYPE_NEST_SUPERBLOCK,idx,off) */
  ushort               sizeclass;   /* superblock sizeclass, in [0,FD_ALLOC_SIZECLASS_CNT) */
  uchar                block_cnt;   /* ==fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt */
  uchar                cgroup_mask; /* ==fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask */
  fd_alloc_block_set_t free_blocks; /* which blocks in this superblock are allocated */
  ulong                next_gaddr;  /* if on the inactive superblock stack, next inactive superblock or NULL, ignored o.w. */

  /* TODO: consider making make a ulong bit packed tuple for
     (sizeclass,block_cnt,cgroup_mask) and adding a cgroup_hint to it? */

  /* Storage for blocks follows */
};

typedef struct fd_alloc_superblock fd_alloc_superblock_t;

/* fd_alloc ***********************************************************/

/* fd_alloc_vgaddr_t provides APIs for versioned gaddrs used in an
   fd_alloc_t's sizeclass inactive stack. */

#define VOFF_NAME      fd_alloc_vgaddr
#define VOFF_TYPE      ulong
#define VOFF_VER_WIDTH 17
#include "../tmpl/fd_voff.c"

/* fd_alloc_private_active_slot returns a pointer to the location in the
   caller's address space where the gaddr of the active superblock for
   (sizeclass,cgroup) is stored.  Assumes alloc is a non-NULL pointer in
   the caller's address space to the fd_alloc (not a join handle). */

FD_FN_CONST static inline ulong *
fd_alloc_private_active_slot( fd_alloc_t * alloc,
                              ulong        sizeclass,
                              ulong        cgroup ) {
  return alloc->active_slot + sizeclass + FD_ALLOC_SIZECLASS_MAX*cgroup;
}

/* fd_alloc_private_active_slot_replace replaces the value currently in
   the slot pointed to by active_slot with new_superblock_gaddr and
   returns the superblock_gaddr previously in there.  This is a compiler
   fence.  If FD_HAS_ATOMIC, this will be done atomically. */

static inline ulong
fd_alloc_private_active_slot_replace( ulong * _active_slot,
                                      ulong   new_superblock_gaddr ) {
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  ulong old_superblock_gaddr = FD_ATOMIC_XCHG( _active_slot, new_superblock_gaddr );
# else
  ulong old_superblock_gaddr = *_active_slot;
  *_active_slot = new_superblock_gaddr;
# endif
  FD_COMPILER_MFENCE();
  return old_superblock_gaddr;
}

/* fd_alloc_private_inactive_stack_push pushes the superblock at the
   workspace global address superblock_gaddr in workspace wksp onto the
   stack _inactive_stack.  This is a compiler fence.  If FD_HAS_ATOMIC,
   this will be done atomically. */

static inline void
fd_alloc_private_inactive_stack_push( fd_alloc_vgaddr_t * _inactive_stack,
                                      fd_wksp_t *         wksp,
                                      ulong               superblock_gaddr ) {
  fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

  for(;;) {

    /* Read the top of the inactive stack. */

    FD_COMPILER_MFENCE();
    fd_alloc_vgaddr_t old = *_inactive_stack;
    FD_COMPILER_MFENCE();

    ulong top_ver   = fd_alloc_vgaddr_ver( old );
    ulong top_gaddr = fd_alloc_vgaddr_off( old ) << FD_ALLOC_SUPERBLOCK_LG_ALIGN;

    /* Try to push the top of the inactive stack */

    fd_alloc_vgaddr_t new = fd_alloc_vgaddr( top_ver+1UL, superblock_gaddr >> FD_ALLOC_SUPERBLOCK_LG_ALIGN );

    FD_COMPILER_MFENCE();
    superblock->next_gaddr = top_gaddr;
    FD_COMPILER_MFENCE();

#   if FD_HAS_ATOMIC
    if( FD_LIKELY( FD_ATOMIC_CAS( _inactive_stack, old, new )==old ) ) break;
#   else
    if( FD_LIKELY( (*_inactive_stack)==old ) ) { *_inactive_stack = new; break; }
#   endif

    /* Hmmm ... that failed ... try again */

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();
}

/* fd_alloc_private_inactive_stack_pop pops the superblock off the top
   of the stack _inactive_stack.  Returns the non-zero wksp superblock
   gaddr of the popped stack top on success or 0 on failure (i.e.
   _inactive_stack at some point in time between which this was called
   and this returned).  This is a compiler fence.  If FD_HAS_ATOMIC,
   this will be done atomically. */

#if FD_HAS_DEEPASAN
FD_FN_NO_ASAN static
#else
static inline
#endif
ulong
fd_alloc_private_inactive_stack_pop( fd_alloc_vgaddr_t * _inactive_stack,
                                     fd_wksp_t *         wksp ) {
  ulong top_gaddr;

  for(;;) {

    /* Read the top of the inactive stack.  Return if the inactive stack
       is empty. */

    FD_COMPILER_MFENCE();
    fd_alloc_vgaddr_t old = *_inactive_stack;
    FD_COMPILER_MFENCE();

    /**/  top_gaddr = fd_alloc_vgaddr_off( old ) << FD_ALLOC_SUPERBLOCK_LG_ALIGN;
    ulong top_ver   = fd_alloc_vgaddr_ver( old );
    if( FD_UNLIKELY( !top_gaddr ) ) break;

    /* Try to pop the top of the inactive stack. */

    fd_alloc_superblock_t * top = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, top_gaddr );

    /* Note: under concurrent FD_HAS_DEEPASAN operation, another thread
       could pop and free the inactive superblock at the top and free it
       (thus poisoning top) after our top read above and before our
       next_gaddr read below.  This could trigger a spurious asan
       failure (that, in normal operation, would have been failed and
       retried via the CAS below).  Hence the noasan above. */

    FD_COMPILER_MFENCE();
    ulong next_gaddr = top->next_gaddr;
    FD_COMPILER_MFENCE();

    fd_alloc_vgaddr_t new = fd_alloc_vgaddr( top_ver+1UL, next_gaddr >> FD_ALLOC_SUPERBLOCK_LG_ALIGN );

#   if FD_HAS_ATOMIC
    if( FD_LIKELY( FD_ATOMIC_CAS( _inactive_stack, old, new )==old ) ) break;
#   else
    if( FD_LIKELY( (*_inactive_stack)==old ) ) { *_inactive_stack = new; break; }
#   endif

    /* Hmmm ... that failed ... try again */

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  return top_gaddr;
}

/* fd_alloc_private_alloc will allocate a sizeclass sized block from
   the given alloc with the concurrency hint cgroup_hint.  On success,
   returns the superblock that contains the allocated block in the
   caller's address space and *_block_idx will hold the index of the
   allocated block.  On failure, returns NULL and *_block_idx is
   unchanged. */

static fd_alloc_superblock_t *
fd_alloc_private_alloc( fd_alloc_t * alloc,
                        fd_wksp_t *  wksp,
                        ulong        sizeclass,
                        ulong        cgroup_hint,
                        ulong *      _block_idx );

/* fd_alloc_private_free frees (superblock,block_idx).  Assumes join is a
   current local join to an allocator, superblock points in the caller's
   address space to a valid superblock from this allocator, and
   block_idx a valid block index for this superblock that is currently
   allocated. */

static void
fd_alloc_private_free( fd_alloc_t *            join,
                       fd_alloc_superblock_t * superblock,
                       ulong                   block_idx );

/* Constructors *******************************************************/

ulong
fd_alloc_align( void ) {
  return alignof(fd_alloc_t);
}

ulong
fd_alloc_footprint( void ) {
  return sizeof(fd_alloc_t);
}

void *
fd_alloc_new( void * shmem,
              ulong  tag ) {

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

  if( FD_UNLIKELY( fd_wksp_gaddr_hi( wksp ) > (1UL<<(fd_alloc_vgaddr_OFF_WIDTH + FD_ALLOC_SUPERBLOCK_LG_ALIGN)) ) ) {
    FD_LOG_WARNING(( "wksp too large for current fd_alloc implementation" ));
    return NULL;
  }

  if( FD_UNLIKELY( !tag ) ) {
    FD_LOG_WARNING(( "bad tag" ));
    return NULL;
  }

  fd_alloc_t * alloc = (fd_alloc_t *)shmem;
  memset( alloc, 0, sizeof(fd_alloc_t) );

  alloc->wksp_off = (ulong)alloc - (ulong)wksp;
  alloc->tag      = tag;

  FD_COMPILER_MFENCE();
  alloc->magic = FD_ALLOC_MAGIC;
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

  return fd_alloc_join_cgroup_hint_set( alloc, cgroup_hint );
}

void *
fd_alloc_leave( fd_alloc_t * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return fd_alloc_private_join_alloc( join );
}

void *
fd_alloc_private_delete( void * shalloc,
                         int    level ) {

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
  alloc->magic = 0UL;
  FD_COMPILER_MFENCE();

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  if( level<=0 ) { /* no wksp cleanup */

    /* nothing to do */

  } else if( level<=1 ) { /* quick wksp cleanup */

    /* For each sizeclass, make all active superblocks inactive and then
       delete all inactive superblocks.  This will not cleanup any
       superblocks that are fully allocated (and thus out of circulation
       for malloc) or any large allocations as a quick wksp cleanup
       assumes the application freed all outstanding allocations before
       calling this. */

    for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {
      fd_alloc_vgaddr_t * _inactive_stack = alloc->inactive_stack + sizeclass;

      ulong cgroup_cnt = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask + 1UL;
      for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
        ulong superblock_gaddr =
          fd_alloc_private_active_slot_replace( fd_alloc_private_active_slot( alloc, sizeclass, cgroup_idx ), 0UL );
        if( FD_UNLIKELY( superblock_gaddr ) ) fd_alloc_private_inactive_stack_push( _inactive_stack, wksp, superblock_gaddr );
      }

      for(;;) {
        ulong superblock_gaddr = fd_alloc_private_inactive_stack_pop( _inactive_stack, wksp );
        if( FD_LIKELY( !superblock_gaddr ) ) break;
        fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

        fd_alloc_hdr_t hdr = superblock->hdr;
        if( FD_UNLIKELY( hdr==FD_ALLOC_HDR_ROOT_SUPERBLOCK ) ) fd_wksp_free( wksp, superblock_gaddr );
        else {
          fd_alloc_superblock_t * parent_superblock = (fd_alloc_superblock_t *)((ulong)superblock - fd_alloc_hdr_off( hdr ));
          ulong                   parent_block_idx  = fd_alloc_hdr_idx( hdr );
          fd_alloc_private_free( alloc, parent_superblock, parent_block_idx );
        }
      }
    }

  } else { /* deep wksp cleanup (level>1) */

    /* A deep wksp cleanup will free all wksp allocations that match the
       alloc's tag. */

    fd_wksp_tag_free( wksp, &alloc->tag, 1UL );

  }

  return shalloc;
}

void * fd_alloc_delete( void * shalloc ) { return fd_alloc_private_delete( shalloc, 1 ); }

static fd_alloc_superblock_t *
fd_alloc_private_alloc( fd_alloc_t * alloc,
                        fd_wksp_t *  wksp,
                        ulong        sizeclass,
                        ulong        cgroup_hint,
                        ulong *      _block_idx ) {

  ulong cgroup_mask = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask;

  ulong cgroup = cgroup_hint & cgroup_mask;

  /* Try to get exclusive access to the preferred active superblock
     for (sizeclass,cgroup).  Note that all active superblocks have at
     least one free block.  We do a test-and-test-and-set style to avoid
     an atomic operation if there currently isn't an active superblock
     for (sizeclass,cgroup). */

  ulong * active_slot = fd_alloc_private_active_slot( alloc, sizeclass, cgroup );

  ulong superblock_gaddr = *active_slot;

  if( FD_LIKELY( superblock_gaddr ) ) superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, 0UL );

  /* At this point, if superblock_gaddr is non-zero, we have exclusive
     access to the superblock and only we can allocate blocks from it.
     (Other threads could free blocks to it concurrently though.)

     If superblock_gaddr is zero, there was no preferred active
     superblock for (sizeclass,cgroup) when we looked.  So, we try to
     pop the inactive superblock stack for this sizeclass.  Note that
     all inactive superblocks also have at least one free block.

     If that fails, we try to allocate a new superblock to hold this
     allocation.  If we are able to do so, obviously the new superblock
     will have at least one free block for this allocation.  (Yes,
     malloc calls itself recursively.  The base case is root superblock
     allocation from the underlying workspace.)

     If that fails, we are in trouble and fail (we are either out of
     memory or have too much wksp fragmentation). */

  if( FD_UNLIKELY( !superblock_gaddr ) ) {

    superblock_gaddr = fd_alloc_private_inactive_stack_pop( alloc->inactive_stack + sizeclass, wksp );

    if( FD_UNLIKELY( !superblock_gaddr ) ) {

      fd_alloc_superblock_t * superblock;
      fd_alloc_hdr_t          hdr;

      ulong parent_sizeclass = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].parent_sizeclass;

      if( FD_LIKELY( parent_sizeclass<FD_ALLOC_SIZECLASS_CNT ) ) {

        ulong                   parent_idx;
        fd_alloc_superblock_t * parent_superblock =
          fd_alloc_private_alloc( alloc, wksp, parent_sizeclass, cgroup_hint, &parent_idx );
        if( FD_UNLIKELY( !parent_superblock ) ) return NULL;

        ulong parent_off = sizeof(fd_alloc_superblock_t)
                         + parent_idx*(ulong)fd_alloc_sizeclass_cfg[ parent_sizeclass ].block_footprint;

        superblock = (fd_alloc_superblock_t *)((ulong)parent_superblock + parent_off);
        hdr        = fd_alloc_hdr( FD_ALLOC_HDR_TYPE_NEST_SUPERBLOCK, parent_idx, parent_off );

#       if FD_HAS_DEEPASAN
        /* At this point, the block containing the nested superblock is
           poisoned.  Unpoison the header region.  Note that blocks are
           aligned FD_ALLOC_SUPERBLOCK_ALIGN, FD_ALLOC_SUPERBLOCK_ALIGN
           is at least FD_ASAN_ALIGN and sizeof(fd_alloc_superblock_t)
           is a FD_ALLOC_SUPERBLOCK_ALIGN multiple. */
        fd_asan_unpoison( superblock, sizeof(fd_alloc_superblock_t) );
#       endif

        superblock_gaddr = fd_wksp_gaddr_fast( wksp, superblock );

      } else {

        superblock_gaddr = fd_wksp_alloc( wksp, FD_ALLOC_SUPERBLOCK_ALIGN, FD_ALLOC_ROOT_SUPERBLOCK_FOOTPRINT, alloc->tag );
        if( FD_UNLIKELY( !superblock_gaddr ) ) return NULL;

        superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );
        hdr        = FD_ALLOC_HDR_ROOT_SUPERBLOCK;

#       if FD_HAS_DEEPASAN
        /* At this point, the entire root superblock is unpoisoned.
           Poison the superblock block (keeping the header unpoisoned).
           See note above regarding alignments. */
        fd_asan_poison( superblock+1, FD_ALLOC_ROOT_SUPERBLOCK_FOOTPRINT - sizeof(fd_alloc_superblock_t) );
#       endif

      }

      ulong block_cnt = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt;

      superblock->hdr         = hdr;
      superblock->sizeclass   = (ushort)sizeclass;
      superblock->block_cnt   = (uchar)block_cnt;
      superblock->cgroup_mask = (uchar)cgroup_mask;
      superblock->free_blocks = fd_alloc_block_set_all( block_cnt );
      superblock->next_gaddr  = 0UL;

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

  fd_alloc_block_set_t * _free_blocks = &superblock->free_blocks;

  FD_COMPILER_MFENCE();
  fd_alloc_block_set_t free_blocks_before = *_free_blocks;
  FD_COMPILER_MFENCE();

  ulong block_idx = (ulong)fd_alloc_block_set_first( free_blocks_before );

  fd_alloc_block_set_t free_blocks_after = fd_alloc_block_set_sub_then_fetch( _free_blocks, fd_alloc_block_set_ele( block_idx ) );

  /* At this point, we've allocated block block_idx from the superblock
     and free_blocks_after gives the set of free blocks in the
     superblock immediately after the allocation occurred. */

  if( FD_LIKELY( free_blocks_after ) ) {

    /* At this point, we know the superblock has at least one
       allocated block in it (the one we just allocated) and one free
       block in it.  And this will hold true until we put this
       superblock back into circulation.  Specifically, nobody can free
       the block we just allocated until we return to tell them about it
       and nobody can allocate any remaining free blocks until we get
       this superblock back into circulation.  To get this superblock
       back into circulation, we make it the active superblock for
       (sizeclass,cgroup). */

    ulong displaced_superblock_gaddr = fd_alloc_private_active_slot_replace( active_slot, superblock_gaddr );

    /* And if this displaced a previously active superblock (e.g.
       another thread made a different superblock the active one while
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
       allocation occurred.  We should not make put this superblock into
       circulation as it would break the invariants that all superblocks
       in circulation have at least one free block.

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

  *_block_idx = block_idx;
  return superblock;
}

static void
fd_alloc_private_free( fd_alloc_t *            join,
                       fd_alloc_superblock_t * superblock,
                       ulong                   block_idx ) {

  /* These reads and the ASAN poisoning must be before the free because
     block could potentially be reused by other threads the moment it is
     marked as free. */

  ulong sizeclass   = (ulong)superblock->sizeclass;
  ulong block_cnt   = (ulong)superblock->block_cnt;
  ulong cgroup_mask = (ulong)superblock->cgroup_mask;

# if FD_HAS_DEEPASAN /* Poison the block we are about to free */
  ulong block_footprint = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;
  ulong block_laddr     = (ulong)superblock + sizeof(fd_alloc_superblock_t) + block_idx*block_footprint;
  fd_asan_poison( (void *)block_laddr, block_footprint );
# endif

  fd_alloc_block_set_t * _free_blocks = &superblock->free_blocks;

  fd_alloc_block_set_t block = fd_alloc_block_set_ele( block_idx );

  fd_alloc_block_set_t free_blocks_after = fd_alloc_block_set_add_then_fetch( _free_blocks, block );

  /* At this point, superblock is no longer safe to read and
     free_blocks_after is the set of free blocks just after the free. */

  if( FD_UNLIKELY( free_blocks_after==block ) ) {

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

       The second option is about as simple and optimizes the single
       threaded and paired use cases as this thread is also likely the
       same thread that malloc'd this.  Pipelined is marginally worse as
       the superblock will have to take two hops before it gets reused
       again (from the free-ing thread active superblock to the inactive
       stack to the malloc-ing active superblock).

       The third and fourth options can simultaneously get all options
       optimized but they require extra plumbing (either under the hood
       as per the note in malloc above or from the caller to get the
       extra context).

       Currently we do the second option for simplicity and optimal
       behaviors in the single threaded and paired use cases.  (The
       fourth option is possible via the user changing the join's
       cgroup_hint to match the thread of the original allocator.) */

    fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );
    fd_wksp_t *  wksp  = fd_alloc_private_wksp( alloc );

    ulong cgroup = fd_alloc_join_cgroup_hint( join ) & cgroup_mask;

    ulong * _active_slot = fd_alloc_private_active_slot( alloc, sizeclass, cgroup );

    ulong displaced_superblock_gaddr = fd_alloc_private_active_slot_replace( _active_slot, fd_wksp_gaddr_fast( wksp, superblock ) );

    /* If this displaced an already active superblock, we need to push
       the displaced superblock onto the inactive stack (note that the
       superblock cannot be the same as the currently active superblock
       because the superblock was not in circulation before). */

    if( FD_UNLIKELY( displaced_superblock_gaddr ) )
      fd_alloc_private_inactive_stack_push( alloc->inactive_stack + sizeclass, wksp, displaced_superblock_gaddr );

    return;

  }

  ulong all_blocks = fd_alloc_block_set_all( block_cnt );

  if( FD_LIKELY( free_blocks_after!=all_blocks ) ) return;

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

     Likewise, though the post deletion top->next_gaddr read will get a
     stale value in this scenario, it will highly likely not be injected
     into the inactive_stack because the CAS will detect that
     inactive_stack top has changed and fail.

     And, lastly, we version the inactive_stack top such that, even if
     somehow we had a thread stall in pop after reading top->next_gaddr
     / other threads do other operations that ultimately keep top the
     same change the value of top->next_gaddr / stalled thread resumes,
     the version number on the stalled thread will be wrong cause the
     CAS to fail.  (There is a theoretical risk of version number reuse
     but the version number is wide enough to make that risk zero on any
     practical timescale.) */

  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  fd_alloc_vgaddr_t * _inactive_stack = alloc->inactive_stack + sizeclass;

  ulong deletion_candidate_gaddr = fd_alloc_private_inactive_stack_pop( _inactive_stack, wksp );
  if( FD_LIKELY( !deletion_candidate_gaddr ) ) return; /* no deletion candidate, unclear branch prob */

  fd_alloc_superblock_t * deletion_candidate = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, deletion_candidate_gaddr );

  if( FD_LIKELY( deletion_candidate->free_blocks!=all_blocks ) ) { /* deletion candidate not empty -> return to circulation */
    fd_alloc_private_inactive_stack_push( _inactive_stack, wksp, deletion_candidate_gaddr );
    return;
  }

  fd_alloc_hdr_t hdr = deletion_candidate->hdr;
  if( FD_LIKELY( hdr!=FD_ALLOC_HDR_ROOT_SUPERBLOCK ) ) { /* empty deletion candidate in a parent superblock, free from parent */
    fd_alloc_private_free( join, (fd_alloc_superblock_t *)((ulong)deletion_candidate - fd_alloc_hdr_off( hdr )),
                           fd_alloc_hdr_idx( hdr ) );
    return;
  }

# if FD_HAS_DEEPASAN
  /* At this point, just the header of the root superblock to delete
     is unpoisoned.  Since fd_wksp_free will poison the entire root
     superblock anyway, we don't need to do anything here. */
# endif

  fd_wksp_free( wksp, deletion_candidate_gaddr ); /* empty deletion candidate wksp allocated, free from wksp */
}

void *
fd_alloc_malloc_at_least( fd_alloc_t * join,
                          ulong        align,
                          ulong        sz,
                          ulong *      _max ) {

  /* Handle default align, NULL alloc, 0 size, non-power-of-two align,
     unreasonably large sz and NULL _max.  footprint has room for a
     fd_alloc_hdr_t, sz bytes and enough padding to allow for the
     alignment of superblock blocks / wksp allocations is at least
     alignof(fd_alloc_hdr_t). */

  if( FD_UNLIKELY( !_max ) ) return NULL;

  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );

  align = fd_ulong_if( !align, FD_ALLOC_MALLOC_ALIGN_DEFAULT, align );

  ulong footprint = sz + fd_ulong_max( align, sizeof(fd_alloc_hdr_t) );

  if( FD_UNLIKELY( (!alloc) | (!fd_ulong_is_pow2( align )) | (!sz) | (footprint<=sz) ) ) {
    *_max = 0UL;
    return NULL;
  }

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  /* At this point, alloc is non-NULL and backed by wksp, align is a
     power-of-2, footprint is a reasonable non-zero value.  If this is a
     large user allocation, allocate it directly from the underlying
     workspace. */

  if( FD_UNLIKELY( footprint > FD_ALLOC_FOOTPRINT_SMALL_THRESH ) ) {
    ulong part_gaddr_lo;
    ulong part_gaddr_hi;
    if( FD_UNLIKELY( !fd_wksp_alloc_at_least( wksp, alignof(fd_alloc_hdr_t), footprint, alloc->tag,
                                              &part_gaddr_lo, &part_gaddr_hi ) ) ) {
      *_max = 0UL;
      return NULL;
    }

    /* Carve the requested allocation out of the newly allocated
       partition, prepending the allocation header for use by free.  If
       we are running under the address sanitizer, note that
       fd_wksp_alloc_at_least already unpoisoned this partition.  If we
       are running under the memory sanitizer, we mark the returned
       region as uninitialized. */

    ulong part_laddr     = (ulong)fd_wksp_laddr_fast( wksp, part_gaddr_lo );
    ulong part_footprint = part_gaddr_hi - part_gaddr_lo;

    ulong alloc_laddr = fd_ulong_align_up( part_laddr + sizeof(fd_alloc_hdr_t), align );
    ulong asz         = alloc_laddr - part_laddr;

#   if FD_ALLOC_STYLE==1 /* clear all align padding */
    if( asz > sizeof(fd_alloc_hdr_t) ) memset( (void *)part_laddr, 0, asz - sizeof(fd_alloc_hdr_t) );
#   else /* partially clear align padding to improve diagnostics */
    *(uint *)part_laddr = 0U;
#   endif

    *_max = part_footprint - asz;
    return fd_msan_poison( fd_alloc_hdr_store( (void *)alloc_laddr, FD_ALLOC_HDR_USER_LARGE ), *_max );
  }

  /* At this point, this is a small user allocation.  Determine the
     preferred sizeclass and cgroup_hint and then allocate a suitable
     block. */

  ulong sizeclass   = fd_alloc_preferred_sizeclass( footprint );
  ulong cgroup_hint = fd_alloc_join_cgroup_hint( join );

  ulong                   block_idx;
  fd_alloc_superblock_t * superblock = fd_alloc_private_alloc( alloc, wksp, sizeclass, cgroup_hint, &block_idx );
  if( FD_UNLIKELY( !superblock ) ) {
    *_max = 0UL;
    return NULL;
  }

  /* Carve the requested allocation out of the newly allocated block,
     prepending the allocation header for use by free.  If we are
     running under the address sanitizer, we unpoison the block (see
     note above about asan alignment).  If we are running under the
     memory sanitizer, we mark the returned region as uninitialized. */

  ulong block_footprint = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;
  ulong block_laddr     = (ulong)superblock + sizeof(fd_alloc_superblock_t) + block_idx*block_footprint;

# if FD_HAS_DEEPASAN
  fd_asan_unpoison( (void *)block_laddr, block_footprint );
# endif

  ulong alloc_laddr = fd_ulong_align_up( block_laddr + sizeof(fd_alloc_hdr_t), align );
  ulong asz         = alloc_laddr - block_laddr;

# if FD_ALLOC_STYLE==1 /* clear all align padding */
  if( asz > sizeof(fd_alloc_hdr_t) ) memset( (void *)block_laddr, 0, asz - sizeof(fd_alloc_hdr_t) );
# else /* partially clear align padding to improve diagnostics */
  *(fd_alloc_hdr_t *)block_laddr = 0U;
# endif

  fd_alloc_hdr_t hdr = fd_alloc_hdr( FD_ALLOC_HDR_TYPE_USER_SMALL, block_idx, alloc_laddr - (ulong)superblock );

  *_max = block_footprint - asz;
  return fd_msan_poison( fd_alloc_hdr_store( (void *)alloc_laddr, hdr ), *_max );
}

void
fd_alloc_free( fd_alloc_t * join,
               void *       laddr ) {

  /* Handle NULL alloc and/or NULL laddr */

  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );
  if( FD_UNLIKELY( (!alloc) | (!laddr) ) ) return;

  /* At this point, we have a valid join and a pointer to the first byte
     of an allocation done by it.  Load the allocation header.  If the
     header indicates this is a large allocation, free it from the
     underlying wksp (note that fd_wksp_free_laddr works for any byte
     within the wksp allocation ... thus we don't have to apply a header
     offset and thus can reuse the header idx and off for data integrity
     checks).  Otherwise (i.e. the header indicates this allocation is a
     block in a superblock), free it from the containing superblock. */

  fd_alloc_hdr_t hdr = fd_alloc_hdr_load( laddr );

  if( FD_UNLIKELY( hdr==FD_ALLOC_HDR_USER_LARGE ) ) {
    fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

#   if FD_HAS_DEEPASAN
    /* Note that fd_wksp_free will poison the partition on our behalf so
       we don't have anything to do here. */
#   endif

    fd_wksp_free( wksp, fd_wksp_gaddr_fast( wksp, laddr ) );
    return;
  }

  fd_alloc_private_free( join, (fd_alloc_superblock_t *)((ulong)laddr - fd_alloc_hdr_off( hdr )), fd_alloc_hdr_idx( hdr ) );
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
     larger superblocks in which they are nested could become completely
     empty.  At the end of compaction, if no other operations are
     running concurrently, any remaining superblocks should contain at
     least one user small allocation somewhere in them. */

  for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {
    fd_alloc_block_set_t all_blocks      = fd_alloc_block_set_all( (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt );
    ulong                cgroup_cnt      = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask + 1UL;
    fd_alloc_vgaddr_t *  _inactive_stack = alloc->inactive_stack + sizeclass;

    /* For each active superblock in this sizeclass */

    for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
      ulong * _active_slot = fd_alloc_private_active_slot( alloc, sizeclass, cgroup_idx );

      ulong superblock_gaddr = fd_alloc_private_active_slot_replace( _active_slot, 0UL );
      if( !superblock_gaddr ) continue; /* application dependent branch prob */
      fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

      /* At this point, we have atomically acquired the cgroup_idx's
         active superblock and it has at least one free block.  If this
         superblock is empty, we push it onto the inactive stack (for
         freeing below).  Otherwise, we put the superblock back into
         circulation (we know from the above it still has at least one
         free block, preserving the invariant).  This might displace a
         superblock that another thread made active behind our back.  We
         push any such superblock block onto the inactive stack (it also
         will have at least one free block for the same reasons). */

      if( superblock->free_blocks==all_blocks ) { /* application dependent branch prob */
        fd_alloc_private_inactive_stack_push( _inactive_stack, wksp, superblock_gaddr );
      } else {
        ulong displaced_superblock_gaddr = fd_alloc_private_active_slot_replace( _active_slot, superblock_gaddr );
        if( FD_UNLIKELY( displaced_superblock_gaddr ) )
          fd_alloc_private_inactive_stack_push( _inactive_stack, wksp, displaced_superblock_gaddr );
      }
    }

    /* Drain the inactive stack for this sizeclass.  All empty
       superblocks found are freed.  All other superblocks will be
       pushed onto a local stack (every one will have at least one free
       block).  After the inactive stack drain, we drain the local stack
       back into the inactive stack to get all these remaining
       superblocks back into circulation (also safe for the same
       reasons) and with same relative ordering (nice but not required).
       We technically don't need to use a lockfree push / pop for the
       local stack but no sense in implementing a second version for
       this mostly diagnostic / teardown oriented use case. */

    fd_alloc_vgaddr_t _local_stack[1];

    *_local_stack = fd_alloc_vgaddr( 0UL, 0UL );

    for(;;) {
      ulong superblock_gaddr = fd_alloc_private_inactive_stack_pop( _inactive_stack, wksp );
      if( !superblock_gaddr ) break; /* application dependent branch prob */
      fd_alloc_superblock_t * superblock = (fd_alloc_superblock_t *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

      if( superblock->free_blocks==all_blocks ) { /* if superblock is empty, free it, application dependent branch prob */

        fd_alloc_hdr_t hdr = superblock->hdr;
        if( FD_LIKELY( hdr!=FD_ALLOC_HDR_ROOT_SUPERBLOCK ) ) { /* empty superblock in a parent superblock, free from parent */
          fd_alloc_private_free( join, (fd_alloc_superblock_t *)((ulong)superblock - fd_alloc_hdr_off( hdr )),
                                 fd_alloc_hdr_idx( hdr ) );
        } else {
          fd_wksp_free( wksp, superblock_gaddr ); /* empty superblock wksp allocated, free from wksp */
        }

      } else {

        fd_alloc_private_inactive_stack_push( _local_stack, wksp, superblock_gaddr );

      }
    }

    for(;;) {
      ulong superblock_gaddr = fd_alloc_private_inactive_stack_pop( _local_stack, wksp );
      if( !superblock_gaddr ) break; /* application dependent branch prob */
      fd_alloc_private_inactive_stack_push( _inactive_stack, wksp, superblock_gaddr );
    }
  }
}

int
fd_alloc_is_empty( fd_alloc_t * join ) {
  fd_alloc_t * alloc = fd_alloc_private_join_alloc( join );
  if( FD_UNLIKELY( !alloc ) ) return 0;

  /* Compact out any preallocated memory from the wksp */

  fd_alloc_compact( join );

  /* At this point, if there are no user allocations, there should be no
     wksp partitions tagged with the allocator's tag (except, maybe, the
     partition that holds the fd_alloc state, if the creator used the
     same tag there).  So we compute the number of partitions used by
     the alloc's tag and deduct if necessary the partition used to hold
     the fd_alloc's metadata. */

  fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

  fd_wksp_usage_t usage[1];
  fd_wksp_usage( wksp, &alloc->tag, 1UL, usage );

  usage->used_cnt -= (ulong)(fd_wksp_tag( wksp, fd_wksp_gaddr_fast( wksp, alloc ) )==alloc->tag);

  return !usage->used_cnt;
}

/* fd_alloc_fprintf pretty prints comprehensive details about the state
   of the allocator to stream.  Returns the number of characters printed
   to stream (saturated to INT_MAX).

   IMPORTANT SAFETY TIP!  If FD_ALLOC_STYLE==0 or if called while
   concurrent operations are in progress, this can spuriously report
   errors (due to alignment padding containing stale fd_alloc_hdr_t or
   from concurrent operations changing allocations while they are being
   analyzed by the below).

   IMPORTANT SAFETY TIP!  fd_alloc_printf can generate ASAN errors if
   run concurrently under ASAN because concurrent operations might
   poison regions of the wksp as they are being analyzed by the below.
   Hence the below functions are marked as FD_FN_NO_ASAN.  Similar
   considerations for FD_FN_NO_MSAN. */

#include <stdio.h>
#include "../wksp/fd_wksp_private.h"

FD_FN_NO_ASAN FD_FN_NO_MSAN static fd_alloc_hdr_t
fd_alloc_hdr_load_no_san( void const * laddr ) {
  return *(fd_alloc_hdr_t const *)((ulong)laddr - sizeof(fd_alloc_hdr_t));
}

FD_FN_NO_ASAN FD_FN_NO_MSAN static ulong
fd_alloc_private_superblock_fprintf( FILE *            stream,           /* Stream to fprintf */
                                     fd_wksp_t const * wksp,
                                     ulong             superblock_gaddr, /* Superblock to fprintf */
                                     ulong             parent_gaddr_lo,  /* wksp region that contains this superblock */
                                     ulong             parent_gaddr_hi,
                                     int               recurse,          /* Should this recurse into nested superblocks */
                                     ulong             indent_cnt,       /* How much to indent */
                                     ulong *           ctr ) {

  ulong cnt = 0UL;

# define EMIT( f ) do {                                              \
    for( ulong _rem=indent_cnt; _rem; _rem-- ) fputc( ' ', stream ); \
    cnt += (ulong)fd_int_max( (f), 0 ) + indent_cnt;                 \
  } while(0)

# define SB_TEST( c ) \
  do { if( FD_UNLIKELY( !(c) ) ) { EMIT( fprintf( stream, "unexpected: %s failed\n", #c ) ); ctr[0]++; return cnt; } } while(0)

  /* validate the superblock header */

  fd_alloc_superblock_t const * parent;
  if( !parent_gaddr_lo ) {
    parent          = NULL;
    parent_gaddr_lo = superblock_gaddr;
  } else {
    parent = (fd_alloc_superblock_t const *)fd_wksp_laddr_fast( wksp, parent_gaddr_lo );
  }

  SB_TEST( parent_gaddr_lo<=superblock_gaddr                                  ); /* safe to read superblock header */
  SB_TEST( (superblock_gaddr+sizeof(fd_alloc_superblock_t))<=parent_gaddr_hi  ); /* " */
  SB_TEST( fd_ulong_is_aligned( superblock_gaddr, FD_ALLOC_SUPERBLOCK_ALIGN ) ); /* " */

  fd_alloc_superblock_t const * superblock = (fd_alloc_superblock_t const *)fd_wksp_laddr_fast( wksp, superblock_gaddr );

  ulong                sizeclass   = (ulong)superblock->sizeclass;
  ulong                block_cnt   = (ulong)superblock->block_cnt;
  ulong                cgroup_mask = (ulong)superblock->cgroup_mask;
  fd_alloc_block_set_t free_blocks =        superblock->free_blocks;
  ulong                next_gaddr  =        superblock->next_gaddr;

  SB_TEST( sizeclass  < FD_ALLOC_SIZECLASS_CNT                                 ); /* valid sizeclass */
  SB_TEST( block_cnt  ==(ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt   ); /* block_cnt   matches sizeclass */
  SB_TEST( cgroup_mask==(ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask ); /* cgroup_mask matches sizeclass */
  SB_TEST( free_blocks==(free_blocks & fd_alloc_block_set_all( block_cnt ))    ); /* no spurious bits set */
  SB_TEST( fd_ulong_is_aligned( next_gaddr, FD_ALLOC_SUPERBLOCK_ALIGN )        ); /* aligned gaddr or NULL gaddr */

  ulong block_footprint      = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;
  ulong superblock_footprint = sizeof(fd_alloc_superblock_t) + block_cnt*block_footprint;

  SB_TEST( (superblock_gaddr + superblock_footprint)<=parent_gaddr_hi ); /* safe to read superblock body */

  /* validate the superblock nesting */

  ulong parent_sizeclass;

  if( !parent ) {

    parent_sizeclass = FD_ALLOC_SIZECLASS_CNT;

    SB_TEST( superblock->hdr==FD_ALLOC_HDR_ROOT_SUPERBLOCK ); /* root superblock */

  } else {

    parent_sizeclass = (ulong)parent->sizeclass;

    ulong parent_block_footprint = (ulong)fd_alloc_sizeclass_cfg[ parent_sizeclass ].block_footprint;

    fd_alloc_hdr_t hdr = superblock->hdr;
    int   type = fd_alloc_hdr_type( hdr );
    ulong idx  = fd_alloc_hdr_idx ( hdr );
    ulong off  = fd_alloc_hdr_off ( hdr );

    SB_TEST( type==FD_ALLOC_HDR_TYPE_NEST_SUPERBLOCK                           ); /* nested superblock */
    SB_TEST( idx < (ulong)fd_alloc_sizeclass_cfg[ parent_sizeclass ].block_cnt ); /* valid index */
    SB_TEST( off == sizeof(fd_alloc_superblock_t) + idx*parent_block_footprint ); /* valid offset */
    SB_TEST( off == ((ulong)superblock - (ulong)parent)                        ); /* " */

  }

  SB_TEST( parent_sizeclass==(ulong)fd_alloc_sizeclass_cfg[ sizeclass ].parent_sizeclass ); /* valid parent sizeclass */

  EMIT( fprintf( stream, "%s superblock at [%013lx,%013lx)\n",
                 parent ? "nested" : "root", superblock_gaddr, superblock_gaddr + superblock_footprint ) );

  indent_cnt += 2UL;

  EMIT( fprintf( stream, "sizeclass   %3lu (cgroup_cnt %2lu block_cnt %2lu block_footprint %lu)\n",
                 sizeclass, cgroup_mask+1UL, block_cnt, block_footprint ) );

  ulong free_cnt = (ulong)fd_ulong_popcnt( free_blocks );

  EMIT( fprintf( stream, "free_blocks %013lx next_gaddr %013lx (free_cnt %2lu used_cnt %2lu)\n",
                 free_blocks, next_gaddr, free_cnt, block_cnt - free_cnt ) );

  /* iterate over all used blocks in the superblock */

  for( ulong block_idx=0UL; block_idx<block_cnt; block_idx++ ) {
    if( fd_alloc_block_set_test( free_blocks, block_idx ) ) continue;

    /* At this point, the block block_idx is in use and should either
       contain a child superblock or a USER_SMALL allocation.  Test if
       the block is a child superblock (note that will recursively test
       the contents of the child if so).  If not, search the block for a
       valid fd_alloc_hdr_t (there should be at least one ...  if more
       than one, the later ones are probably user data that accidentally
       matched a header). */

    ulong block_gaddr_lo = superblock_gaddr + sizeof(fd_alloc_superblock_t) + block_idx*block_footprint;
    ulong block_gaddr_hi = block_gaddr_lo + block_footprint;

    fd_alloc_hdr_t hdr = fd_alloc_hdr_load_no_san( fd_wksp_laddr_fast( wksp, block_gaddr_lo + sizeof(fd_alloc_hdr_t) ) );

    if( hdr==fd_alloc_hdr( FD_ALLOC_HDR_TYPE_NEST_SUPERBLOCK, block_idx, block_gaddr_lo - superblock_gaddr ) ) {

      EMIT( fprintf( stream, "block %2lu [%013lx,%013lx): nested superblock\n", block_idx, block_gaddr_lo, block_gaddr_hi ) );

      if( recurse ) cnt += fd_alloc_private_superblock_fprintf( stream, wksp, block_gaddr_lo,
                                                                superblock_gaddr, superblock_gaddr + superblock_footprint,
                                                                recurse, indent_cnt+2UL, ctr );

    } else {

      ulong align      = 1UL;
      ulong align_stop = block_footprint - sizeof(fd_alloc_hdr_t); /* Note: block_footprint > sizeof(fd_alloc_hdr_t) */

      for(;;) {

        if( FD_UNLIKELY( align>=align_stop ) ) {
          EMIT( fprintf( stream, "block %2lu [%013lx,%013lx): alloc header not found\n",
                         block_idx, block_gaddr_lo, block_gaddr_hi ) );
          ctr[0]++;
          break;
        }

        ulong alloc_gaddr = fd_ulong_align_up( block_gaddr_lo + sizeof(fd_alloc_hdr_t), align );

        fd_alloc_hdr_t hdr = fd_alloc_hdr_load_no_san( fd_wksp_laddr_fast( wksp, alloc_gaddr ) );

        if( FD_LIKELY( hdr==fd_alloc_hdr( FD_ALLOC_HDR_TYPE_USER_SMALL, block_idx, alloc_gaddr - superblock_gaddr ) ) ) {
          ulong alloc_max = block_gaddr_hi - alloc_gaddr;
          EMIT( fprintf( stream, "block %2lu [%013lx,%013lx): small user allocation (gaddr %013lx max %lu)\n",
                         block_idx, block_gaddr_lo, block_gaddr_hi, alloc_gaddr, alloc_max ));
          ctr[1]++;
          break;
        }

        align <<= 1;
      }

    }
  }

# undef EMIT

  return cnt;
}

FD_FN_NO_ASAN FD_FN_NO_MSAN int
fd_alloc_fprintf( fd_alloc_t * join,
                  FILE *       stream ) {
  if( FD_UNLIKELY( !stream ) ) return 0; /* NULL stream, can't print anything */

  ulong cnt = 0UL;

# define EMIT(x) do { cnt += (ulong)fd_int_max( (x), 0 ); } while(0)

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

    EMIT( fprintf( stream, "alloc: gaddr -, join_cgroup_hint %lu, magic 0x0 (bad)\n", cgroup_hint ) );
    ctr[0]++;

  } else { /* Normal join */

    fd_wksp_t * wksp = fd_alloc_private_wksp( alloc );

    ulong wksp_gaddr_lo  = wksp->gaddr_lo;
    ulong wksp_gaddr_hi  = wksp->gaddr_hi;

    /* Print the summary header */

    EMIT( fprintf( stream, "alloc: wksp %s gaddr %013lx, join_cgroup_hint %lu, magic 0x%lx (%s)\n",
                   wksp->name, fd_wksp_gaddr_fast( wksp, alloc ), cgroup_hint,
                   alloc->magic, alloc->magic==FD_ALLOC_MAGIC ? "good" : "bad" ) );
    if( FD_UNLIKELY( alloc->magic!=FD_ALLOC_MAGIC ) ) ctr[0]++;

    /* Print known details about each sizeclass */

    ulong block_footprint = 0UL;
    for( ulong sizeclass=0UL; sizeclass<FD_ALLOC_SIZECLASS_CNT; sizeclass++ ) {
      ulong block_footprint_prev = block_footprint;
      /**/  block_footprint  = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_footprint;

      ulong parent_sizeclass = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].parent_sizeclass;
      ulong block_cnt        = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].block_cnt;
      ulong cgroup_cnt       = (ulong)fd_alloc_sizeclass_cfg[ sizeclass ].cgroup_mask + 1UL;

      fd_alloc_vgaddr_t inactive_stack = alloc->inactive_stack[ sizeclass ];

      ulong inactive_stack_ver   = fd_alloc_vgaddr_ver( inactive_stack );
      ulong inactive_stack_gaddr = fd_alloc_vgaddr_off( inactive_stack ) << FD_ALLOC_SUPERBLOCK_LG_ALIGN;

      /* Omit sizeclasses that have no superblocks in circulation */

      int do_print = !!inactive_stack_gaddr;
      if( !do_print ) {
        for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
          if( *fd_alloc_private_active_slot( alloc, sizeclass, cgroup_idx ) ) {
            do_print = 1;
            break;
          }
        }
        if( !do_print ) continue;
      }

      /* Print size class header */

      EMIT( fprintf( stream,
                     "  sizeclass %3lu: parent_sizeclass %3lu, cgroup_cnt %2lu, block_cnt %2lu, footprint (%lu,%lu]\n",
                     sizeclass, parent_sizeclass, cgroup_cnt, block_cnt, block_footprint_prev, block_footprint ) );

      /* Print inactive stack top */

      EMIT( fprintf( stream, "    inactive_stack: gaddr %013lx, version %lu\n", inactive_stack_gaddr, inactive_stack_ver ) );

      /* Print active superblocks */

      ulong superblock_gaddr;

      for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
        superblock_gaddr = *fd_alloc_private_active_slot( alloc, sizeclass, cgroup_idx );
        if( !superblock_gaddr ) continue;
        ulong next_gaddr = ((fd_alloc_superblock_t const *)fd_wksp_laddr_fast( wksp, superblock_gaddr))->next_gaddr;
        EMIT( fprintf( stream, "    superblock %013lx: next %013lx (ignored), active (cgroup_idx %2lu)\n",
                       superblock_gaddr, next_gaddr, cgroup_idx ) );
      }

      /* Print leading inactive superblocks (best effort) */

      superblock_gaddr = inactive_stack_gaddr;
      for( ulong rem=1024UL; rem; rem-- ) {
        if( !( (wksp_gaddr_lo<=superblock_gaddr) & (superblock_gaddr<wksp_gaddr_hi) &
               fd_ulong_is_aligned( superblock_gaddr, FD_ALLOC_SUPERBLOCK_ALIGN ) ) ) {
          if( FD_UNLIKELY( superblock_gaddr ) ) {
            EMIT( fprintf( stream, "    inactive stack likely modified by a concurrent operation\n" ) );
            ctr[0]++;
          }
          break;
        }
        ulong next_gaddr = ((fd_alloc_superblock_t const *)fd_wksp_laddr_fast( wksp, superblock_gaddr))->next_gaddr;
        EMIT( fprintf( stream, "    superblock %013lx: next %013lx, inactive\n", superblock_gaddr, next_gaddr ) );
        superblock_gaddr = next_gaddr;
      }
    }

    /* Scan the wksp partition table for partitions that match this
       allocation tag.  We do this in a brute force way that is not algo
       efficient to avoid taking a lock. */

    ulong alloc_gaddr_lo = fd_wksp_gaddr_fast( wksp, alloc );
    ulong alloc_gaddr_hi = alloc_gaddr_lo + FD_ALLOC_FOOTPRINT;
    ulong alloc_tag      = alloc->tag;

    ulong                     part_max = wksp->part_max;
    fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );

    for( ulong part_idx=0UL; part_idx<part_max; part_idx++ ) {
      if( pinfo[ part_idx ].tag!=alloc_tag ) continue; /* skip ones that don't match */

      ulong part_gaddr_lo = pinfo[ part_idx ].gaddr_lo;
      ulong part_gaddr_hi = pinfo[ part_idx ].gaddr_hi;
      if( FD_UNLIKELY( !((wksp_gaddr_lo<=part_gaddr_lo) & (part_gaddr_lo<part_gaddr_hi) & (part_gaddr_hi<=wksp_gaddr_hi)) ) ) {
        EMIT( fprintf( stream, "  partition [%013lx,%013lx): invalid\n", part_gaddr_lo, part_gaddr_hi ) );
        ctr[0]++;
        continue;
      }

      ulong part_footprint = part_gaddr_hi - part_gaddr_lo;

      if( FD_UNLIKELY( (part_gaddr_lo<=alloc_gaddr_lo) & (alloc_gaddr_hi<=part_gaddr_hi) ) ) { /* Partition metadata */
        EMIT( fprintf( stream, "  partition [%013lx,%013lx): metadata\n", part_gaddr_lo, part_gaddr_hi ) );
        ctr[2] += 1UL;
        ctr[3] += part_footprint;
        continue;
      }

      if( FD_UNLIKELY( !fd_ulong_is_aligned( part_gaddr_lo, alignof(fd_alloc_hdr_t) ) ) ) {
        EMIT( fprintf( stream, "  partition [%013lx,%013lx): misaligned\n", part_gaddr_lo, part_gaddr_hi ) );
        ctr[0]++;
        continue;
      }

      if( FD_UNLIKELY( part_footprint <= FD_ALLOC_FOOTPRINT_SMALL_THRESH ) ) {
        EMIT( fprintf( stream, "  partition [%013lx,%013lx): runt fd_alloc partition\n", part_gaddr_lo, part_gaddr_hi ) );
        ctr[0]++;
        continue;
      }

      fd_alloc_hdr_t hdr = fd_alloc_hdr_load_no_san( fd_wksp_laddr_fast( wksp, part_gaddr_lo + sizeof(fd_alloc_hdr_t) ) );

      if( FD_LIKELY( (hdr           ==FD_ALLOC_HDR_ROOT_SUPERBLOCK                   ) &
                     (part_footprint==FD_ALLOC_ROOT_SUPERBLOCK_FOOTPRINT             ) &
                     (fd_ulong_is_aligned( part_gaddr_lo, FD_ALLOC_SUPERBLOCK_ALIGN )) ) ) {

        EMIT( fprintf( stream, "  partition [%013lx,%013lx): root superblock\n", part_gaddr_lo, part_gaddr_hi ) );
        ctr[2]++;
        ctr[3] += part_footprint;

        cnt += fd_alloc_private_superblock_fprintf( stream, wksp, part_gaddr_lo, 0UL, part_gaddr_hi,
                                                    1 /*recurse*/, 4UL /*indent*/, ctr );

      } else {

        /* Search the partition for a USER_LARGE fd_alloc_hdr_t.  There
           will be at least one if the partition contains a USER_LARGE
           allocation (if more than one ... the later ones are probably
           user data that looked like a valid hdr).  It is theoretically
           possible for junk in an overaligned alloc to accidentally
           look like a header (in which case, this logic will compute
           the wrong location / max for the user large allocation.  This
           can be avoided by clearing the alignment padding in
           fd_malloc_align_at_least.  Once we have a plausible location
           for the user's large alloc, we can compute bounds to how
           large a size was used.  We use the upper bound the size
           estimate for simplicity (it would take a lot more space and
           time overhead in normal operation to track the exact size and
           alignment requested explicitly). */

        ulong align      = 1UL;
        ulong align_stop = part_footprint - sizeof(fd_alloc_hdr_t);

        for(;;) {

          if( FD_UNLIKELY( align>=align_stop ) ) {
            EMIT( fprintf( stream, "  partition [%013lx,%013lx): alloc header not found\n", part_gaddr_lo, part_gaddr_hi ) );
            ctr[0]++;
            break;
          }

          ulong alloc_gaddr = fd_ulong_align_up( part_gaddr_lo + sizeof(fd_alloc_hdr_t), align );

          fd_alloc_hdr_t hdr = fd_alloc_hdr_load_no_san( fd_wksp_laddr_fast( wksp, alloc_gaddr ) );

          if( FD_LIKELY( hdr==FD_ALLOC_HDR_USER_LARGE ) ) {
            ulong alloc_max = part_gaddr_hi - alloc_gaddr;
            EMIT( fprintf( stream, "  partition [%013lx,%013lx): large user allocation (gaddr %013lx max %lu)\n",
                           part_gaddr_lo, part_gaddr_hi, alloc_gaddr, alloc_max ));
            ctr[2]++;
            ctr[3] += part_footprint;
            ctr[4] += 1UL;
            ctr[5] += part_footprint;
            break;
          }

          align <<= 1;
        }

      }
    }
  }

  /* Print summary statistics */

  EMIT( fprintf( stream,
                 "  summary\n"
                 "    errors detected       %21lu%s\n"
                 "    small alloc cnt       %21lu\n"
                 "    wksp part used        %21lu\n"
                 "    wksp byte used        %21lu\n"
                 "    large alloc part used %21lu\n"
                 "    large alloc byte used %21lu\n",
                 ctr[0], ctr[0] ? " (highly likely spurious if running concurrent and/or with dirty align padding)" : "",
                 ctr[1], ctr[2], ctr[3], ctr[4], ctr[5] ) );

  return (int)fd_ulong_min( cnt, (ulong)INT_MAX );
}
