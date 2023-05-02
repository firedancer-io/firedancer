/*
  Simple template that implements a pool of elements represented by a
  linear array. Elements can be allocated from the pool and released
  back to it. The intended usage is for a map, such as a hash
  table or red-black tree. Elements of the map are managed by the
  pool and allocated before insertion.
*/

#ifndef MAP_POOL_NAME
#define "Define MAP_POOL_NAME"
#endif

#ifndef MAP_POOL_T
#define "Define MAP_POOL_T"
#endif

/* Namespace macros */
#define MAP_POOL_(n) FD_EXPAND_THEN_CONCAT3(MAP_POOL_NAME,_,n)

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef MAP_POOL_IMPL_STYLE
#define MAP_POOL_IMPL_STYLE 0
#endif

#if MAP_POOL_IMPL_STYLE==0 || MAP_POOL_IMPL_STYLE==1

FD_PROTOTYPES_BEGIN

/*
  E.g. ulong my_pool_align( void );

  Return the byte alignment required by a element pool.
*/
ulong MAP_POOL_(align)( void );
/*
  E.g. ulong my_pool_footprint( ulong max );

  Return the number of bytes of memory required by a pool with the
  given maximum number of elements.
*/
ulong MAP_POOL_(footprint)( ulong max );
/*
  E.g. ulong my_pool_max_for_footprint( ulong footprint );

  Return the recommended maximum number of map elements for a given
  memory footprint.
*/
ulong MAP_POOL_(max_for_footprint)( ulong footprint );
/*
  E.g. void * my_pool_new( void * shmem, ulong max );

  Initialize memory for a element pool for a given maximum number of
  elements. All elements in the pool will be uninitialized and
  available for allocation to start. There must be enough memory for
  the required footprint.
*/
void * MAP_POOL_(new)( void * shmem, ulong  max );
/*
  E.g. my_element_t * my_pool_join( void * shmem );

  Attach to a element pool which is already formatted (possibly in shared
  memory). The resulting pointer represents the pool.
*/
MAP_POOL_T * MAP_POOL_(join)( void * shmem );
/*
  E.g. void * my_pool_leave( my_element_t * join );

  Detach from a element pool. This will not call any "destructors" on the
  elements. If applications require additional memory management, they
  must solve this problem.
*/
void * MAP_POOL_(leave)( MAP_POOL_T * join );
/*
  E.g. void * my_pool_delete( void * shmem );

  Mark a pool as deleted.
*/
void * MAP_POOL_(delete)( void * shmem );
/*
  E.g. ulong my_pool_max( my_element_t const * join );

  Return the maximum number of elements that the pool was configured with.
*/
ulong MAP_POOL_(max)( MAP_POOL_T const * join );
/*
  E.g. my_element_t * my_pool_allocate( my_element_t * join );

  Allocate a element out of a pool. Returns NULL if the pool is fully
  utilized. The application must initialize any values in the element after
  allocation. For example:

    my_element_t * n = my_pool_allocate( join );
    n->value = 456;
*/
MAP_POOL_T * MAP_POOL_(allocate)( MAP_POOL_T * join );
/*
  E.g. void my_pool_release( my_element_t * join, my_element_t * element);

  Release a element back into the pool for later allocation.
*/
void MAP_POOL_(release)( MAP_POOL_T * join, MAP_POOL_T * element );
/*
  Verify that a element is valid for a pool. Log an error and
  terminate if it is not.
*/
void MAP_POOL_(validate_element)( MAP_POOL_T * join, MAP_POOL_T * element );
/*
  E.g. long my_pool_local_to_global( my_element_t * join, my_element_t * elem );

  Convert a local root pointer to a global address which can be stored
  in shared memory. This allows a pool to be relocated. Use
  global_to_local to convert back.
*/
long MAP_POOL_(local_to_global)( MAP_POOL_T * join, MAP_POOL_T * element );
/*
  E.g. my_element_t * my_pool_global_to_local( my_element_t * join, long elem );

  Convert a global address to a local element pointer. This allows a pool
  to be relocated.
*/
MAP_POOL_T * MAP_POOL_(global_to_local)( MAP_POOL_T * join, long element );

#ifdef MAP_POOL_SENTINEL
/*
  Application provided function for initializing a sentinel element
*/
void MAP_POOL_(new_sentinel)( MAP_POOL_T * element );
#endif
                                       
FD_PROTOTYPES_END

struct MAP_POOL_(private) {
  ulong magic;    /* MAP_POOL_MAGIC */
  ulong max;      /* Size of element array */
  uint free;      /* head of free list */
};

typedef struct MAP_POOL_(private) MAP_POOL_(private_t);

/*
  Get the private metadata from a join pointer.
*/
static inline MAP_POOL_(private_t) *
  MAP_POOL_(private_meta)( MAP_POOL_T * join ) {
  return (MAP_POOL_(private_t) *)(((ulong)join) - sizeof(MAP_POOL_(private_t)));
}

/*
  Get the private metadata from a join pointer as a const.
*/
static inline MAP_POOL_(private_t) const *
  MAP_POOL_(private_meta_const)( MAP_POOL_T const * join ) {
  return (MAP_POOL_(private_t) const *)(((ulong)join) - sizeof(MAP_POOL_(private_t)));
}

#endif /* MAP_POOL_IMPL_STYLE==0 || MAP_POOL_IMPL_STYLE==1 */

#if MAP_POOL_IMPL_STYLE==0 || MAP_POOL_IMPL_STYLE==2

/*
  Return the byte alignment required by a element pool.
*/
ulong MAP_POOL_(align)( void ) {
  return fd_ulong_max( alignof(MAP_POOL_T), 64UL );
}

/*
  Get the footprint of the private metadata.
*/
static inline ulong MAP_POOL_(private_meta_footprint)( void ) {
  return fd_ulong_align_up( sizeof(MAP_POOL_(private_t)), MAP_POOL_(align)() );
}

/*
  Return the number of bytes of memory required by a pool with the
  given maximum number of elements.
*/
ulong MAP_POOL_(footprint)( ulong max ) {
  ulong align          = MAP_POOL_(align)();
  ulong meta_footprint = MAP_POOL_(private_meta_footprint)(); /* Multiple of align */
  ulong data_footprint = fd_ulong_align_up( sizeof(MAP_POOL_T)*max, align );
  ulong thresh         = (ULONG_MAX - align - meta_footprint + 1UL) / sizeof(MAP_POOL_T);
  return fd_ulong_if( max > thresh, 0UL, meta_footprint + data_footprint );
}

/*
  Return the recommended maximum number of elements for a given memory
  footprint.
*/
ulong MAP_POOL_(max_for_footprint)( ulong footprint ) {
  ulong meta_footprint = MAP_POOL_(private_meta_footprint)(); /* Multiple of align */
  return (footprint - meta_footprint) / sizeof(MAP_POOL_T);
}

/* Free list terminator */
#ifndef MAP_POOL_NIL
#define MAP_POOL_NIL ~0U
#endif

/* Get the next element in the free list */
#ifndef MAP_POOL_NEXT
/* Just step on whatever is there */
#define MAP_POOL_NEXT(_elem_) (*(uint*)(_elem_))
#endif

/* Arbitrary magic number */
#ifndef MAP_POOL_MAGIC
#define MAP_POOL_MAGIC 3693906804964735521UL
#endif

/*
  Initialize memory for a element pool for a given maximum number of
  elements. All elements in the pool will be uninitialized and available for
  allocation to start. There must be enough memory for the required
  footprint.
*/
void * MAP_POOL_(new)( void * shmem, ulong  max ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, MAP_POOL_(align)() ) ) ) return NULL;

  if( FD_UNLIKELY( !MAP_POOL_(footprint)( max ) ) ) return NULL;

  MAP_POOL_T * join = (MAP_POOL_T *)(((ulong)shmem) + MAP_POOL_(private_meta_footprint)());
  /* Build free list */
  uint last = MAP_POOL_NIL;
  for (uint i = 0; i < max; ++i) {
#ifdef MAP_POOL_SENTINEL
    /* Some maps have a special "sentinel" element which is
       initialized on creation and shouldn't be included in the free
       list */
    if (i == MAP_POOL_SENTINEL) {
      MAP_POOL_(new_sentinel)(join + MAP_POOL_SENTINEL);
      continue;
    }
#endif
    MAP_POOL_NEXT(join + i) = last;
    last = i;
  }

  /* Init metadata */
  MAP_POOL_(private_t) * meta = MAP_POOL_(private_meta)( join );
  meta->magic = MAP_POOL_MAGIC;
  meta->max = max;
  meta->free = last;
  return shmem;
}

/*
  Attach to a element pool which is already formatted (possibly in shared
  memory).
*/
MAP_POOL_T * MAP_POOL_(join)( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, MAP_POOL_(align)() ) ) ) return NULL;

  MAP_POOL_T * join = (MAP_POOL_T *)(((ulong)shmem) + MAP_POOL_(private_meta_footprint)());
  MAP_POOL_(private_t) * meta = MAP_POOL_(private_meta)( join );
  if ( meta->magic != MAP_POOL_MAGIC ) {
    FD_LOG_WARNING(("invalid pool pointer"));
    return NULL;
  }
  
  return join;
}

/*
  Detach from a element pool. This will not call any "destructors" on the
  elements. If applications require additional memory management, they
  must solve this problem.
*/
void * MAP_POOL_(leave)( MAP_POOL_T * join ) {

  if( FD_UNLIKELY( !join ) ) return NULL;

  return (void *)(((ulong)join) - MAP_POOL_(private_meta_footprint)());
}

/*
  Mark a pool as deleted.
*/
void * MAP_POOL_(delete)( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) return NULL;

  MAP_POOL_T * join = (MAP_POOL_T *)(((ulong)shmem) + MAP_POOL_(private_meta_footprint)());
  MAP_POOL_(private_t) * meta = MAP_POOL_(private_meta)( join );
  meta->magic = 0;

  return shmem;
}

/*
  E.g. ulong my_pool_max( my_element_t const * join );

  Return the maximum number of elements that the pool was configured with.
*/
ulong MAP_POOL_(max)( MAP_POOL_T const * join ) {
  MAP_POOL_(private_t) const * meta = MAP_POOL_(private_meta_const)( join );
  return meta->max;
}

/*
  Allocate a element out of a pool. Returns NULL if the pool is fully
  utilized. The application must initialize any values in the element after
  allocation. For example:

    my_element_t * n = my_pool_allocate( join );
    n->value = 456;
*/
MAP_POOL_T * MAP_POOL_(allocate)( MAP_POOL_T * join ) {
  MAP_POOL_(private_t) * meta = MAP_POOL_(private_meta)( join );
  if (meta->free == MAP_POOL_NIL)
    return NULL;
  MAP_POOL_T * element = &join[meta->free];
  meta->free = MAP_POOL_NEXT(element);
  return element;
}

/*
  Release a element back into the pool for later allocation.
*/
void MAP_POOL_(release)( MAP_POOL_T * join, MAP_POOL_T * element ) {
  MAP_POOL_(private_t) * meta = MAP_POOL_(private_meta)( join );
  MAP_POOL_NEXT(element) = meta->free;
  meta->free = (uint)(element - join);
}

/*
  Verify that a element is valid for a pool
*/
void MAP_POOL_(validate_element)( MAP_POOL_T * join, MAP_POOL_T * element ) {
  if (element == NULL)
    return;
  MAP_POOL_(private_t) * meta = MAP_POOL_(private_meta)( join );
  ulong index = (ulong)(element - join);
  if ( FD_UNLIKELY(meta->magic != MAP_POOL_MAGIC || index >= meta->max || element != join + index) )
    FD_LOG_ERR(("invalid element pointer"));
}

/*
  Convert a local element pointer to a global address which can be stored
  in shared memory. This allows a pool to be relocated. Use
  global_to_local to convert back.
*/
long MAP_POOL_(local_to_global)( MAP_POOL_T * join, MAP_POOL_T * element ) {
  return (element == NULL ? -1 : (element - join));
}

/*
  Convert a global address to a local element pointer. This allows a pool
  to be relocated.
*/
MAP_POOL_T * MAP_POOL_(global_to_local)( MAP_POOL_T * join, long element ) {
  return (element == -1 ? NULL : join + element);
}

#endif /* MAP_POOL_IMPL_STYLE==0 || MAP_POOL_IMPL_STYLE==2 */

#undef MAP_POOL_
#undef MAP_POOL_IMPL_STYLE
#undef MAP_POOL_NIL
#undef MAP_POOL_NEXT
#undef MAP_POOL_MAGIC
