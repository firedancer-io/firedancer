#include "../fd_util.h"

#define ELE_MAX  (8UL)
#define ELE_IDX_NULL (~0UL)

static struct {
  ulong prev;
  ulong next;
  ulong val;
} ref_ele[ ELE_MAX ];

static ulong ref_pool       = ELE_IDX_NULL;
static ulong ref_dlist_head = ELE_IDX_NULL;
static ulong ref_dlist_tail = ELE_IDX_NULL;

static inline void
ref_pool_init( ulong ele_cnt ) { /* In [0,ELE_MAX] */
  if( !ele_cnt ) {
    ref_pool = ELE_IDX_NULL;
    return;
  }

  ref_pool = 0UL;

  for( ulong ele_idx=1UL; ele_idx<ele_cnt; ele_idx++ ) {
    ref_ele[ ele_idx-1UL ].prev = ELE_IDX_NULL;
    ref_ele[ ele_idx-1UL ].next = ele_idx;
    ref_ele[ ele_idx-1UL ].val  = 0UL;
  }

  ref_ele[ ele_cnt-1UL ].prev = ELE_IDX_NULL;
  ref_ele[ ele_cnt-1UL ].next = ELE_IDX_NULL;
  ref_ele[ ele_cnt-1UL ].val  = 0UL;
}

static inline int           /* 1 if pool has no elements to acquire, 0 otherwise */
ref_pool_is_empty( void ) {
  return ref_pool==ELE_IDX_NULL;
}

static inline ulong            /* ele_idx, ele_idx not in pool on return */
ref_pool_idx_acquire( void ) { /* assumes not empty */
  ulong ele_idx = ref_pool;
  ref_pool = ref_ele[ele_idx].next;
  return ele_idx;
}

static inline void                      /* ele_idx in pool on return */
ref_pool_idx_release( ulong ele_idx ) { /* assumes not in pool and not in dlist */
  ref_ele[ele_idx].next = ref_pool;
  ref_pool              = ele_idx;
}

static inline int            /* 1 if dlist is empty, 0 otherwise */
ref_dlist_is_empty( void ) {
  return ref_dlist_head==ELE_IDX_NULL;
}

static inline ulong
ref_dlist_idx_peek_head( void ) { /* assumes not empty */
  return ref_dlist_head;
}

static inline ulong
ref_dlist_idx_peek_tail( void ) { /* assumes not empty */
  return ref_dlist_tail;
}

static inline void
ref_dlist_idx_push_head( ulong ele_idx ) { /* assumes ele_idx not in dlist and not in pool */
  ulong next_idx = ref_dlist_head;
  ref_ele[ ele_idx ].prev = ELE_IDX_NULL;
  ref_ele[ ele_idx ].next = next_idx;
  if( next_idx==ELE_IDX_NULL ) ref_dlist_tail           = ele_idx;
  else                         ref_ele[ next_idx ].prev = ele_idx;
  ref_dlist_head = ele_idx;
}

static inline void
ref_dlist_idx_push_tail( ulong ele_idx ) { /* assumes ele_idx not in dlist and not in pool */
  ulong prev_idx = ref_dlist_tail;
  ref_ele[ ele_idx ].prev = prev_idx;
  ref_ele[ ele_idx ].next = ELE_IDX_NULL;
  if( prev_idx==ELE_IDX_NULL ) ref_dlist_head           = ele_idx;
  else                         ref_ele[ prev_idx ].next = ele_idx;
  ref_dlist_tail = ele_idx;
}

static inline ulong              /* removed ele_idx, not in dlist and not in pool on return */
ref_dlist_idx_pop_head( void ) { /* assumes not empty */
  ulong ele_idx  = ref_dlist_head;
  ulong next_idx = ref_ele[ ele_idx ].next;
  ref_dlist_head = next_idx;
  if( next_idx==ELE_IDX_NULL ) ref_dlist_tail           = ELE_IDX_NULL;
  else                         ref_ele[ next_idx ].prev = ELE_IDX_NULL;
  return ele_idx;
}

static inline ulong              /* removed ele_idx, not in dlist and not in pool on return */
ref_dlist_idx_pop_tail( void ) { /* assumes not empty */
  ulong ele_idx  = ref_dlist_tail;
  ulong prev_idx = ref_ele[ ele_idx ].prev;
  ref_dlist_tail = prev_idx;
  if( prev_idx==ELE_IDX_NULL ) ref_dlist_head           = ELE_IDX_NULL;
  else                         ref_ele[ prev_idx ].next = ELE_IDX_NULL;
  return ele_idx;
}

static inline void                               /* ele_idx in dlist before dlist_idx on return */
ref_dlist_idx_insert_before( ulong ele_idx,      /* assumes not in dlist and not in pool */
                             ulong dlist_idx ) { /* assumes in dlist */
  ulong prev_idx = ref_ele[ dlist_idx ].prev;

  ref_ele[ ele_idx ].prev = prev_idx;
  ref_ele[ ele_idx ].next = dlist_idx;

  ref_ele[ dlist_idx ].prev =ele_idx;

  if( prev_idx==ELE_IDX_NULL ) ref_dlist_head           = ele_idx;
  else                         ref_ele[ prev_idx ].next = ele_idx;
}

static inline void                              /* ele_idx in dlist after dlist_idx on return */
ref_dlist_idx_insert_after( ulong ele_idx,      /* assumes not in dlist and not in pool */
                            ulong dlist_idx ) { /* assumes in dlist */
  ulong next_idx = ref_ele[ dlist_idx ].next;

  ref_ele[ ele_idx ].next = next_idx;
  ref_ele[ ele_idx ].prev = dlist_idx;

  ref_ele[ dlist_idx ].next =ele_idx;

  if( next_idx==ELE_IDX_NULL ) ref_dlist_tail           = ele_idx;
  else                         ref_ele[ next_idx ].prev = ele_idx;
}

static inline void                      /* ele_idx not in dlist and not in pool on return */
ref_dlist_idx_remove( ulong ele_idx ) { /* assumes in dlist */
  ulong prev_idx = ref_ele[ ele_idx ].prev;
  ulong next_idx = ref_ele[ ele_idx ].next;

  if( prev_idx==ELE_IDX_NULL ) ref_dlist_head           = next_idx;
  else                         ref_ele[ prev_idx ].next = next_idx;

  if( next_idx==ELE_IDX_NULL ) ref_dlist_tail           = prev_idx;
  else                         ref_ele[ next_idx ].prev = prev_idx;
}

static inline void                       /* ele_idx in dlist where old_idx was, old_idx not in dlist and not in pool on return */
ref_dlist_idx_replace( ulong ele_idx,    /* assumes not in dlist and not in pool */
                       ulong old_idx ) { /* assumes in dlist */
  ulong prev_idx = ref_ele[ old_idx ].prev;
  ulong next_idx = ref_ele[ old_idx ].next;

  ref_ele[ ele_idx ].prev = prev_idx;
  ref_ele[ ele_idx ].next = next_idx;

  if( prev_idx==ELE_IDX_NULL ) ref_dlist_head           = ele_idx;
  else                         ref_ele[ prev_idx ].next = ele_idx;

  if( next_idx==ELE_IDX_NULL ) ref_dlist_tail           = ele_idx;
  else                         ref_ele[ next_idx ].prev = ele_idx;
}

#if 0 /* not used */
static inline void             /* all elements that were in dlist are not in dlist and not in pool on return */
ref_dlist_remove_all( void ) {
  ref_dlist_head = ELE_IDX_NULL;
  ref_dlist_tail = ELE_IDX_NULL;
}
#endif

#define CIDX_T uchar

struct tst_ele {
  CIDX_T prev_cidx;
  CIDX_T next_cidx;
  ulong  val;
};

typedef struct tst_ele tst_ele_t;

#define POOL_NAME  tst_pool
#define POOL_T     tst_ele_t
#define POOL_IDX_T CIDX_T
#define POOL_NEXT  next_cidx
#include "fd_pool.c"

#define DLIST_NAME  tst_dlist
#define DLIST_ELE_T tst_ele_t
#define DLIST_IDX_T CIDX_T
#define DLIST_PREV  prev_cidx
#define DLIST_NEXT  next_cidx
#include "fd_dlist.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max", NULL, ELE_MAX );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu)", ele_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define SCRATCH_ALIGN     (128UL)
# define SCRATCH_FOOTPRINT (1024UL)
  uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

  if( FD_UNLIKELY( ele_max>ELE_MAX                                         ) ) FD_LOG_ERR(( "Update ELE_MAX" ));
  if( FD_UNLIKELY( !fd_ulong_is_aligned( tst_pool_align(), SCRATCH_ALIGN ) ) ) FD_LOG_ERR(( "Update SCRATCH_ALIGN" ));
  if( FD_UNLIKELY( tst_pool_footprint( ele_max )>SCRATCH_FOOTPRINT         ) ) FD_LOG_ERR(( "Update SCRATCH_FOOTPRINT" ));

  ref_pool_init( ele_max );
  tst_ele_t * tst_ele = tst_pool_join( tst_pool_new( scratch, ele_max ) );

  FD_LOG_NOTICE(( "Testing construction" ));

  FD_TEST( tst_dlist_ele_max()==(ulong)(CIDX_T)~0UL );

  ulong align = tst_dlist_align();
  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( align<=4096UL );

  ulong footprint = tst_dlist_footprint();
  FD_TEST( !!footprint );
  FD_TEST( !(footprint % align) );

  FD_TEST( !tst_dlist_new( NULL        ) ); /* NULL shmem */
  FD_TEST( !tst_dlist_new( (void *)1UL ) ); /* misaligned shmem */

  tst_dlist_t shmem[1];
  void * shdlist = tst_dlist_new( shmem );
  FD_TEST( shdlist );

  FD_TEST( !tst_dlist_join( NULL        ) ); /* NULL shmem */
  FD_TEST( !tst_dlist_join( (void *)1UL ) ); /* misaligned shmem */

  tst_dlist_t * tst_dlist = tst_dlist_join( shdlist );
  FD_TEST( tst_dlist );

  FD_LOG_NOTICE(( "Testing operations" ));

  FD_TEST( tst_dlist_is_empty( tst_dlist, tst_ele ) );

  for( ulong dlist_cnt=0UL; dlist_cnt<ele_max+1UL; dlist_cnt++ ) {

    /* dlist is empty at this point */

    for( ulong rem=dlist_cnt; rem; rem-- ) {
      ulong ele_idx = tst_pool_idx_acquire( tst_ele );
      tst_ele[ ele_idx ].val = fd_rng_ulong( rng );
      FD_TEST( tst_dlist_idx_push_tail( tst_dlist, ele_idx, tst_ele )==tst_dlist );
    }

    /* dlist has dlist_cnt elements at this point */

    FD_TEST( tst_dlist_is_empty( tst_dlist, tst_ele )==!dlist_cnt );
    FD_TEST( tst_dlist_remove_all( tst_dlist, tst_ele ) );
    FD_TEST( tst_dlist_is_empty( tst_dlist, tst_ele ) );

    /* dlist is empty at this point but we don't know which pool
       elements the remove_all returned to us.  So we reset tst_pool as
       a quick-and-dirty way to get all tst_ele back into the pool. */

    tst_ele = tst_pool_join( tst_pool_new( tst_pool_delete( tst_pool_leave( tst_ele ) ), ele_max ) );
  }

  ulong dlist_cnt = 0UL;

  ulong diag_rem = 0UL;
  for( ulong iter_rem=1000000000UL; iter_rem; iter_rem-- ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      FD_LOG_NOTICE(( "remaining %10lu (dlist_cnt %lu)", iter_rem, dlist_cnt ));
      diag_rem = 50000000UL;
    }
    diag_rem--;

    /* Randomly pick an operation to do */

    ulong r = fd_rng_ulong( rng );

    int op  = (int)(r & 0xfUL); r >>= 4;
    int ele = (int)(r & 1UL);   r >>= 5;

    switch( op ) {

    default: { /* Test empty / peek_head / peek_tail */
      int is_empty = tst_dlist_is_empty( tst_dlist, tst_ele );
      FD_TEST( is_empty==ref_dlist_is_empty() );
      if( FD_UNLIKELY( is_empty ) ) break;

      ulong tst_head = tst_dlist_idx_peek_head( tst_dlist, tst_ele );
      ulong ref_head = ref_dlist_idx_peek_head();
      FD_TEST( tst_head<ele_max );
      FD_TEST( tst_ele[ tst_head ].val==ref_ele[ ref_head ].val );
      FD_TEST( tst_dlist_ele_peek_head      ( tst_dlist, tst_ele )==&tst_ele[ tst_head ] );
      FD_TEST( tst_dlist_ele_peek_head_const( tst_dlist, tst_ele )==&tst_ele[ tst_head ] );

      ulong tst_tail = tst_dlist_idx_peek_tail( tst_dlist, tst_ele );
      ulong ref_tail = ref_dlist_idx_peek_tail();
      FD_TEST( tst_tail<ele_max );
      FD_TEST( tst_ele[ tst_tail ].val==ref_ele[ ref_tail ].val );
      FD_TEST( tst_dlist_ele_peek_tail      ( tst_dlist, tst_ele )==&tst_ele[ tst_tail ] );
      FD_TEST( tst_dlist_ele_peek_tail_const( tst_dlist, tst_ele )==&tst_ele[ tst_tail ] );
      break;
    }

    case 0: { /* Push head */
      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_idx = ref_pool_idx_acquire();
      ulong tst_idx = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );
      ref_ele[ ref_idx ].val = val;
      ref_dlist_idx_push_head( ref_idx );

      tst_ele[ tst_idx ].val = val;
      if( ele ) FD_TEST( tst_dlist_ele_push_head( tst_dlist, &tst_ele[tst_idx], tst_ele )==tst_dlist );
      else      FD_TEST( tst_dlist_idx_push_head( tst_dlist, tst_idx,           tst_ele )==tst_dlist );
      dlist_cnt++;
      break;
    }

    case 1: { /* Push tail */
      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_idx = ref_pool_idx_acquire();
      ulong tst_idx = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );

      ref_ele[ ref_idx ].val = val;
      ref_dlist_idx_push_tail( ref_idx );

      tst_ele[ tst_idx ].val = val;
      if( ele ) FD_TEST( tst_dlist_ele_push_tail( tst_dlist, &tst_ele[tst_idx], tst_ele )==tst_dlist );
      else      FD_TEST( tst_dlist_idx_push_tail( tst_dlist, tst_idx,           tst_ele )==tst_dlist );
      dlist_cnt++;
      break;
    }

    case 2: { /* Pop head */
      if( FD_UNLIKELY( ref_dlist_is_empty() ) ) break;

      ulong ref_idx = ref_dlist_idx_pop_head();
      ulong tst_idx;
      if( ele ) tst_idx = (ulong)(tst_dlist_ele_pop_head( tst_dlist, tst_ele ) - tst_ele);
      else      tst_idx =         tst_dlist_idx_pop_head( tst_dlist, tst_ele );
      FD_TEST( tst_idx<ele_max );
      dlist_cnt--;

      FD_TEST( tst_ele[ tst_idx ].val==ref_ele[ ref_idx ].val );

      ref_pool_idx_release( ref_idx );
      tst_pool_idx_release( tst_ele, tst_idx );
      break;
    }

    case 3: { /* Pop tail */
      if( FD_UNLIKELY( ref_dlist_is_empty() ) ) break;

      ulong ref_idx = ref_dlist_idx_pop_tail();
      ulong tst_idx;
      if( ele ) tst_idx = (ulong)(tst_dlist_ele_pop_tail( tst_dlist, tst_ele ) - tst_ele);
      else      tst_idx =         tst_dlist_idx_pop_tail( tst_dlist, tst_ele );
      FD_TEST( tst_idx<ele_max );
      dlist_cnt--;

      FD_TEST( tst_ele[ tst_idx ].val==ref_ele[ ref_idx ].val );

      ref_pool_idx_release( ref_idx );
      tst_pool_idx_release( tst_ele, tst_idx );
      break;
    }

    case 4: { /* Forward iterator and insert before */

      /* Select the same element from each list uniform IID random */

      if( FD_UNLIKELY( ref_dlist_is_empty() ) ) break;

      ulong ref_ins;
      ulong tst_ins = ele_max;

      ulong depth = r % dlist_cnt; /* In [0,dlist_cnt), note that dlist_cnt>0 at this point */
      ulong rem;

      rem = depth;
      for( ref_ins=ref_dlist_head; ref_ins!=ELE_IDX_NULL; ref_ins=ref_ele[ref_ins].next ) {
        if( !rem ) break;
        rem--;
      }

      rem = depth;
      for( tst_dlist_iter_t tst_iter=tst_dlist_iter_fwd_init( tst_dlist, tst_ele );
           !tst_dlist_iter_done( tst_iter, tst_dlist, tst_ele );
           tst_iter=tst_dlist_iter_fwd_next( tst_iter, tst_dlist, tst_ele ) ) {
        if( !rem ) {
          if( ele ) tst_ins = (ulong)(tst_dlist_iter_ele( tst_iter, tst_dlist, tst_ele ) - tst_ele);
          else      tst_ins =         tst_dlist_iter_idx( tst_iter, tst_dlist, tst_ele );
          break;
        }
        rem--;
      }

      FD_TEST( tst_ins<ele_max );
      FD_TEST( tst_ele[ tst_ins ].val==ref_ele[ ref_ins ].val );

      /* Insert a new element before it if possible */

      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_new = ref_pool_idx_acquire();
      ulong tst_new = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );

      ref_ele[ ref_new ].val = val;
      tst_ele[ tst_new ].val = val;

      ref_dlist_idx_insert_before( ref_new, ref_ins );
      if( ele ) FD_TEST( tst_dlist_ele_insert_before( tst_dlist, &tst_ele[tst_new], &tst_ele[tst_ins], tst_ele )==tst_dlist );
      else      FD_TEST( tst_dlist_idx_insert_before( tst_dlist,          tst_new,           tst_ins,  tst_ele )==tst_dlist );
      dlist_cnt++;
      break;
    }

    case 5: { /* Reverse iterator and insert after */

      /* Select the same element from each list uniform IID random */

      if( FD_UNLIKELY( ref_dlist_is_empty() ) ) break;

      ulong ref_ins;
      ulong tst_ins = ele_max;

      ulong depth = r % dlist_cnt; /* In [0,dlist_cnt), note that dlist_cnt>0 at this point */
      ulong rem;

      rem = depth;
      for( ref_ins=ref_dlist_tail; ref_ins!=ELE_IDX_NULL; ref_ins=ref_ele[ref_ins].prev ) {
        if( !rem ) break;
        rem--;
      }

      rem = depth;
      for( tst_dlist_iter_t tst_iter=tst_dlist_iter_rev_init( tst_dlist, tst_ele );
           !tst_dlist_iter_done( tst_iter, tst_dlist, tst_ele );
           tst_iter=tst_dlist_iter_rev_next( tst_iter, tst_dlist, tst_ele ) ) {
        if( !rem ) {
          if( ele ) tst_ins = (ulong)(tst_dlist_iter_ele( tst_iter, tst_dlist, tst_ele ) - tst_ele);
          else      tst_ins =         tst_dlist_iter_idx( tst_iter, tst_dlist, tst_ele );
          break;
        }
        rem--;
      }

      FD_TEST( tst_ins<ele_max );
      FD_TEST( tst_ele[ tst_ins ].val==ref_ele[ ref_ins ].val );

      /* Insert a new element after it if possible */

      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_new = ref_pool_idx_acquire();
      ulong tst_new = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );

      ref_ele[ ref_new ].val = val;
      tst_ele[ tst_new ].val = val;

      ref_dlist_idx_insert_after( ref_new, ref_ins );
      if( ele ) FD_TEST( tst_dlist_ele_insert_after( tst_dlist, &tst_ele[tst_new], &tst_ele[tst_ins], tst_ele )==tst_dlist );
      else      FD_TEST( tst_dlist_idx_insert_after( tst_dlist,          tst_new,           tst_ins,  tst_ele )==tst_dlist );
      dlist_cnt++;
      break;
    }

    case 6: case 7: { /* Remove (and forward iterator again), use two cases to keep insert and remove balanced statistically */
      if( FD_UNLIKELY( ref_dlist_is_empty() ) ) break;

      ulong ref_del;
      ulong tst_del = ele_max;

      ulong depth = r % dlist_cnt; /* In [0,dlist_cnt), note that dlist_cnt>0 at this point */
      ulong rem;

      rem = depth;
      for( ref_del=ref_dlist_head; ref_del!=ELE_IDX_NULL; ref_del=ref_ele[ref_del].next ) {
        if( !rem ) break;
        rem--;
      }

      rem = depth;
      for( tst_dlist_iter_t tst_iter=tst_dlist_iter_fwd_init( tst_dlist, tst_ele );
           !tst_dlist_iter_done( tst_iter, tst_dlist, tst_ele );
           tst_iter=tst_dlist_iter_fwd_next( tst_iter, tst_dlist, tst_ele ) ) {
        if( !rem ) {
          if( ele ) tst_del = (ulong)(tst_dlist_iter_ele_const( tst_iter, tst_dlist, tst_ele ) - tst_ele);
          else      tst_del =         tst_dlist_iter_idx      ( tst_iter, tst_dlist, tst_ele );
          break;
        }
        rem--;
      }

      FD_TEST( tst_del<ele_max );
      FD_TEST( tst_ele[ tst_del ].val==ref_ele[ ref_del ].val );

      ref_dlist_idx_remove( ref_del );
      if( ele ) FD_TEST( tst_dlist_ele_remove( tst_dlist, &tst_ele[tst_del], tst_ele )==tst_dlist );
      else      FD_TEST( tst_dlist_idx_remove( tst_dlist,          tst_del,  tst_ele )==tst_dlist );
      dlist_cnt--;

      ref_pool_idx_release( ref_del );
      tst_pool_idx_release( tst_ele, tst_del );
      break;
    }

    case 8: { /* replace (and reverse iterator again) */
      if( FD_UNLIKELY( ref_dlist_is_empty() ) ) break;

      /* Select the same element from each list uniform IID random */

      ulong ref_old;
      ulong tst_old = ele_max;

      ulong depth = r % dlist_cnt; /* In [0,dlist_cnt), note that dlist_cnt>0 at this point */
      ulong rem;

      rem = depth;
      for( ref_old=ref_dlist_tail; ref_old!=ELE_IDX_NULL; ref_old=ref_ele[ref_old].prev ) {
        if( !rem ) break;
        rem--;
      }

      rem = depth;
      for( tst_dlist_iter_t tst_iter=tst_dlist_iter_rev_init( tst_dlist, tst_ele );
           !tst_dlist_iter_done( tst_iter, tst_dlist, tst_ele );
           tst_iter=tst_dlist_iter_rev_next( tst_iter, tst_dlist, tst_ele ) ) {
        if( !rem ) {
          if( ele ) tst_old = (ulong)(tst_dlist_iter_ele_const( tst_iter, tst_dlist, tst_ele ) - tst_ele);
          else      tst_old =         tst_dlist_iter_idx      ( tst_iter, tst_dlist, tst_ele );
          break;
        }
        rem--;
      }

      FD_TEST( tst_old<ele_max );
      FD_TEST( tst_ele[ tst_old ].val==ref_ele[ ref_old ].val );

      /* Replace it with a different element if possible */

      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_new = ref_pool_idx_acquire();
      ulong tst_new = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );

      ref_ele[ ref_new ].val = val;
      tst_ele[ tst_new ].val = val;

      ref_dlist_idx_replace( ref_new, ref_old );
      if( ele ) FD_TEST( tst_dlist_ele_replace( tst_dlist, &tst_ele[tst_new], &tst_ele[tst_old], tst_ele )==tst_dlist );
      else      FD_TEST( tst_dlist_idx_replace( tst_dlist,          tst_new,           tst_old,  tst_ele )==tst_dlist );

      ref_pool_idx_release( ref_old );
      tst_pool_idx_release( tst_ele, tst_old );
      break;
    }

    case 9: { /* Test verify */
      FD_TEST( !tst_dlist_verify( tst_dlist, ele_max, tst_ele ) );
      break;
    }

    }
  }

  FD_LOG_NOTICE(( "Test destruction" ));

  FD_TEST( !tst_dlist_leave( NULL ) ); /* NULL dlist */

  FD_TEST( tst_dlist_leave( tst_dlist )==(void *)shdlist );

  FD_TEST( !tst_dlist_delete( NULL        ) ); /* NULL shdlist */
  FD_TEST( !tst_dlist_delete( (void *)1UL ) ); /* misaliged    */

  FD_TEST( tst_dlist_delete( shdlist )==(void *)shmem );

  FD_TEST( !tst_dlist_join  ( shdlist ) ); /* bad magic */
  FD_TEST( !tst_dlist_delete( shdlist ) ); /* bad magic */

  FD_LOG_NOTICE(( "Cleaning up" ));

  tst_pool_delete( tst_pool_leave( tst_ele ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

