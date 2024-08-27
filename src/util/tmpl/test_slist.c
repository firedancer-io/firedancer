#include "../fd_util.h"

#define ELE_MAX  (8UL)
#define ELE_IDX_NULL (~0UL)

static struct {
  ulong next;
  ulong val;
} ref_ele[ ELE_MAX ];

static ulong ref_pool      = ELE_IDX_NULL;
static ulong ref_list_head = ELE_IDX_NULL;
static ulong ref_list_tail = ELE_IDX_NULL;

static inline void
ref_pool_init( ulong ele_cnt ) { /* In [0,ELE_MAX] */
  if( !ele_cnt ) {
    ref_pool = ELE_IDX_NULL;
    return;
  }

  ref_pool = 0UL;

  for( ulong ele_idx=1UL; ele_idx<ele_cnt; ele_idx++ ) {
    ref_ele[ ele_idx-1UL ].next = ele_idx;
    ref_ele[ ele_idx-1UL ].val  = 0UL;
  }

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
ref_pool_idx_release( ulong ele_idx ) { /* assumes not in pool and not in list */
  ref_ele[ele_idx].next = ref_pool;
  ref_pool              = ele_idx;
}

static inline int            /* 1 if list is empty, 0 otherwise */
ref_list_is_empty( void ) {
  return ref_list_head==ELE_IDX_NULL;
}

static inline ulong
ref_list_idx_peek_head( void ) { /* assumes not empty */
  return ref_list_head;
}

static inline ulong
ref_list_idx_peek_tail( void ) { /* assumes not empty */
  return ref_list_tail;
}

static inline void
ref_list_idx_push_head( ulong ele_idx ) { /* assumes ele_idx not in list and not in pool */
  ulong next_idx = ref_list_head;
  ref_ele[ ele_idx ].next = next_idx;
  if( next_idx==ELE_IDX_NULL ) ref_list_tail = ele_idx;
  ref_list_head = ele_idx;
}

static inline void
ref_list_idx_push_tail( ulong ele_idx ) { /* assumes ele_idx not in list and not in pool */
  ulong prev_idx = ref_list_tail;
  ref_ele[ ele_idx ].next = ELE_IDX_NULL;
  if( prev_idx==ELE_IDX_NULL ) ref_list_head            = ele_idx;
  else                         ref_ele[ prev_idx ].next = ele_idx;
  ref_list_tail = ele_idx;
}

static inline ulong              /* removed ele_idx, not in list and not in pool on return */
ref_list_idx_pop_head( void ) { /* assumes not empty */
  ulong ele_idx  = ref_list_head;
  ulong next_idx = ref_ele[ ele_idx ].next;
  ref_list_head = next_idx;
  if( next_idx==ELE_IDX_NULL ) ref_list_tail = ELE_IDX_NULL;
  return ele_idx;
}

#if 0 /* not used */
static inline void             /* all elements that were in list are not in list and not in pool on return */
ref_list_remove_all( void ) {
  ref_list_head = ELE_IDX_NULL;
  ref_list_tail = ELE_IDX_NULL;
}
#endif

#define CIDX_T uchar

struct tst_ele {
  CIDX_T next_cidx;
  ulong  val;
};

typedef struct tst_ele tst_ele_t;

#define POOL_NAME  tst_pool
#define POOL_T     tst_ele_t
#define POOL_IDX_T CIDX_T
#define POOL_NEXT  next_cidx
#include "fd_pool.c"

#define SLIST_NAME  tst_slist
#define SLIST_ELE_T tst_ele_t
#define SLIST_IDX_T CIDX_T
#define SLIST_NEXT  next_cidx
#include "fd_slist.c"

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

  FD_TEST( tst_slist_ele_max()==(ulong)(CIDX_T)~0UL );

  ulong align = tst_slist_align();
  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( align<=4096UL );

  ulong footprint = tst_slist_footprint();
  FD_TEST( !!footprint );
  FD_TEST( !(footprint % align) );

  FD_TEST( !tst_slist_new( NULL        ) ); /* NULL shmem */
  FD_TEST( !tst_slist_new( (void *)1UL ) ); /* misaligned shmem */

  tst_slist_t shmem[1];
  void * shlist = tst_slist_new( shmem );
  FD_TEST( shlist );

  FD_TEST( !tst_slist_join( NULL        ) ); /* NULL shmem */
  FD_TEST( !tst_slist_join( (void *)1UL ) ); /* misaligned shmem */

  tst_slist_t * tst_slist = tst_slist_join( shlist );
  FD_TEST( tst_slist );

  FD_LOG_NOTICE(( "Testing operations" ));

  FD_TEST( tst_slist_is_empty( tst_slist ) );

  for( ulong list_cnt=0UL; list_cnt<ele_max+1UL; list_cnt++ ) {

    /* list is empty at this point */

    for( ulong rem=list_cnt; rem; rem-- ) {
      ulong ele_idx = tst_pool_idx_acquire( tst_ele );
      tst_ele[ ele_idx ].val = fd_rng_ulong( rng );
      FD_TEST( tst_slist_idx_push_tail( tst_slist, ele_idx, tst_ele )==tst_slist );
    }

    /* list has list_cnt elements at this point */

    FD_TEST( tst_slist_is_empty( tst_slist )==!list_cnt );
    FD_TEST( tst_slist_remove_all( tst_slist ) );
    FD_TEST( tst_slist_is_empty( tst_slist ) );

    /* list is empty at this point but we don't know which pool
       elements the remove_all returned to us.  So we reset tst_pool as
       a quick-and-dirty way to get all tst_ele back into the pool. */

    tst_ele = tst_pool_join( tst_pool_new( tst_pool_delete( tst_pool_leave( tst_ele ) ), ele_max ) );
  }

  ulong list_cnt = 0UL;

  ulong diag_rem = 0UL;
  for( ulong iter_rem=1000000000UL; iter_rem; iter_rem-- ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      FD_LOG_NOTICE(( "remaining %10lu (list_cnt %lu)", iter_rem, list_cnt ));
      diag_rem = 50000000UL;
    }
    diag_rem--;

    /* Randomly pick an operation to do */

    ulong r = fd_rng_ulong( rng );

    int op  = (int)(r & 0x7UL); r >>= 3;
    int ele = (int)(r & 1UL);   r >>= 1;

    switch( op ) {

    default: { /* Test empty / peek_head / peek_tail */
      int is_empty = tst_slist_is_empty( tst_slist );
      FD_TEST( is_empty==ref_list_is_empty() );
      if( FD_UNLIKELY( is_empty ) ) break;

      ulong tst_head = tst_slist_idx_peek_head( tst_slist );
      ulong ref_head = ref_list_idx_peek_head();
      FD_TEST( tst_head<ele_max );
      FD_TEST( tst_ele[ tst_head ].val==ref_ele[ ref_head ].val );
      FD_TEST( tst_slist_ele_peek_head      ( tst_slist, tst_ele )==&tst_ele[ tst_head ] );
      FD_TEST( tst_slist_ele_peek_head_const( tst_slist, tst_ele )==&tst_ele[ tst_head ] );

      ulong tst_tail = tst_slist_idx_peek_tail( tst_slist );
      ulong ref_tail = ref_list_idx_peek_tail();
      FD_TEST( tst_tail<ele_max );
      FD_TEST( tst_ele[ tst_tail ].val==ref_ele[ ref_tail ].val );
      FD_TEST( tst_slist_ele_peek_tail      ( tst_slist, tst_ele )==&tst_ele[ tst_tail ] );
      FD_TEST( tst_slist_ele_peek_tail_const( tst_slist, tst_ele )==&tst_ele[ tst_tail ] );
      break;
    }

    case 0: { /* Push head */
      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_idx = ref_pool_idx_acquire();
      ulong tst_idx = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );
      ref_ele[ ref_idx ].val = val;
      ref_list_idx_push_head( ref_idx );

      tst_ele[ tst_idx ].val = val;
      if( ele ) FD_TEST( tst_slist_ele_push_head( tst_slist, &tst_ele[tst_idx], tst_ele )==tst_slist );
      else      FD_TEST( tst_slist_idx_push_head( tst_slist, tst_idx,           tst_ele )==tst_slist );
      list_cnt++;
      break;
    }

    case 1: { /* Push tail */
      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_idx = ref_pool_idx_acquire();
      ulong tst_idx = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );

      ref_ele[ ref_idx ].val = val;
      ref_list_idx_push_tail( ref_idx );

      tst_ele[ tst_idx ].val = val;
      if( ele ) FD_TEST( tst_slist_ele_push_tail( tst_slist, &tst_ele[tst_idx], tst_ele )==tst_slist );
      else      FD_TEST( tst_slist_idx_push_tail( tst_slist, tst_idx,           tst_ele )==tst_slist );
      list_cnt++;
      break;
    }

    case 2: case 3: { /* Pop head, use two cases to keep insert and remove balanced statistically */
      if( FD_UNLIKELY( ref_list_is_empty() ) ) break;

      ulong ref_idx = ref_list_idx_pop_head();
      ulong tst_idx;
      if( ele ) tst_idx = (ulong)(tst_slist_ele_pop_head( tst_slist, tst_ele ) - tst_ele);
      else      tst_idx =         tst_slist_idx_pop_head( tst_slist, tst_ele );
      FD_TEST( tst_idx<ele_max );
      list_cnt--;

      FD_TEST( tst_ele[ tst_idx ].val==ref_ele[ ref_idx ].val );

      ref_pool_idx_release( ref_idx );
      tst_pool_idx_release( tst_ele, tst_idx );
      break;
    }

    case 4: { /* Test verify */
      FD_TEST( !tst_slist_verify( tst_slist, ele_max, tst_ele ) );
      break;
    }

    }
  }

  FD_LOG_NOTICE(( "Test destruction" ));

  FD_TEST( !tst_slist_leave( NULL ) ); /* NULL list */

  FD_TEST( tst_slist_leave( tst_slist )==(void *)shlist );

  FD_TEST( !tst_slist_delete( NULL        ) ); /* NULL shlist */
  FD_TEST( !tst_slist_delete( (void *)1UL ) ); /* misaliged    */

  FD_TEST( tst_slist_delete( shlist )==(void *)shmem );

  FD_LOG_NOTICE(( "Cleaning up" ));

  tst_pool_delete( tst_pool_leave( tst_ele ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

