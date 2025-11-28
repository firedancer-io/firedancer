#include "../fd_util.h"
#if FD_HAS_HOSTED
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define ELE_MAX  (8UL)
#define ELE_IDX_NULL (~0UL)

static struct {
  ulong prev;
  ulong next;
  ulong val;
} ref_ele[ ELE_MAX ];

static ulong ref_pool       = ELE_IDX_NULL;
static ulong ref_slist_head = ELE_IDX_NULL;
static ulong ref_slist_tail = ELE_IDX_NULL;

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
ref_pool_idx_release( ulong ele_idx ) { /* assumes not in pool and not in slist */
  ref_ele[ele_idx].next = ref_pool;
  ref_pool              = ele_idx;
}

static inline int            /* 1 if slist is empty, 0 otherwise */
ref_slist_is_empty( void ) {
  return ref_slist_head==ELE_IDX_NULL;
}

static inline ulong
ref_slist_idx_peek_head( void ) { /* assumes not empty */
  return ref_slist_head;
}

static inline ulong
ref_slist_idx_peek_tail( void ) { /* assumes not empty */
  return ref_slist_tail;
}

static inline void
ref_slist_idx_push_head( ulong ele_idx ) { /* assumes ele_idx not in slist and not in pool */
  ulong next_idx = ref_slist_head;
  ref_ele[ ele_idx ].prev = ELE_IDX_NULL;
  ref_ele[ ele_idx ].next = next_idx;
  if( next_idx==ELE_IDX_NULL ) ref_slist_tail           = ele_idx;
  else                         ref_ele[ next_idx ].prev = ele_idx;
  ref_slist_head = ele_idx;
}

static inline void
ref_slist_idx_push_tail( ulong ele_idx ) { /* assumes ele_idx not in slist and not in pool */
  ulong prev_idx = ref_slist_tail;
  ref_ele[ ele_idx ].prev = prev_idx;
  ref_ele[ ele_idx ].next = ELE_IDX_NULL;
  if( prev_idx==ELE_IDX_NULL ) ref_slist_head           = ele_idx;
  else                         ref_ele[ prev_idx ].next = ele_idx;
  ref_slist_tail = ele_idx;
}

static inline ulong              /* removed ele_idx, not in slist and not in pool on return */
ref_slist_idx_pop_head( void ) { /* assumes not empty */
  ulong ele_idx  = ref_slist_head;
  ulong next_idx = ref_ele[ ele_idx ].next;
  ref_slist_head = next_idx;
  if( next_idx==ELE_IDX_NULL ) ref_slist_tail           = ELE_IDX_NULL;
  else                         ref_ele[ next_idx ].prev = ELE_IDX_NULL;
  return ele_idx;
}

static inline void                              /* ele_idx in slist after slist_idx on return */
ref_slist_idx_insert_after( ulong ele_idx,      /* assumes not in slist and not in pool */
                            ulong slist_idx ) { /* assumes in slist */
  ulong next_idx = ref_ele[ slist_idx ].next;

  ref_ele[ ele_idx ].next = next_idx;
  ref_ele[ ele_idx ].prev = slist_idx;

  ref_ele[ slist_idx ].next =ele_idx;

  if( next_idx==ELE_IDX_NULL ) ref_slist_tail           = ele_idx;
  else                         ref_ele[ next_idx ].prev = ele_idx;
}


#if 0 /* not used */
static inline void             /* all elements that were in slist are not in slist and not in pool on return */
ref_slist_remove_all( void ) {
  ref_slist_head = ELE_IDX_NULL;
  ref_slist_tail = ELE_IDX_NULL;
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
  void * shslist = tst_slist_new( shmem );
  FD_TEST( shslist );

  FD_TEST( !tst_slist_join( NULL        ) ); /* NULL shmem */
  FD_TEST( !tst_slist_join( (void *)1UL ) ); /* misaligned shmem */

  tst_slist_t * tst_slist = tst_slist_join( shslist );
  FD_TEST( tst_slist );

  FD_LOG_NOTICE(( "Testing operations" ));

  FD_TEST( tst_slist_is_empty( tst_slist, tst_ele ) );

  for( ulong slist_cnt=0UL; slist_cnt<ele_max+1UL; slist_cnt++ ) {

    /* slist is empty at this point */

    for( ulong rem=slist_cnt; rem; rem-- ) {
      ulong ele_idx = tst_pool_idx_acquire( tst_ele );
      tst_ele[ ele_idx ].val = fd_rng_ulong( rng );
      FD_TEST( tst_slist_idx_push_tail( tst_slist, ele_idx, tst_ele )==tst_slist );
    }

    /* slist has slist_cnt elements at this point */

    FD_TEST( tst_slist_is_empty( tst_slist, tst_ele )==!slist_cnt );
    FD_TEST( tst_slist_remove_all( tst_slist, tst_ele ) );
    FD_TEST( tst_slist_is_empty( tst_slist, tst_ele ) );

    /* slist is empty at this point but we don't know which pool
       elements the remove_all returned to us.  So we reset tst_pool as
       a quick-and-dirty way to get all tst_ele back into the pool. */

    tst_ele = tst_pool_join( tst_pool_new( tst_pool_delete( tst_pool_leave( tst_ele ) ), ele_max ) );
  }

  ulong slist_cnt = 0UL;

  ulong diag_rem = 0UL;
  for( ulong iter_rem=1000000000UL; iter_rem; iter_rem-- ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      FD_LOG_NOTICE(( "remaining %10lu (slist_cnt %lu)", iter_rem, slist_cnt ));
      diag_rem = 50000000UL;
    }
    diag_rem--;

    /* Randomly pick an operation to do */

    ulong r = fd_rng_ulong( rng );

    int op  = (int)(r & 0xfUL); r >>= 4;
    int ele = (int)(r & 1UL);   r >>= 5;

    switch( op ) {

    default: { /* Test empty / peek_head / peek_tail */
      int is_empty = tst_slist_is_empty( tst_slist, tst_ele );
      FD_TEST( is_empty==ref_slist_is_empty() );
      if( FD_UNLIKELY( is_empty ) ) break;

      ulong tst_head = tst_slist_idx_peek_head( tst_slist, tst_ele );
      ulong ref_head = ref_slist_idx_peek_head();
      FD_TEST( tst_head<ele_max );
      FD_TEST( tst_ele[ tst_head ].val==ref_ele[ ref_head ].val );
      FD_TEST( tst_slist_ele_peek_head      ( tst_slist, tst_ele )==&tst_ele[ tst_head ] );
      FD_TEST( tst_slist_ele_peek_head_const( tst_slist, tst_ele )==&tst_ele[ tst_head ] );

      ulong tst_tail = tst_slist_idx_peek_tail( tst_slist, tst_ele );
      ulong ref_tail = ref_slist_idx_peek_tail();
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
      ref_slist_idx_push_head( ref_idx );

      tst_ele[ tst_idx ].val = val;
      if( ele ) FD_TEST( tst_slist_ele_push_head( tst_slist, &tst_ele[tst_idx], tst_ele )==tst_slist );
      else      FD_TEST( tst_slist_idx_push_head( tst_slist, tst_idx,           tst_ele )==tst_slist );
      slist_cnt++;
      break;
    }

    case 1: { /* Push tail */
      if( FD_UNLIKELY( ref_pool_is_empty() ) ) break;

      ulong ref_idx = ref_pool_idx_acquire();
      ulong tst_idx = tst_pool_idx_acquire( tst_ele );

      ulong val = fd_rng_ulong( rng );

      ref_ele[ ref_idx ].val = val;
      ref_slist_idx_push_tail( ref_idx );

      tst_ele[ tst_idx ].val = val;
      if( ele ) FD_TEST( tst_slist_ele_push_tail( tst_slist, &tst_ele[tst_idx], tst_ele )==tst_slist );
      else      FD_TEST( tst_slist_idx_push_tail( tst_slist, tst_idx,           tst_ele )==tst_slist );
      slist_cnt++;
      break;
    }

    case 2: { /* Pop head */
      if( FD_UNLIKELY( ref_slist_is_empty() ) ) break;

      ulong ref_idx = ref_slist_idx_pop_head();
      ulong tst_idx;
      if( ele ) tst_idx = (ulong)(tst_slist_ele_pop_head( tst_slist, tst_ele ) - tst_ele);
      else      tst_idx =         tst_slist_idx_pop_head( tst_slist, tst_ele );
      FD_TEST( tst_idx<ele_max );
      slist_cnt--;

      FD_TEST( tst_ele[ tst_idx ].val==ref_ele[ ref_idx ].val );

      ref_pool_idx_release( ref_idx );
      tst_pool_idx_release( tst_ele, tst_idx );
      break;
    }

    case 3: { /* Insert after */

      /* Select the same element from each list uniform IID random */

      if( FD_UNLIKELY( ref_slist_is_empty() ) ) break;

      ulong ref_ins;
      ulong tst_ins = ele_max;

      ulong depth = r % slist_cnt; /* In [0,slist_cnt), note that slist_cnt>0 at this point */
      ulong rem;

      rem = depth;
      for( ref_ins=ref_slist_head; ref_ins!=ELE_IDX_NULL; ref_ins=ref_ele[ref_ins].next ) {
        if( !rem ) break;
        rem--;
      }

      rem = depth;
      for( tst_slist_iter_t tst_iter=tst_slist_iter_init( tst_slist, tst_ele );
          !tst_slist_iter_done( tst_iter, tst_slist, tst_ele );
          tst_iter=tst_slist_iter_next( tst_iter, tst_slist, tst_ele ) ) {
        if( !rem ) {
          if( ele ) tst_ins = (ulong)(tst_slist_iter_ele( tst_iter, tst_slist, tst_ele ) - tst_ele);
          else      tst_ins =         tst_slist_iter_idx( tst_iter, tst_slist, tst_ele );
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

      ref_slist_idx_insert_after( ref_new, ref_ins );
      if( ele ) FD_TEST( tst_slist_ele_insert_after( tst_slist, &tst_ele[tst_new], &tst_ele[tst_ins], tst_ele )==tst_slist );
      else      FD_TEST( tst_slist_idx_insert_after( tst_slist,          tst_new,           tst_ins,  tst_ele )==tst_slist );
      slist_cnt++;
      break;
    }

    case 4: { /* Forward iterator */

      if( FD_UNLIKELY( ref_slist_is_empty() ) ) break;

      ulong ref_ins;
      ulong tst_ins = ele_max;

      ulong depth = r % slist_cnt; /* In [0,slist_cnt), note that slist_cnt>0 at this point */
      ulong rem;

      rem = depth;
      for( ref_ins=ref_slist_head; ref_ins!=ELE_IDX_NULL; ref_ins=ref_ele[ref_ins].next ) {
        if( !rem ) break;
        rem--;
      }

      rem = depth;
      for( tst_slist_iter_t tst_iter=tst_slist_iter_init( tst_slist, tst_ele );
           !tst_slist_iter_done( tst_iter, tst_slist, tst_ele );
           tst_iter=tst_slist_iter_next( tst_iter, tst_slist, tst_ele ) ) {
        if( !rem ) {
          if( ele ) tst_ins = (ulong)(tst_slist_iter_ele( tst_iter, tst_slist, tst_ele ) - tst_ele);
          else      tst_ins =         tst_slist_iter_idx( tst_iter, tst_slist, tst_ele );
          break;
        }
        rem--;
      }

      FD_TEST( tst_ins<ele_max );
      FD_TEST( tst_ele[ tst_ins ].val==ref_ele[ ref_ins ].val );
      break;
    }


    case 5: { /* Test verify */
      FD_TEST( !tst_slist_verify( tst_slist, ele_max, tst_ele ) );
      break;
    }

    }
  }

  /* test handholding */
#if FD_HAS_HOSTED && FD_TMPL_USE_HANDHOLDING
  #define FD_EXPECT_LOG_CRIT( CALL ) do {                          \
    FD_LOG_DEBUG(( "Testing that "#CALL" triggers FD_LOG_CRIT" )); \
    pid_t pid = fork();                                            \
    FD_TEST( pid >= 0 );                                           \
    if( pid == 0 ) {                                               \
      fd_log_level_logfile_set( 6 );                               \
      __typeof__(CALL) res = (CALL);                               \
      __asm__("" : "+r"(res));                                     \
      _exit( 0 );                                                  \
    }                                                              \
    int status = 0;                                                \
    wait( &status );                                               \
                                                                   \
    FD_TEST( WIFSIGNALED(status) && WTERMSIG(status)==6 );         \
  } while( 0 )                                                     \

  FD_LOG_NOTICE(( "Testing boundary conditions of operations on an empty slist" ));
  FD_TEST( tst_slist_remove_all( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_idx_peek_head      ( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_ele_peek_tail      ( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_ele_peek_head      ( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_ele_peek_tail_const( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_ele_peek_head_const( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_idx_peek_tail      ( tst_slist, tst_ele ) );
  FD_EXPECT_LOG_CRIT( tst_slist_idx_pop_head       ( tst_slist, tst_ele ) );
#else
  FD_LOG_WARNING(( "skip: testing handholding, requires hosted" ));
#endif

  FD_LOG_NOTICE(( "Test destruction" ));

  FD_TEST( !tst_slist_leave( NULL ) ); /* NULL slist */

  FD_TEST( tst_slist_leave( tst_slist )==(void *)shslist );

  FD_TEST( !tst_slist_delete( NULL        ) ); /* NULL shslist */
  FD_TEST( !tst_slist_delete( (void *)1UL ) ); /* misaligned    */

  FD_TEST( tst_slist_delete( shslist )==(void *)shmem );

  FD_TEST( !tst_slist_join  ( shslist ) ); /* bad magic */
  FD_TEST( !tst_slist_delete( shslist ) ); /* bad magic */

  FD_LOG_NOTICE(( "Cleaning up" ));

  tst_pool_delete( tst_pool_leave( tst_ele ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
