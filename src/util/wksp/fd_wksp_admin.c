#include "fd_wksp_private.h"

int
fd_wksp_private_lock( fd_wksp_t * wksp ) {
# if FD_WKSP_LOCK_RECLAIM
  int   warning = 0;
#endif
  ulong me      = fd_log_group_id();

  ulong * _owner = &wksp->owner;
  for(;;) {

    /* Note that we emulate CAS on platforms without FD_HAS_ATOMIC
       to minimize the amount of code differences we have to test.  On
       platforms without FD_HAS_ATOMIC, a workspace should not be used
       concurrently though. */

    FD_COMPILER_MFENCE();
#   if FD_HAS_ATOMIC
    ulong pid = FD_ATOMIC_CAS( _owner, ULONG_MAX, me );
#   else
    ulong pid = FD_VOLATILE_CONST( *_owner );
    if( pid==ULONG_MAX ) FD_VOLATILE( *_owner ) = me;
#   endif
    FD_COMPILER_MFENCE();

    if( FD_LIKELY( pid==ULONG_MAX ) ) return FD_WKSP_SUCCESS;

# if FD_WKSP_LOCK_RECLAIM
    int status = fd_log_group_id_query( pid );
    if( FD_UNLIKELY( status==FD_LOG_GROUP_ID_QUERY_DEAD ) ) { /* A process died while holding the lock, try to recover the lock */

      FD_COMPILER_MFENCE();
#     if FD_HAS_ATOMIC
      ulong cur = FD_ATOMIC_CAS( _owner, pid, me );
#     else
      ulong cur = FD_VOLATILE_CONST( *_owner );
      if( cur==pid ) FD_VOLATILE( *_owner ) = me;
#     endif
      FD_COMPILER_MFENCE();

      if( FD_LIKELY( cur==pid ) ) { /* We recovered the lock from the dead pid, try to fix up incomplete ops */

        FD_LOG_WARNING(( "Process %lu died in an operation on wksp %s; verifying", pid, wksp->name ));
        if( FD_LIKELY( !fd_wksp_verify( wksp ) ) ) { /* logs details of issues detected */
          FD_LOG_NOTICE(( "wksp verified" ));
          return FD_WKSP_SUCCESS;
        }

        FD_LOG_WARNING(( "Issues detected; rebuilding" ));
        if( FD_UNLIKELY( fd_wksp_rebuild( wksp, wksp->seed ) ) ) { /* Rebuild failed (logs details of issues detected) */
          /* Return control of the lock to the previous owner */
          FD_COMPILER_MFENCE();
          FD_VOLATILE( *_owner ) = pid;
          FD_COMPILER_MFENCE();
          FD_LOG_WARNING(( "corrupt wksp detected" ));
          return FD_WKSP_ERR_CORRUPT;
        }

        FD_LOG_NOTICE(( "wksp rebuilt" ));
        return FD_WKSP_SUCCESS;

      }

      /* Somebody beat us to recovering the lock ... try again */

    } else if( FD_UNLIKELY( status!=FD_LOG_GROUP_ID_QUERY_LIVE ) ) { /* Unclear pid status ... issue a warning and try again */

      if( FD_UNLIKELY( !warning ) ) {
        FD_LOG_WARNING(( "wksp %s is owned by unknown pid %li; attempting to recover", wksp->name, pid ));
        warning = 1;
      }

    }

    /* At this point, either another thread in this process has the
       lock, another active thread in another process has the lock,
       another unknown status thread in other process has the lock or
       another thread beat us to reclaim the lock from a dead process.
       In any case, we don't have the lock.  Wait a while to limit O/S
       contention and try again. */

    FD_YIELD();
# else

    /* If we are running without FD_WKSP_LOCK_RECLAIM then it is assumed
       that the contention is caused by a tile pinned to another core,
       and that this core is itself pinned so spin locking is best. */
    FD_SPIN_PAUSE();

#endif
  }

  /* never get here */
}

/* Public APIs ********************************************************/

ulong
fd_wksp_part_max_est( ulong footprint,
                      ulong sz_typical ) {
  footprint       = fd_ulong_align_dn( footprint, FD_WKSP_ALIGN );
  ulong data_end  = footprint - 1UL;
  ulong pinfo_off = fd_wksp_private_pinfo_off();
  ulong consumed  = sizeof(fd_wksp_private_pinfo_t) + sz_typical;
  ulong part_max  = (data_end - pinfo_off) / (consumed + (ulong)!consumed); /* avoid div-by-zero */
  if( FD_UNLIKELY( (!footprint) | (!sz_typical) | (sz_typical>consumed) | (pinfo_off>data_end) ) ) return 0UL;
  return fd_ulong_min( part_max, FD_WKSP_PRIVATE_PINFO_IDX_NULL );
}

ulong
fd_wksp_data_max_est( ulong footprint,
                      ulong part_max ) {
  footprint = fd_ulong_align_dn( footprint, FD_WKSP_ALIGN );
  ulong data_end  = footprint - 1UL;
  ulong data_off  = fd_wksp_private_data_off( part_max );
  if( FD_UNLIKELY( (!part_max) | (part_max>FD_WKSP_PRIVATE_PINFO_IDX_NULL) |
                   (part_max > ((ULONG_MAX - fd_wksp_private_pinfo_off())/sizeof(fd_wksp_private_pinfo_t))) | /* covered above */
                   (!footprint) | (data_off>=data_end) ) ) return 0UL;
  return data_end - data_off;
}

ulong
fd_wksp_align( void ) {
  return FD_WKSP_ALIGN;
}

ulong
fd_wksp_footprint( ulong part_max,
                   ulong data_max ) {
  ulong data_off = fd_wksp_private_data_off( part_max );
  if( FD_UNLIKELY( (!part_max) | (part_max>FD_WKSP_PRIVATE_PINFO_IDX_NULL) | (!data_max) |
                   (part_max > ((ULONG_MAX - fd_wksp_private_pinfo_off())/sizeof(fd_wksp_private_pinfo_t))) | /* Covered above */
                   (data_max > (ULONG_MAX - FD_WKSP_ALIGN + 1UL - data_off - 1UL)                         ) ) ) return 0UL;
  return fd_ulong_align_up( data_off + data_max + 1UL, FD_WKSP_ALIGN );
}

void *
fd_wksp_new( void *       shmem,
             char const * name,
             uint         seed,
             ulong        part_max,
             ulong        data_max ) {
  fd_wksp_t * wksp = (fd_wksp_t *)shmem;

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)wksp, FD_WKSP_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return NULL;
  }

  ulong name_len = fd_shmem_name_len( name );
  if( FD_UNLIKELY( !name_len ) ) {
    FD_LOG_WARNING(( "bad name" ));
    return NULL;
  }

  ulong footprint = fd_wksp_footprint( part_max, data_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad part_max and/or data_max" ));
    return NULL;
  }

  fd_memset( wksp, 0, footprint );

  wksp->part_max       = part_max;
  wksp->data_max       = data_max;
  wksp->gaddr_lo       = fd_wksp_private_data_off( part_max );
  wksp->gaddr_hi       = wksp->gaddr_lo + data_max;
  fd_memcpy( wksp->name, name, name_len+1UL );
  wksp->seed           = seed;
  wksp->idle_top_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  wksp->part_head_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  wksp->part_tail_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  wksp->part_used_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  wksp->part_free_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  wksp->cycle_tag      = 4UL;  /* Verify uses tags 0-3 */
  wksp->owner          = 0UL;  /* Mark as locked and in construction */

  /* Note that wksp->owner was set to zero above, "locking" the wksp by
     group_id 0.  And the memset above set all the partition tags to
     zero such that there are no allocated partitions.  So once we set
     magic below, we can finish the initialization by rebuilding and
     unlocking.  Since fd_log_group_id is non-zero, the zero owner
     indicates to any remote observer of the shared memory region that
     the wksp is being built for the first time. */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->magic ) = FD_WKSP_MAGIC;
  FD_COMPILER_MFENCE();

  int err = fd_wksp_rebuild( wksp, seed );
  if( FD_UNLIKELY( err ) ) { /* Should be impossible at this point */

    FD_COMPILER_MFENCE();
    FD_VOLATILE( wksp->magic ) = 0UL;
    FD_COMPILER_MFENCE();

    FD_LOG_WARNING(( "fd_wksp_rebuild failed (%i-%s)", err, fd_wksp_strerror( err ) ));
    return NULL;
  }

  #if FD_HAS_DEEPASAN
  /* Populate entire wksp with human-readable junk bytes to assist with debugging. */

  void * laddr_lo = fd_wksp_laddr_fast( wksp, wksp->gaddr_lo + sizeof(fd_wksp_t) );
  //fd_memset( laddr_lo, 'A', wksp->data_max );
  FD_LOG_NOTICE((" laddr_lo=%lx, sz=%lu", laddr_lo, footprint - sizeof(fd_wksp_t)));
  fd_asan_poison(laddr_lo, footprint - sizeof(fd_wksp_t) );
  #endif 

  fd_wksp_private_unlock( wksp );

  return wksp;
}

fd_wksp_t *
fd_wksp_join( void * shwksp ) {
  fd_wksp_t * wksp = (fd_wksp_t *)shwksp;

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL shwksp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)wksp, FD_WKSP_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return NULL;
  }

  if( FD_UNLIKELY( wksp->magic!=FD_WKSP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return wksp;
}

void *
fd_wksp_leave( fd_wksp_t * wksp ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  return (void *)wksp;
}

void *
fd_wksp_delete( void * shwksp ) {
  fd_wksp_t * wksp = (fd_wksp_t *)shwksp;

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL shwksp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)wksp, FD_WKSP_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return NULL;
  }

  if( FD_UNLIKELY( wksp->magic!=FD_WKSP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  /* TODO: consider testing owner */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  #if FD_HAS_DEEPASAN
  /* Unpoison everything in case region of memory is reallocated at some point.
     Fill wksp bytes with human readable junk for debugging. */
  ulong wksp_footprint = fd_wksp_footprint( wksp->part_max, wksp->data_max );
  fd_asan_unpoison( wksp, wksp_footprint );
  fd_memset( (void*)wksp, 'B', wksp_footprint );
  #endif

  return wksp;
}

char const * fd_wksp_name    ( fd_wksp_t const * wksp ) { return wksp->name;     }
uint         fd_wksp_seed    ( fd_wksp_t const * wksp ) { return wksp->seed;     }
ulong        fd_wksp_part_max( fd_wksp_t const * wksp ) { return wksp->part_max; }
ulong        fd_wksp_data_max( fd_wksp_t const * wksp ) { return wksp->data_max; }

ulong
fd_wksp_owner( fd_wksp_t const * wksp ) {
  FD_COMPILER_MFENCE();
  ulong owner = FD_VOLATILE_CONST( wksp->owner );
  FD_COMPILER_MFENCE();
  return owner;
}

char const *
fd_wksp_strerror( int err ) {
  switch( err ) {
  case FD_WKSP_SUCCESS:     return "success";
  case FD_WKSP_ERR_INVAL:   return "inval";
  case FD_WKSP_ERR_FAIL:    return "fail";
  case FD_WKSP_ERR_CORRUPT: return "corrupt";
  default: break;
  }
  return "unknown";
}

int
fd_wksp_verify( fd_wksp_t * wksp ) {

# define TEST(c) do {                                                                             \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_WKSP_ERR_CORRUPT; } \
  } while(0)

  /* Validate metadata */

  TEST( wksp );
  TEST( wksp->magic==FD_WKSP_MAGIC );

  ulong part_max = wksp->part_max;
  ulong data_max = wksp->data_max;
  TEST( fd_wksp_footprint( part_max, data_max ) );

  ulong gaddr_lo = wksp->gaddr_lo; TEST( gaddr_lo==fd_wksp_private_data_off( part_max ) );
  ulong gaddr_hi = wksp->gaddr_hi; TEST( gaddr_hi==gaddr_lo+data_max                    );

  TEST( fd_shmem_name_len( wksp->name ) );

  /* seed is arbitrary */

  TEST( wksp->cycle_tag >= 4UL );

  /* TODO: consider verifying owner */

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  /* Clear out cycle tags */

  for( ulong i=0UL; i<part_max; i++ ) pinfo[ i ].cycle_tag = 0UL;

  /* Verify the idle stack */

  ulong idle_cnt = 0UL;

  do {
    ulong i = fd_wksp_private_pinfo_idx( wksp->idle_top_cidx );
    while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {

      /* Visit i.  Note that i has not been validated yet. */

      TEST( i<part_max            ); /* Validate i */
      TEST( !pinfo[ i ].cycle_tag ); /* Make sure not visited before */
      pinfo[ i ].cycle_tag = 1UL;    /* Mark as visited in idle stack */
      idle_cnt++;                    /* Update the idle cnt */

      /* Advance to the next idle */

      i = fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx );
    }
  } while(0);

  /* Idle stack looks intact, verify partitioning */

  ulong free_cnt = 0UL;
  ulong used_cnt = 0UL;

  do {
    ulong j = FD_WKSP_PRIVATE_PINFO_IDX_NULL;
    ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
    ulong g = gaddr_lo;

    int last_free = 0;

    while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {

      /* At this point, we last visited j.  Visit i.  Note that j has
         been validated but i has not. */

      TEST( i<part_max                                           ); /* Validate i */
      TEST( pinfo[ i ].gaddr_lo==g                               ); /* Make sure partition is tightly adjacent to previous */
      TEST( pinfo[ i ].gaddr_hi> g                               ); /* Make sure partition size is non-zero */
      TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].prev_cidx )==j ); /* Make sure correct prev partition */
      TEST( !pinfo[ i ].cycle_tag                                ); /* Make sure not visited before */
      pinfo[ i ].cycle_tag = 2UL;                                   /* Mark as visited in partitioning */

      g = pinfo[ i ].gaddr_hi;                                      /* Extract where the next partition should start */
      int is_free = !pinfo[ i ].tag;                                /* Determine if this partition is free or used */
      TEST( !(last_free & is_free) );                               /* Make sure no adjacent free partitions */
      free_cnt += (ulong) is_free;                                  /* Update the free cnt */
      used_cnt += (ulong)!is_free;                                  /* Update the used cnt */

      /* Advance to the next partition */

      last_free = is_free;

      j = i;
      i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
    }

    TEST( fd_wksp_private_pinfo_idx( wksp->part_tail_cidx )==j ); /* Make sure correct partition tail */
    TEST( g==gaddr_hi );                                          /* Make sure complete partitioning */
    TEST( (idle_cnt + free_cnt + used_cnt)==part_max );           /* Make sure no lost idle partitions */
  } while(0);

  /* Idle stack and partitioning look intact, validate used treap */

  do {
    ulong visit_cnt = 0UL;

    ulong i = fd_wksp_private_pinfo_idx( wksp->part_used_cidx );
    ulong s = FD_WKSP_PRIVATE_PINFO_IDX_NULL;
    ulong g = gaddr_lo;

    if( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
      TEST( i<part_max );                                             /* Validate i */
      TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx )==s ); /* Validate parent */
    }

    for(;;) {

      /* At this point i is and everything on stack is validated */

      if( fd_wksp_private_pinfo_idx_is_null( i ) ) {
        if( fd_wksp_private_pinfo_idx_is_null( s ) ) break; /* Done */

        /* Pop stack */

        i = s;
        s = fd_wksp_private_pinfo_idx( pinfo[ i ].stack_cidx );

        /* Visit i */

        ulong p = fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx ); /* Extract the parent */

        TEST( pinfo[ i ].gaddr_lo>=g    );            /* Make sure this starts after last visited */
        TEST( pinfo[ i ].tag            );            /* Make sure tagged as a used partition */
        TEST( pinfo[ i ].cycle_tag==2UL );            /* Make sure in partitioning and not visited yet this traversal */
        if( !fd_wksp_private_pinfo_idx_is_null( p ) ) /* Make sure heap property satisfied */
          TEST( pinfo[ p ].heap_prio >= pinfo[ i ].heap_prio );

        TEST( !pinfo[ i ].in_same );                  /* Make sure unique */
        TEST( fd_wksp_private_pinfo_idx_is_null( fd_wksp_private_pinfo_idx( pinfo[ i ].same_cidx ) ) ); /* " */

        pinfo[ i ].cycle_tag = 3UL;                   /* Mark as visited this traversal */
        visit_cnt++;                                  /* Update the visit cnt */
        g = pinfo[ i ].gaddr_hi;                      /* Get minimum start for next partition */

        /* Traverse the right subtree */

        p = i;
        i = fd_wksp_private_pinfo_idx( pinfo[ i ].right_cidx );
        if( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
          TEST( i<part_max );                                             /* Validate i */
          TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx )==p ); /* Validate parent */
        }

      } else {

        /* At this point i and everything on the stack is validated.
           Push i to the stack and recurse on the left subtree. */

        pinfo[ i ].stack_cidx = fd_wksp_private_pinfo_cidx( s );
        s = i;
        i = fd_wksp_private_pinfo_idx( pinfo[ i ].left_cidx );
        if( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
          TEST( i<part_max );                                             /* Validate i */
          TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx )==s ); /* Validate parent */
        }

      }
    }

    TEST( visit_cnt==used_cnt ); /* Make sure all used partitions in used treap */
  } while(0);

  /* Idle stack, partitioning and used treap look intact, validate the
     free treap. */

  do {
    ulong visit_cnt = 0UL;

    ulong i  = fd_wksp_private_pinfo_idx( wksp->part_free_cidx );
    ulong s  = FD_WKSP_PRIVATE_PINFO_IDX_NULL;
    ulong sz = 0UL;

    if( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
      TEST( i<part_max );                                             /* Validate i */
      TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx )==s ); /* Validate parent */
    }

    for(;;) {

      /* At this point i and everything on the stack is validated */

      if( fd_wksp_private_pinfo_idx_is_null( i ) ) {
        if( fd_wksp_private_pinfo_idx_is_null( s ) ) break; /* Done */

        /* Pop stack */

        i = s;
        s = fd_wksp_private_pinfo_idx( pinfo[ i ].stack_cidx );

        /* Visit i */

        ulong p   = fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx ); /* Extract the parent */
        ulong isz = fd_wksp_private_pinfo_sz( pinfo + i );               /* Extract the size */

        TEST( isz>sz              ); /* Make sure this partition i larger than previous */
        TEST( !pinfo[ i ].tag     ); /* Make sure tagged as a free partition */
        TEST( !pinfo[ i ].in_same ); /* Make sure marked as not in same */

        if( !fd_wksp_private_pinfo_idx_is_null( p ) ) { /* Make sure heap property satisfied */
          TEST( pinfo[ p ].heap_prio >= pinfo[ i ].heap_prio );
        }

        sz = isz; /* Update largest size partition seen so far */

        /* Traverse all same sized partitions */

        ulong j = i;
        for(;;) {

          /* At this point, j is validated */

          TEST( pinfo[ j ].cycle_tag==2UL ); /* Make sure in partitioning and not visited yet this traversal */
          pinfo[ j ].cycle_tag = 3UL;        /* Mark as visited this traversal */
          visit_cnt++;

          ulong k = fd_wksp_private_pinfo_idx( pinfo[ j ].same_cidx );    /* Get the next same sized */
          if( fd_wksp_private_pinfo_idx_is_null( k ) ) break;             /* If no more, we are done with this node */
          TEST( k<part_max );                                             /* Make sure valid index */
          TEST( fd_wksp_private_pinfo_sz( pinfo + k )==sz );              /* Make sure same size */
          TEST( pinfo[ k ].in_same );                                     /* Make sure marked as in same */
          TEST( fd_wksp_private_pinfo_idx_is_null( fd_wksp_private_pinfo_idx( pinfo[ k ].left_cidx  ) ) );
          TEST( fd_wksp_private_pinfo_idx_is_null( fd_wksp_private_pinfo_idx( pinfo[ k ].right_cidx ) ) );
          TEST( fd_wksp_private_pinfo_idx( pinfo[ k ].parent_cidx )==j ); /* Make sure correct parent */
          j = k;
        }

        /* Recurse on the right subtree */

        p = i;
        i = fd_wksp_private_pinfo_idx( pinfo[ i ].right_cidx );
        if( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
          TEST( i<part_max );                                             /* Validate i */
          TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx )==p ); /* Validate parent */
        }

      } else {

        TEST( i<part_max ); /* Validate i */

        /* At this point i and everything on the stack is validated.
           Push i to the stack and recurse on the left subtree. */

        pinfo[ i ].stack_cidx = fd_wksp_private_pinfo_cidx( s );
        s = i;
        i = fd_wksp_private_pinfo_idx( pinfo[ i ].left_cidx );
        if( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
          TEST( i<part_max );                                             /* Validate i */
          TEST( fd_wksp_private_pinfo_idx( pinfo[ i ].parent_cidx )==s ); /* Validate parent */
        }
      }
    }

    TEST( visit_cnt==free_cnt ); /* Make sure all free partitions in free treap */

  } while(0);

# undef TEST

  return FD_WKSP_SUCCESS;
}

int
fd_wksp_rebuild( fd_wksp_t * wksp,
                 uint        seed ) {

  /* Load the wksp metadata, don't rebuild if any of it looks even
     slightly off. */

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return FD_WKSP_ERR_CORRUPT;
  }

  ulong magic     = wksp->magic;
  ulong part_max  = wksp->part_max;
  ulong data_max  = wksp->data_max;
  ulong gaddr_lo  = wksp->gaddr_lo;
  ulong gaddr_hi  = wksp->gaddr_hi;
  ulong cycle_tag = wksp->cycle_tag;

  /* TODO: consider verifying owner */

  ulong footprint    = fd_wksp_footprint( part_max, data_max );
  ulong gaddr_lo_exp = fd_wksp_private_data_off( part_max );
  ulong gaddr_hi_exp = gaddr_lo_exp + data_max;
  if( FD_UNLIKELY( (magic!=FD_WKSP_MAGIC) | (!footprint) | (!fd_shmem_name_len( wksp->name )) |
                   (gaddr_lo!=gaddr_lo_exp) | (gaddr_hi!=gaddr_hi_exp) | (cycle_tag<4UL) ) ) {
    FD_LOG_WARNING(( "bad metadata\n\t"
                     "magic     %016lx (exp %016lx)\n\t"
                     "part_max  %lu data_max %lu (footprint %lu)\n\t"
                     "gaddr_lo  %lu (exp %lu)\n\t"
                     "gaddr_hi  %lu (exp %lu)\n\t"
                     "cycle_tag %lu (exp>=4)",
                     magic, FD_WKSP_MAGIC, part_max, data_max, footprint,
                     gaddr_lo, gaddr_lo_exp, gaddr_hi, gaddr_hi_exp, cycle_tag ));
    return FD_WKSP_ERR_CORRUPT;
  }

  /* Scan the wksp pinfo and insert any used partitions into the used
     treap and put the rest on the idle stack.  If there is any sign of
     corruption (empty, bad range or overlap between used partitions),
     we abort the rebuild (this is almost certainly data corruption of
     some form and we don't have enough info to resolve a conflict
     without potentially making the situation worse).  We do the scan in
     reverse order to rebuild the idle stack in forward order.

     Note that we don't ever change the gaddr_lo,gaddr_hi of any tagged
     partitions such that operation is guaranteed to never change the
     single source of truth.  As such, this operation can be interrupted
     and restarted arbitrarily safely.*/

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  do {
    wksp->seed           = seed;
    wksp->idle_top_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL ); /* Flush idle stack */
    wksp->part_used_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL ); /* Flush used treap */
    wksp->part_free_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL ); /* Flush free treap */

    ulong i = part_max;
    while( i ) {
      i--;

      /* Ideally, heap priorities should just be a shuffling of the
         integers [0,part_max).  fd_uint_hash will generate such a
         shuffling for part_max = 2^32.  Using the lower 30 bits
         (reserving bit 31 for bulk operations) will yield something
         very close.  We use seed to mix it up some more. */

      pinfo[ i ].in_same    = 0U;
      pinfo[ i ].heap_prio  = fd_uint_hash( seed ^ (uint)i ) & ((1U<<30)-1U);
      pinfo[ i ].stack_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
      pinfo[ i ].cycle_tag  = 0U;

      ulong tag = pinfo[ i ].tag;
      if( !tag ) { /* Not used ... make it available for reuse below */
        fd_wksp_private_idle_stack_push( i, wksp, pinfo );
        continue;
      }

      pinfo[ i ].prev_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
      pinfo[ i ].next_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );

      if( FD_UNLIKELY( fd_wksp_private_used_treap_insert( i, wksp, pinfo ) ) ) return FD_WKSP_ERR_CORRUPT; /* Logs details */
    }
  } while(0);

  /* At this point, a partition is either in the idle stack or used
     treap.  Further, we have:

                 | used                       | idle
       ----------+----------------------------+--------
       gaddr_*   | non-empty range            | 0
                 | no overlap with other used | 0
       tag       | non-zero                   | 0
       in_same   | 0                          | 0
       heap_prio | randomized                 | randomized
       prev      | NULL                       | NULL
       next      | NULL                       | NULL
       left      | used treap managed         | NULL
       right     | used treap managed         | NULL
       same      | used treap managed (NULL)  | NULL
       parent    | used treap managed         | idle stack managed
       stack     | wksp managed               | wksp managed
       cycle_tag | wksp managed               | wksp managed

     In-order traverse the used treap to rebuild the partitioning and
     the free treap. */

  do {
    uint * j_next_cidx_ptr = &wksp->part_head_cidx;  /* Location of most recently added partition next link */

    ulong  j  = FD_WKSP_PRIVATE_PINFO_IDX_NULL; /* Most recently added partition */
    ulong  g0 = gaddr_lo;                       /* Most recently added partition end */

    ulong i = fd_wksp_private_pinfo_idx( wksp->part_used_cidx );
    ulong s = FD_WKSP_PRIVATE_PINFO_IDX_NULL;
    for(;;) {
      if( fd_wksp_private_pinfo_idx_is_null( i ) ) {
        if( fd_wksp_private_pinfo_idx_is_null( s ) ) break; /* Done */

        /* Pop traversal stack */

        i = s;
        s = fd_wksp_private_pinfo_idx( pinfo[ i ].stack_cidx );

        /* Visit i */

        ulong g1 = pinfo[ i ].gaddr_lo;
        if( g1 > g0 ) { /* There's a gap between i and the most recently added partition */

          /* Acquire an idle partition to hold the gap */

          if( FD_UNLIKELY( fd_wksp_private_idle_stack_is_empty( wksp ) ) ) {
            FD_LOG_WARNING(( "part_max (%lu) too small to fill gap before partition %lu (tag %lu gaddr_lo %lu gaddr_hi %lu)",
                             part_max, i, pinfo[i].tag, pinfo[i].gaddr_lo, pinfo[i].gaddr_hi ));
            return FD_WKSP_ERR_CORRUPT;
          }
          ulong k = fd_wksp_private_idle_stack_pop( wksp, pinfo );

          /* Populate the acquired partition with the gap details,
             append it to the wksp partitioning and insert it into the
             free treap.  Note that stack_push/pop reset gaddr_lo,
             gaddr_hi, tag, in_same, {prev, next, left, right, same,
             parent}_cidx.  It preserved heap_prio from its original
             assignment and didn't touch stack_cidx or cycle_tag. */

          pinfo[ k ].gaddr_lo  = g0;
          pinfo[ k ].gaddr_hi  = g1;
          pinfo[ k ].prev_cidx = fd_wksp_private_pinfo_cidx( j );
          *j_next_cidx_ptr = fd_wksp_private_pinfo_cidx( k );
          j_next_cidx_ptr  = &pinfo[ k ].next_cidx;
          j  = k;
          g0 = g1;

          fd_wksp_private_free_treap_insert( j, wksp, pinfo );
        }

        /* Add i to the partitioning. */

        pinfo[ i ].prev_cidx = fd_wksp_private_pinfo_cidx( j );
        *j_next_cidx_ptr = fd_wksp_private_pinfo_cidx( i );
        j_next_cidx_ptr  = &pinfo[ i ].next_cidx;
        j  = i;
        g0 = pinfo[ i ].gaddr_hi;

        /* Traverse the right subtree */

        i = fd_wksp_private_pinfo_idx( pinfo[ i ].right_cidx );

      } else {

        /* Push i to the stack and recurse on the left subtree. */

        pinfo[ i ].stack_cidx = fd_wksp_private_pinfo_cidx( s );
        s = i;
        i = fd_wksp_private_pinfo_idx( pinfo[ i ].left_cidx );

      }
    }

    if( g0 < gaddr_hi ) { /* Have final gap to fill */

      /* This works the same as the above */

      if( FD_UNLIKELY( fd_wksp_private_idle_stack_is_empty( wksp ) ) ) {
        FD_LOG_WARNING(( "part_max (%lu) too small to complete partitioning", part_max ));
        return FD_WKSP_ERR_CORRUPT;
      }
      ulong k = fd_wksp_private_idle_stack_pop( wksp, pinfo );

      pinfo[ k ].gaddr_lo  = g0;
      pinfo[ k ].gaddr_hi  = gaddr_hi;
      pinfo[ k ].prev_cidx = fd_wksp_private_pinfo_cidx( j );
      *j_next_cidx_ptr = fd_wksp_private_pinfo_cidx( k );
      j_next_cidx_ptr  = &pinfo[ k ].next_cidx;
      j  = k;
    //g0 = gaddr_hi;

      fd_wksp_private_free_treap_insert( j, wksp, pinfo );
    }

    wksp->part_tail_cidx = fd_wksp_private_pinfo_cidx( j );

  } while(0);

  return FD_WKSP_SUCCESS;
}
