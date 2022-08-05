#include "fd_wksp_private.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <errno.h>
#include <signal.h>
#include <xmmintrin.h>

/* Private APIs **********************************************/

/* fd_wksp_private_make_hole increases the number of partitions in wksp
   by 1.  Returns zero on success and non-zero on failure (e.g. not
   enough room in wksp to increase the number of partitions).  On
   success, new partitions [0,i) will be identical to old partitions
   [0,i).  New partition i will be a hole such that
   old_part[i]==new_part[i]==new_part[i+1] exactly and partitions
   [i+1,new_part_cnt) will be identical to old partition
   [i,old_part_cnt) respectively where new_part_cnt==old_part_cnt+1.
   Partitions on unchanged on failure.  It is okay if
   i==old_part_cnt==new_part_cnt-1.  This just indicates the created
   hole will be at the very end.

   This is implemented that that at all points in time while this is
   running the partition storage will never lose any information about
   existing partitions and there will be at most one hole somewhere in
   the partitions.  As such, if the caller is terminated while doing
   this, the operation can be rolled back by another thread by
   compacting out any holes.  Assumes the caller has the wksp lock. */

static inline int
fd_wksp_private_make_hole( fd_wksp_t * wksp,
                           ulong       i ) {
  ulong part_cnt = wksp->part_cnt;
  if( FD_UNLIKELY( part_cnt>=wksp->part_max ) ) return 1;
  fd_wksp_private_part_t * part = wksp->part;

  /* Make a hole at the end */

  part_cnt++;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( part[part_cnt] ) = part[part_cnt-1UL]; /* This has no impact until wksp->part_cnt is increased (tail clobbering) */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->part_cnt ) = part_cnt; /* Hole is made */
  FD_COMPILER_MFENCE();

  /* We have a hole at partition (old) part_cnt / (new) part_cnt-1UL.
     Move it to partition (old/new) i. */

  for( ulong hole=part_cnt-1UL; hole>i; hole-- ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( part[hole] ) = part[hole-1UL];
  }
  FD_COMPILER_MFENCE();
  return 0;
}

/* fd_wksp_private_compact_holes compacts all holes in the partition.
   The caller promises partitions j for j<i for i in [0,part_cnt) are
   already compact (i==part_cnt is a no-op as such indicates that the
   caller already knows there are no holes).  The compaction is done
   such that, if the caller is terminated doing this, the operation can
   be safely resumed by another thread.  Assumes the caller has the wksp
   lock. */

static inline void
fd_wksp_private_compact_holes( fd_wksp_t * wksp,
                               ulong       i ) {
  ulong                    part_cnt = wksp->part_cnt;
  fd_wksp_private_part_t * part     = wksp->part;

  ulong j = i;
  for( ; i<part_cnt; i++ ) {
    /* At this point partitions <j are known to be compact (and will
       still be compact if this process is terminated and restarted).
       Further we have examined original partitions <i (where j<=i) and
       the compaction has insured that partitions k in (j,i) are where
       the holes found so far are located.  We are looking for end of
       new/old partition j/i (start of new/old partition j+1/i+1).  If
       old partition i ends after the start of new partition j, old
       partition i is not a hole and gives where new partition j should
       end / new partition j+1 should begin. */
    if( fd_wksp_private_part_gaddr( part[i+1UL] )<=fd_wksp_private_part_gaddr( part[j] ) ) continue; /* Partition i is a hole */
    FD_COMPILER_MFENCE();
    FD_VOLATILE( part[j] ) = part[i]; /* Doesn't change partition j start, just sets the active bit correctly (probably
                                         theoretically unnecessary provided holes are introduced into the partition array very
                                         carefully) */
    FD_COMPILER_MFENCE();
    FD_VOLATILE( part[j+1UL] ) = part[i+1UL]; /* End partition j (active bit might not be right for partition j+1 though) */
    FD_COMPILER_MFENCE();
    j++;
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( part[j] ) = part[i]; /* See notes above about setting active bit */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->part_cnt ) = j; /* Discard trailing holes */
  FD_COMPILER_MFENCE();
}

void
fd_wksp_private_lock( fd_wksp_t * wksp ) {
  FD_COMPILER_MFENCE();

  int   warning = 0;
  ulong me      = fd_log_group_id();

  ulong volatile * _owner = &wksp->owner;
  for(;;) {
    ulong pid = FD_ATOMIC_CAS( _owner, ULONG_MAX, me );
    if( pid==ULONG_MAX ) {
      FD_COMPILER_MFENCE();
      return;
    }

    if( pid!=me && kill( (pid_t)pid, 0 ) ) {

      if( errno==ESRCH ) { /* A process died while holding the lock.  Try to recover the lock. */

        if( FD_ATOMIC_CAS( _owner, pid, me )==pid ) {

          /* We reclaimed the lock.  The partitions might be in an
             inconsistent state (specifically, there might be inactive
             partitions adjacent to each other and there might be holes
             ... partitions that are empty).  Find and repair any
             damage.  If we die in repair, it is okay as others will be
             able to complete our repairs. */

          ulong                    part_cnt = wksp->part_cnt;
          fd_wksp_private_part_t * part     = wksp->part;
          
          /* Merging any adjacent inactive partitions that might have
             been left when the owner was killed.  Leading adjacent
             inactive partionings will become holes.  (FIXME: MERGE
             TRAILING TO GET ACTIVE BIT PROPAGATION BETTER TO SPEED UP
             COMPACT HOLES?) */

          for( ulong i=1UL; i<part_cnt; i++ )
            if( ((!fd_wksp_private_part_active( part[i-1UL] )) & (!fd_wksp_private_part_active( part[i] ))) ) {
              FD_COMPILER_MFENCE();
              FD_VOLATILE( part[i] ) = part[i-1UL];
              FD_COMPILER_MFENCE();
            }

          /* Compact out any holes formed above and/or left when the
             owner was killed.  */

          fd_wksp_private_compact_holes( wksp, 0UL );

          /* We have the lock and the partitioning is repaired. */
          FD_COMPILER_MFENCE();
          return;
        }

        /* Somebody beat us to reclaiming the lock ... try again */

      } else { /* Unclear pid status ... issue a warning and try again */

        if( !warning ) {
          FD_LOG_WARNING(( "wksp %s lock is owned by unknown state pid %li (%i-%s); attempting to recover",
                           wksp->name, pid, errno, strerror( errno ) ));
          warning = 1;
        }
      }
    }

    /* At this point, either another thread in this process has the
       lock, another active thread in another process has the lock,
       another unknown status thread in other process has the lock or
       another thread beat us to reclaim the lock from a dead process.
       In any case, we don't have the lock.  Wait a while to limit O/S
       contention and try again. */

    FD_YIELD();
  }

  /* never get here */
}

/* fd_wksp_cstr_parse extracts the name and gaddr from a [name]:[gaddr]
   cstr.  This doesn't actually validate if name is a compliant
   fd_shmem_name.  That will be handled automatically by the fd_shmem
   APIs. */

static char *                              /* Returns name on success, NULL on failure (logs details) */
fd_wksp_cstr_parse( char const * cstr,     /* cstr to parse */
                    char *       name,     /* Non-NULL, room for FD_SHMEM_NAME_MAX bytes, holds name on success,
                                              potentially clobbered otherwise */
                    ulong *      gaddr ) { /* Non-NULL, holds gaddr on success, untouched otherwise */
  if( FD_UNLIKELY( !cstr ) ) {
    FD_LOG_WARNING(( "NULL cstr" ));
    return NULL;
  }

  ulong len      = 0UL;
  ulong name_len = ULONG_MAX;
  for(;;) {
    if( cstr[len]=='\0' ) break;
    if( cstr[len]==':' ) name_len = len;
    len++;
  }
  ulong gaddr_len = len - name_len - 1UL;

  if( FD_UNLIKELY( !name_len ) ) {
    FD_LOG_WARNING(( "no name found; cstr should be of the form [name]:[gaddr]" ));
    return NULL;
  }

  if( FD_UNLIKELY( name_len==ULONG_MAX ) ) {
    FD_LOG_WARNING((  "no ':' found; cstr should be of the form [name]:[gaddr]" ));
    return NULL;
  }

  if( FD_UNLIKELY( !gaddr_len ) ) {
    FD_LOG_WARNING(( "no gaddr found; cstr should be of the form [name]:[gaddr]" ));
    return NULL;
  }

  if( FD_UNLIKELY( name_len>=FD_SHMEM_NAME_MAX ) ) {
    FD_LOG_WARNING(( "name too long" ));
    return NULL;
  }

  fd_memcpy( name, cstr, name_len );
  name[name_len] = '\0';
  gaddr[0] = fd_cstr_to_ulong( cstr + name_len + 1UL );
  return name;
}

/* High level public APIs *********************************************/

static char *
fd_wksp_private_cstr( char const * name,
                      ulong        gaddr,
                      char *       cstr ) {
  fd_cstr_fini( fd_cstr_append_ulong_as_text( fd_cstr_append_char( fd_cstr_append_cstr( fd_cstr_init( cstr ),
    name ), ':' ), ' ', '\0', gaddr, fd_ulong_base10_dig_cnt( gaddr ) ) );
  return cstr;
}

char *
fd_wksp_cstr( fd_wksp_t const * wksp,
              ulong             gaddr,
              char *            cstr ) {

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !( (!gaddr) | ((wksp->gaddr_lo<=gaddr) & (gaddr<wksp->gaddr_hi)) ) ) ) {
    FD_LOG_WARNING(( "unmappable gaddr" ));
    return NULL;
  }

  if( FD_UNLIKELY( !cstr ) ) {
    FD_LOG_WARNING(( "NULL cstr" ));
    return NULL;
  }

  return fd_wksp_private_cstr( wksp->name, gaddr, cstr );
}

char *
fd_wksp_cstr_alloc( char const * name,
                    ulong        align,
                    ulong        sz,
                    char *       cstr ) {
  if( FD_UNLIKELY( !cstr ) ) {
    FD_LOG_WARNING(( "NULL cstr" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_attach( name );
  if( FD_UNLIKELY( !wksp ) ) return NULL; /* logs details */
  /* name must be valid at this point */

  ulong gaddr = fd_wksp_alloc( wksp, align, sz );
  if( FD_UNLIKELY( (!!sz) & (!gaddr) ) ) {
    fd_wksp_detach( wksp ); /* logs details */
    return NULL;
  }

  fd_wksp_detach( wksp ); /* logs details */
  return fd_wksp_private_cstr( name, gaddr, cstr );
}

void
fd_wksp_cstr_free( char const * cstr ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_cstr_parse( cstr, name, &gaddr ) ) ) return; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return;

  fd_wksp_free( wksp, gaddr ); /* logs details */

  fd_wksp_detach( wksp ); /* logs details */
}

void
fd_wksp_cstr_memset( char const * cstr,
                     int          c ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_cstr_parse( cstr, name, &gaddr ) ) ) return; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return;

  fd_wksp_memset( wksp, gaddr, c ); /* logs details */

  fd_wksp_detach( wksp ); /* logs details */
}

void *
fd_wksp_map( char const * cstr ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_cstr_parse( cstr, name, &gaddr ) ) ) return NULL; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return NULL;

  /* While fd_wksp_laddr will accept gaddrs at gaddr_hi, we don't here
     because fd_wksp_unmap is not guaranteed to be able to figure out
     the wksp from the resulting pointer.  (FIXME: CONSIDER FOOTER ON
     WKSP TO ACCOMODATE THIS?) */

  if( FD_UNLIKELY( gaddr==wksp->gaddr_hi ) ) {
    FD_LOG_WARNING(( "out of range gaddr" ));
    fd_wksp_detach( wksp ); /* logs details */
    return NULL;
  }

  void * laddr = fd_wksp_laddr( wksp, gaddr ); /* logs details */
  if( FD_UNLIKELY( !laddr ) ) {
    /* We do a detach here regardless of this being an error case or not
       (i.e. gaddr was NULL) because unmap will not be able to figure
       out which wksp corresponds to the returned NULL */
    fd_wksp_detach( wksp ); /* logs details */
    return NULL;
  }

  return laddr;
}

void
fd_wksp_unmap( void const * laddr ) {
  if( FD_UNLIKELY( !laddr ) ) return; /* Silent because NULL might not be an error case (i.e. gaddr passed to map was 0/NULL) */

  /* Technically more efficient given current implementation to do:
       shmem_leave_addr( laddr );
     but the below is more official from a software maintainability POV */

  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_join_query_by_addr( laddr, info ) ) ) {
    FD_LOG_WARNING(( "laddr does not seem to be from fd_wksp_map" ));
    return;
  }

  fd_wksp_t * wksp = (fd_wksp_t *)info->join;
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "Called within fd_wksp_join or fd_wksp_leave??" ));
    return;
  }

  fd_wksp_detach( wksp ); /* logs details */
}

static void *
fd_wksp_private_join_func( void *                       context,
                           fd_shmem_join_info_t const * info ) {
  (void)context;
  return fd_wksp_join( info->shmem ); /* logs details */
}

fd_wksp_t *
fd_wksp_attach( char const * name ) {
  return (fd_wksp_t *)
    fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, fd_wksp_private_join_func, NULL, NULL ); /* logs details */
}

static void *
fd_wksp_private_leave_func( void *                       context,
                            fd_shmem_join_info_t const * info ) {
  (void)context;
  return fd_wksp_leave( info->join ); /* logs details */
}

void
fd_wksp_detach( fd_wksp_t * wksp ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return;
  }
  fd_shmem_leave( wksp, fd_wksp_private_leave_func, NULL ); /* logs details */
}

char const *
fd_wksp_name( fd_wksp_t const * wksp ) {
  return wksp->name;
}

/* Low level public APIs **********************************************/

ulong
fd_wksp_align( void ) {
  return FD_WKSP_ALLOC_ALIGN_MIN;
}

ulong
fd_wksp_footprint( ulong sz ) {
  return fd_ulong_if( sz<(2UL*FD_WKSP_ALLOC_ALIGN_MIN), 0UL, fd_ulong_align_up( sz, FD_WKSP_ALLOC_ALIGN_MIN ) );
}

void *
fd_wksp_new( void *       shmem,
             char const * name,
             ulong        sz,
             ulong        part_max ) {
  fd_wksp_t * wksp = (fd_wksp_t *)shmem;

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)wksp, FD_WKSP_ALLOC_ALIGN_MIN ) ) ) {
    FD_LOG_WARNING(( "misaligned wksp" ));
    return NULL;
  }

  ulong name_len = fd_shmem_name_len( name );
  if( FD_UNLIKELY( !name_len ) ) {
    FD_LOG_WARNING(( "bad name (%s)", name ? name : "(null)" ));
    return NULL;
  }

  ulong footprint = fd_wksp_footprint( sz );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad size (%lu)", sz ));
    return NULL;
  }

  /* If we maximally partition the data region (e.g. completely covered
     by FD_WKSP_ALLOC_ALIGN_MIN sized partitions), we would have:

       part_max = data_region_sz / ALIGN_MIN

     partitions.  This in turn require partition array of size:

       sizeof(fd_wksp_private_part_t)*(part_max+1)
       
     which in turn is carved out of the overall workspace.  The wksp
     header is also carved out of the workspace as is any padding
     necessary for alignment.  The general upshot is then, we'd like to
     a pick partition max such that:

       hdr_sz + (part_max+1)*sizeof(fd_wksp_private_part_t) + padding + part_max*ALIGN_MIN ~ footprint

     solving for part_max, we have:

       part_max ~ (footprint - hdr_sz - sizeof(fd_wksp_private_part_t) - padding) / (ALIGN_MIN+sizeof(fd_wksp_private_part_t))

     The padding itself is complex function of this but since we'd
     prefer to overestimate part_max, we can just use the lower bound of
     zero, yielding a reasonble tight upper bound of:

       part_max ~ ceil( (footprint - hdr_sz - sizeof(fd_wksp_private_part_t)) / (ALIGN_MIN+sizeof(fd_wksp_private_part_t) ) )

     which in turn can be rewritten C friendly as:

       part_max ~ (footprint - hdr_sz - sizeof(fd_wksp_private_part_t) + ALIGN_MIN+sizeof(fd_wksp_private_part_t)-1U) /
                  (ALIGN_MIN+sizeof(fd_wksp_private_part_t) ) )

     or:

       part_max ~ (footprint - hdr_sz + ALIGN_MIN - 1U) / (ALIGN_MIN+sizeof(fd_wksp_private_part_t))
       
     For a 4KiB align min and 8 byte fd_wksp_private_part_t, this in
     turn implies there is an asymptotic 0.2% overhead for wksp metadata
     storage. */

  ulong part_max_default = (footprint - FD_WKSP_PRIVATE_HDR_SZ + FD_WKSP_ALLOC_ALIGN_MIN - 1UL)
                         / (FD_WKSP_ALLOC_ALIGN_MIN + sizeof(fd_wksp_private_part_t));
  if( ((!part_max) | (part_max>part_max_default)) ) part_max = part_max_default;

  ulong gaddr_lo = fd_ulong_align_up( FD_WKSP_PRIVATE_HDR_SZ + (part_max+1UL)*sizeof(fd_wksp_private_part_t),
                                      FD_WKSP_ALLOC_ALIGN_MIN );
  ulong gaddr_hi = footprint;

  /* Consider zeroing out all wskp memory here (e.g. init padding to
     zero, touch all the memory in the wksp, etc) */

  wksp->owner    = ULONG_MAX;
  wksp->part_cnt = 1UL;
  wksp->part_max = part_max;
  wksp->gaddr_lo = gaddr_lo;
  wksp->gaddr_hi = gaddr_hi;
  fd_memcpy( wksp->name, name, name_len+1UL );
  wksp->part[0]  = fd_wksp_private_part( 0, gaddr_lo );
  wksp->part[1]  = fd_wksp_private_part( 1, gaddr_hi ); /* active is used to indicate there is nothing allocatable beyond the wksp
                                                           end (free makes use of this for merging logic) */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->magic ) = FD_WKSP_MAGIC;
  FD_COMPILER_MFENCE();
  return wksp;
}

fd_wksp_t *
fd_wksp_join( void * shwksp ) {
  fd_wksp_t * wksp = (fd_wksp_t *)shwksp;

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  if( FD_UNLIKELY( wksp->magic!=FD_WKSP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic (region probably not a wksp)" ));
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

  return wksp;
}

void *
fd_wksp_delete( void * shwksp ) {
  fd_wksp_t * wksp = (fd_wksp_t *)shwksp;

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  if( FD_UNLIKELY( wksp->magic!=FD_WKSP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic (region probably not a wksp)" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return wksp;
}

void *
fd_wksp_laddr( fd_wksp_t * wksp,
               ulong       gaddr ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  if( !gaddr ) return NULL; /* "NULL" maps NULL */

  /* Note: <= used for gaddr_hi below to support mapping ranges of the
     form [lo,hi) between local and global address spaces with no
     special handling if allocation put hi to be at the very end of the
     workspace. */

  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) {
    FD_LOG_WARNING(( "out of range gaddr" ));
    return NULL;
  }

  return (void *)(((ulong)wksp) + gaddr);
}

fd_wksp_t *
fd_wksp_containing( void const * laddr ) {
  if( FD_UNLIKELY( !laddr ) ) return NULL;

  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_join_query_by_addr( laddr, info ) ) ) return NULL;

  fd_wksp_t * wksp = (fd_wksp_t *)info->join;
  if( FD_UNLIKELY( !wksp ) ) return NULL;

  if( FD_UNLIKELY( wksp->magic!=FD_WKSP_MAGIC ) ) return NULL;

  return wksp;
}

ulong
fd_wksp_gaddr( fd_wksp_t * wksp,
               void *      laddr ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return 0UL;
  }

  if( !laddr ) return 0UL; /* NULL maps to "NULL" */

  ulong gaddr = ((ulong)laddr) - ((ulong)wksp);
  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) { /* See note above about why <= for gaddr_hi */
    FD_LOG_WARNING(( "out of range laddr" ));
    return 0UL;
  }

  return gaddr;
}

ulong
fd_wksp_alloc( fd_wksp_t * wksp,
               ulong       align,
               ulong       sz ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return 0UL;
  }

  align = fd_ulong_if( !align, FD_WKSP_ALLOC_ALIGN_DEFAULT, align );
  if( FD_UNLIKELY( !fd_ulong_is_pow2( align ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return 0UL;
  }
  align = fd_ulong_max( align, FD_WKSP_ALLOC_ALIGN_MIN );

  if( FD_UNLIKELY( !sz ) ) return 0UL;

  fd_wksp_private_lock( wksp );

  fd_wksp_private_part_t * part     = wksp->part;
  ulong                    part_cnt = wksp->part_cnt;

  for( ulong i=0UL; i<part_cnt; i++ ) {      
    fd_wksp_private_part_t part_i = part[i];
    if( fd_wksp_private_part_active( part_i ) ) continue;

    ulong lo = fd_wksp_private_part_gaddr( part_i );                /* At least FD_WKSP_ALLOC_ALIGN_MIN aligned */
    ulong r0 = fd_ulong_align_up( lo,    align );                   /* " */
    ulong r1 = fd_ulong_align_up( r0+sz, FD_WKSP_ALLOC_ALIGN_MIN ); /* " */
    ulong hi = fd_wksp_private_part_gaddr( part[i+1UL] );           /* " */

    if( ((lo<=r0) & (r0<r1) & (r1<=hi)) ) { /* Implictly covers sz / align so large as to wrap */

      /* Partition i can handle the request (using a first-fit address
         ordered policy with a block size of FD_WKSP_ALLOC_ALIGN_MIN,
         which has empirically found to be very robust to fragmentation
         in the literature).  Split off any leading blocks of partition
         i that would otherwise be lost from request alignment. */

      if( lo<r0 ) {

        /* If we don't have enough free storage to split this partition,
           we use the whole partition for this request (potentially
           wasteful but more a question of when alloc will start failing
           ... this has at least a chance of surviving).  FIXME:
           CONSIDER EXPLORING MORE RANGES? LOGGING A WARNING? */

        if( fd_wksp_private_make_hole( wksp, i+1UL ) ) {
          FD_COMPILER_MFENCE();
          FD_VOLATILE( part[i] ) = fd_wksp_private_part( 1, lo );
          FD_COMPILER_MFENCE();
          fd_wksp_private_unlock( wksp ); /* Inside the partition but free can handle that */
          return r0;
        }

        /* We have a hole at partition i+1 such that
           old_part[i+1]==new_part[i+1]==new_part[i+2] and atomically
           contract/expand partition i/i+1 into the appropriate split. */

        FD_COMPILER_MFENCE();
        FD_VOLATILE( part[i+1UL] ) = fd_wksp_private_part( 0, r0 );
        FD_COMPILER_MFENCE();

        /* At this point, partition i holds the blocks trimmed off to
           align the request and partition i+1 is where the request will
           actually end up.  Advance i into the next partition that will
           end up holding the request. */

        i++;
        lo = r0;
      }

      /* Partition i as tight as possible for the requested alignment
         but might be larger than necessary.  Split off trailing blocks
         of the partition that would otherwise be lost. */

      if( r1<hi ) {

        /* The splitting logic here is identical to the above */

        if( fd_wksp_private_make_hole( wksp, i+1UL ) ) {
          FD_COMPILER_MFENCE();
          FD_VOLATILE( part[i] ) = fd_wksp_private_part( 1, lo );
          FD_COMPILER_MFENCE();
          fd_wksp_private_unlock( wksp );
          return lo;
        }

        FD_COMPILER_MFENCE();
        FD_VOLATILE( part[i+1UL] ) = fd_wksp_private_part( 0, r1 );
        FD_COMPILER_MFENCE();

        /* At this point, partition i+1 holds the blocks trimmed off to
           pack the request tightly and partition i is where the request
           will actually end up. */
      }

      /* Partition i is as tight as possible for the request. */

      FD_COMPILER_MFENCE();
      FD_VOLATILE( part[i] ) = fd_wksp_private_part( 1, lo );
      FD_COMPILER_MFENCE();
      fd_wksp_private_unlock( wksp );
      return lo;
    }

    /* This partition cannot handle the request. */
  }

  /* No partition can handle this request right now.  Fail. */
  fd_wksp_private_unlock( wksp );
  FD_LOG_WARNING(( "No usable workspace free space available" ));
  return 0UL;
}

void
fd_wksp_free( fd_wksp_t * wksp,
              ulong       gaddr ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return;
  }

  if( FD_UNLIKELY( !gaddr ) ) return;

  fd_wksp_private_lock( wksp );

  /* For all active partitions */

  fd_wksp_private_part_t * part     = wksp->part;
  ulong                    part_cnt = wksp->part_cnt;
  for( ulong i=0UL; i<part_cnt; i++ ) {
    fd_wksp_private_part_t part_i = part[i];
    if( !fd_wksp_private_part_active( part[i] ) ) continue;

    ulong lo = fd_wksp_private_part_gaddr( part_i      ); /* At least FD_WKSP_ALLOC_ALIGN_MIN aligned */
    ulong hi = fd_wksp_private_part_gaddr( part[i+1UL] ); /* " */

    /* If addr is in this active partition, ... */

    if( ((lo<=gaddr) & (gaddr<hi)) ) { /* Yes, strict < for hi */

      /* Mark the partition as free */

      FD_COMPILER_MFENCE();
      FD_VOLATILE( part[i] ) = fd_wksp_private_part( 0, lo );
      FD_COMPILER_MFENCE();

      /* At this point, there are at most three contiguous inactive
         partitions and zero holes.  If partition i+1 is also inactive,
         atomically expand/contract partition i/i+1 to make partition i
         the merged partition and partition i+1 a hole.  Since
         part[part_cnt] is marked as active, no bounds checking is
         necessary (but wouldn't otherwise hurt). */

      if( /*(i+1UL)<part_cnt &&*/ !fd_wksp_private_part_active( part[i+1UL] ) ) {
        FD_COMPILER_MFENCE();
        FD_VOLATILE( part[i+1UL] ) = part[i+2UL];
        FD_COMPILER_MFENCE();
      }

      /* At this point, there are at most two contiguous inactive
         partitions and one hole.  If partition i-1 is also inactive,
         atomically expand/contract partition i-1/i to make partition
         i-1 the merged partition and partition i a hole. */

      if( i>0UL && !fd_wksp_private_part_active( part[i-1UL] ) ) {
        FD_COMPILER_MFENCE();
        FD_VOLATILE( part[i] ) = part[i+1UL];
        FD_COMPILER_MFENCE();
      }

      /* At this point, there are no adjacent contiguous inactive
         partitions but either zero, one (at i) or two holes (at i and
         i+1).  Compact them out. */

      fd_wksp_private_compact_holes( wksp, i );

      fd_wksp_private_unlock( wksp );
      return;
    }

    /* This partition cannot handle the request. */
  }

  /* addr not found in a active partition */

  fd_wksp_private_unlock( wksp );
  FD_LOG_WARNING(( "gaddr does not seem to point to a current wksp allocation" ));
}

void
fd_wksp_memset( fd_wksp_t * wksp,
                ulong       gaddr,
                int         c ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return;
  }

  if( FD_UNLIKELY( !gaddr ) ) return;

  fd_wksp_private_lock( wksp );

  /* For all active partitions */

  fd_wksp_private_part_t * part     = wksp->part;
  ulong                    part_cnt = wksp->part_cnt;
  for( ulong i=0UL; i<part_cnt; i++ ) {
    fd_wksp_private_part_t part_i = part[i];
    if( !fd_wksp_private_part_active( part[i] ) ) continue;

    ulong lo = fd_wksp_private_part_gaddr( part_i      ); /* At least FD_WKSP_ALLOC_ALIGN_MIN aligned */
    ulong hi = fd_wksp_private_part_gaddr( part[i+1UL] ); /* " */

    /* If addr is in this active partition, ... */

    if( ((lo<=gaddr) & (gaddr<hi)) ) { /* Yes, strict < for hi */
      fd_memset( fd_wksp_laddr( wksp, gaddr ), c, hi-lo );
      fd_wksp_private_unlock( wksp );
      return;
    }

    /* This partition cannot handle the request. */
  }

  /* addr not found in an active partition */

  fd_wksp_private_unlock( wksp );
  FD_LOG_WARNING(( "gaddr does not seem to point to a current wksp allocation" ));
}

void
fd_wksp_check( fd_wksp_t * wksp ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return;
  }

  ulong owner = FD_VOLATILE_CONST( wksp->owner );
  if( FD_UNLIKELY( owner!=ULONG_MAX ) ) {
    FD_LOG_NOTICE(( "wksp locked (pid %lu)", owner ));
    fd_wksp_private_lock( wksp );
    /* FIXME: CONSIDER MORE INTERNAL INTEGRITY CHECKS IN HERE */
    fd_wksp_private_unlock( wksp );
    FD_LOG_NOTICE(( "wksp unlocked" ));
  }
}

void
fd_wksp_reset( fd_wksp_t * wksp ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return;
  }

  fd_wksp_private_lock( wksp );

  /* Free partition 0 and expand it cover the entire data region to make
     all other partitions holes atomically.  Could be done as two
     separate writes ala:

       FD_COMPILER_MFENCE();
       FD_VOLATILE( wksp->part[0] ) = fd_wksp_private_part( 0, wksp->gaddr_lo );
       FD_COMPILER_MFENCE();
       FD_VOLATILE( wksp->part[1] ) = fd_wksp_private_part( 1, wksp->gaddr_hi );
       FD_COMPILER_MFENCE();

     but it becomes theoretically possible for the caller to be killed
     after the first write such that the effect would only to free
     partition 0.  Doing both writes concurrently makes the entire
     operation atomic.  See note in fd_wksp_new and fd_wksp_free why the
     part[1] is marked as active. */

  FD_COMPILER_MFENCE();
  _mm_store_si128( (__m128i *)wksp->part, _mm_set_epi64x( (long)fd_wksp_private_part( 1, wksp->gaddr_hi ),
                                                          (long)fd_wksp_private_part( 0, wksp->gaddr_lo ) ) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->part_cnt ) = 1UL; /* Trim off all holes */
  FD_COMPILER_MFENCE();

  fd_wksp_private_unlock( wksp );
}

#endif
