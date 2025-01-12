#include "fd_wksp_private.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* This is an implementation detail and not strictly part of the v2
   specification. */

#define FD_WKSP_CHECKPT_V2_CGROUP_MAX (1024UL)

int
fd_wksp_private_checkpt_v2( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            ulong        mode,
                            char const * uinfo,
                            int          frame_style_compressed ) {

  (void)tpool; (void)t0; (void)t1; /* Thread parallelization not currently implemented */

  char const * binfo = fd_log_build_info;

  if( FD_UNLIKELY( !fd_checkpt_frame_style_is_supported( frame_style_compressed ) ) ) {
    FD_LOG_WARNING(( "compressed frames are not supported on this target" ));
    return FD_WKSP_ERR_INVAL;
  }

  int err_fail;

  int            locked  =  0;
  int            fd      = -1;
  fd_checkpt_t * checkpt = NULL;

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  char const * name     = wksp->name;
  ulong        name_len = fd_shmem_name_len( name );
  if( FD_UNLIKELY( !name_len ) ) {
    FD_LOG_WARNING(( "checkpt wksp to \"%s\" failed due to bad name; attempting to continue", path ));
    err_fail = FD_WKSP_ERR_CORRUPT;
    goto fail;
  }

  /* Lock the wksp */

  {
    int _err = fd_wksp_private_lock( wksp ); /* logs details */
    if( FD_UNLIKELY( _err ) ) {
      FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed due to being locked; attempting to continue", name, path ));
      err_fail = _err;
      goto fail;
    }
    locked = 1;
  }

  /* Determine a reasonable number of cgroups (note: in principle we
     could thread parallelize this but it probably isn't worth the extra
     complexity). */

  ulong cgroup_cnt;
  ulong alloc_cnt = 0UL;

  {
#   define WKSP_TEST( c ) do {                                                                                  \
      if( FD_UNLIKELY( !(c) ) ) {                                                                               \
        FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed due to failing test %s; attempting to continue", \
                         name, path, #c ));                                                                     \
        err_fail = FD_WKSP_ERR_CORRUPT;                                                                         \
        goto fail;                                                                                              \
      }                                                                                                         \
    } while(0)

    /* Count the number of allocations by traversing over all partitions
       in reverse order by gaddr_lo (same iteration we will do to assign
       partitions to cgroups), validating as we go. */

    ulong part_max  = wksp->part_max;
    ulong data_lo   = wksp->gaddr_lo;
    ulong data_hi   = wksp->gaddr_hi;
    ulong cycle_tag = wksp->cycle_tag++;

    WKSP_TEST( (0UL<data_lo) & (data_lo<=data_hi) ); /* Valid data region */

    ulong gaddr_last = data_hi;

    ulong part_idx = fd_wksp_private_pinfo_idx( wksp->part_tail_cidx );
    while( !fd_wksp_private_pinfo_idx_is_null( part_idx ) ) {

      /* Load partition metadata and validate it */

      WKSP_TEST( part_idx<part_max );                      /* Valid idx */
      WKSP_TEST( pinfo[ part_idx ].cycle_tag!=cycle_tag ); /* No cycles */
      pinfo[ part_idx ].cycle_tag = cycle_tag;             /* Mark part_idx as visited */

      ulong gaddr_lo = pinfo[ part_idx ].gaddr_lo;
      ulong gaddr_hi = pinfo[ part_idx ].gaddr_hi;
      ulong tag      = pinfo[ part_idx ].tag;

      WKSP_TEST( (data_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi==gaddr_last) ); /* Valid partition range */
      gaddr_last = gaddr_lo;

      /* If this partition holds an allocation, count it */

      alloc_cnt += (ulong)(tag>0UL);

      /* Advance to the previous partition */

      part_idx = fd_wksp_private_pinfo_idx( pinfo[ part_idx ].prev_cidx );
    }

    WKSP_TEST( gaddr_last==data_lo ); /* Complete partitioning */

    /* Compute a reasonable cgroup_cnt for alloc_cnt.  To do this,
       let N be the number of allocations.  We assume they have IID
       sizes with mean U and standard deviation S.  If we assign each
       allocation to 1 of M cgroups IID uniform random (we will do
       better below but we pessimize here), in the limit of N>>M>>1, a
       cgroup's load (total number of allocation bytes assigned to a
       cgroup to compress) is Gaussian (by central limit theorem) with
       mean (N/M)U with standard deviation sqrt(N/M) sqrt(U^2+S^2).

       That is, we are load balanced on average (yay) but there is some
       natural imbalance expected due to statistical fluctuations (boo).
       Noting that allocation sizes are positive, if we further assume
       that S<~U typically (note that it is theoretically possible to
       have a positive valued random variable with S arbitrarily larger
       than U), then the cgroup load standard deviation is typically
       less than sqrt(2N/M) U.

       The load for each cgroup will be approximately independent of
       each other for M>>1.  Extremal value statistics for a Gaussian
       then implies that the least loaded cgroup is typically likely to
       have more than (N/M)U - sqrt(2N/M) U sqrt(2 ln M) load.  We want
       this to be positive such such that the least loaded cgroup will
       typically have some load:

            (N/M)U >> sqrt((4 N ln M)/M))U
         -> (N/M)  >> 4 ln M

       That is, we want pick the number of cgroups such that the number
       of allocations per cgroup on average much greater than a few
       times the natural log of the number of cgroups.

       Given the number of cgroups is at most CGROUP_MAX ~ 1024, the
       above implies if we target more than ~28 allocations per cgroup
       on average, each cgroup is likely to get some load and cgroups
       will be reasonably load balanced on average.  We use 32 below for
       computational convenience. */

    cgroup_cnt = fd_ulong_min( (alloc_cnt+31UL)/32UL, FD_WKSP_CHECKPT_V2_CGROUP_MAX );

#   undef WKSP_TEST
  }

  /* Assign allocations to cgroups (note: in principle we could thread
     parallelize this but it also probably isn't worth the extra
     complexity). */

  uint  cgroup_head_cidx[ FD_WKSP_CHECKPT_V2_CGROUP_MAX ]; /* Head of a linked list for partitions assigned to each cgroup */
  ulong cgroup_alloc_cnt[ FD_WKSP_CHECKPT_V2_CGROUP_MAX ]; /* Number of partitions in each cgroup */

  {

    /* Initialize the cgroups to empty */

    ulong cgroup_load[ FD_WKSP_CHECKPT_V2_CGROUP_MAX ];

    uint null_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
    for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {
      cgroup_head_cidx[ cgroup_idx ] = null_cidx;
      cgroup_alloc_cnt[ cgroup_idx ] = 0UL;
      cgroup_load     [ cgroup_idx ] = 0UL;
    }

    /* Configure cgroup sampling */

    ulong cgroup_cursor = 0UL;
    ulong cgroup_idx    = 0UL;

    /* For all partitions in reverse order by gaddr_lo */

    ulong part_idx = fd_wksp_private_pinfo_idx( wksp->part_tail_cidx );
    while( !fd_wksp_private_pinfo_idx_is_null( part_idx ) ) {

      /* Load partition metadata */

      ulong gaddr_lo = pinfo[ part_idx ].gaddr_lo;
      ulong gaddr_hi = pinfo[ part_idx ].gaddr_hi;
      ulong tag      = pinfo[ part_idx ].tag;

      /* If this partition holds an allocation, deterministically assign
         it to a cgroup in an approximately load balanced way such that
         the assignments will be identical for the same set of
         allocations and cgroup_cnt. */

      if( tag ) { /* ~50/50 */

        /* Sample a handful of cgroups and pick the least loaded to
           approximate a greedy load balance method.  We consider the
           most recently assigned cgroup (which was thought to be
           lightly loaded at the previous assignment), a cyclically
           sampled cgroup (ala striping) and two pseudo-randomly sampled
           cgroups based on the common hash of gaddr_lo (ala random
           assignment).  We don't care if our samples collide; we are
           just trying to improve on load balance over straight striping
           and random sampling (both of which are already asymptotically
           are load balanced as per the above).

           We could use a min-heap here but that would be
           algorithmically more expensive, more complex to implement and
           unlikely to improve load balance much futher (it would be
           the greedy load balance method, which is also asymptotically
           optimal but not perfect ... perfect load balance is a
           computationally hard knapsack like problem but pretty good
           load balance is easy). */

        {
          ulong h = fd_ulong_hash( gaddr_lo );

          ulong i0 = cgroup_idx;             ulong l0 = cgroup_load[ i0 ];
          ulong i1 = cgroup_cursor;          ulong l1 = cgroup_load[ i1 ];
          ulong i2 =  h        % cgroup_cnt; ulong l2 = cgroup_load[ i2 ];
          ulong i3 = (h >> 32) % cgroup_cnt; ulong l3 = cgroup_load[ i3 ];

          i0 = fd_ulong_if( l0<=l1, i0, i1 ); l0 = fd_ulong_min( l0, l1 );
          i1 = fd_ulong_if( l2<=l3, i2, i3 ); l1 = fd_ulong_min( l2, l3 );
          i0 = fd_ulong_if( l0<=l1, i0, i1 ); l0 = fd_ulong_min( l0, l1 );

          cgroup_cursor = fd_ulong_if( cgroup_cursor<cgroup_cnt-1UL, cgroup_cursor+1UL, 0UL );
          cgroup_idx    = i0;
        }

        /* Update this cgroup's partition count and load.  The load is
           currently the total uncompressed bytes of partition metadata
           and data (TODO: consider adding a fixed base cost here to
           account for fixed computational overheads too.  This would be
           an order of magnitude ballpark of the cost of doing 2
           fd_checkpt_buf relative to the marginal cost of checkpointing
           an additional byte for some representative target ... note
           that specific target details should not be incorporated into
           this because then specific checkpt byte stream would be
           sensitive to who wrote the checkpt and ideally checkpt should
           be bit-for-bit identical for identical wksp regardless of the
           target details). */

        cgroup_alloc_cnt[ cgroup_idx ]++;
        cgroup_load     [ cgroup_idx ] += 3UL*sizeof(ulong) + (gaddr_hi - gaddr_lo);

        /* Push this partition onto the cgroup's stack.  Since we are
           iterating over partitions in reverse order by gaddr_lo, the
           stack for each cgroup can be treated as a linked list in
           sorted order by gaddr_lo (helps with metdata
           compressibility). */

        pinfo[ part_idx ].stack_cidx   = cgroup_head_cidx[ cgroup_idx ];
        cgroup_head_cidx[ cgroup_idx ] = fd_wksp_private_pinfo_cidx( part_idx );
      }

      /* Advance to the previous partition */

      part_idx = fd_wksp_private_pinfo_idx( pinfo[ part_idx ].prev_cidx );
    }
  }

  /* At this point, each wksp partitions to checkpt have been assigned
     to a cgroup, the cgroups are approximately load balanced and the
     partitions for each cgroup are given in a singly linked list sorted
     in ascending order by gaddr_lo. */

  /* Create the checkpt file */

  {
    mode_t old_mask = umask( (mode_t)0 );
    fd = open( path, O_CREAT|O_EXCL|O_WRONLY, (mode_t)mode );
    umask( old_mask );
    if( FD_UNLIKELY( fd==-1 ) ) {
      FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed opening file with flags_O_CREAT|O_EXCL|O_WRONLY in mode 0%03lo "
                      "(%i-%s); attempting to continue", name, path, mode, errno, fd_io_strerror( errno ) ));
      err_fail = FD_WKSP_ERR_FAIL;
      goto fail;
    }
  }

  /* Initialize the checkpt */

  ulong frame_off[ FD_WKSP_CHECKPT_V2_CGROUP_MAX+6UL ];
  ulong frame_cnt = 0UL;

  fd_checkpt_t  _checkpt[ 1 ];
  uchar         wbuf[ FD_CHECKPT_WBUF_MIN ];

  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, FD_CHECKPT_WBUF_MIN ); /* logs details */
  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed when initializing; attempting to continue", name, path ));
    err_fail = FD_WKSP_ERR_FAIL;
    goto fail;
  }

# define CHECKPT_OPEN(frame_style) do {                                                                                \
    int _err = fd_checkpt_open_advanced( checkpt, (frame_style), &frame_off[ frame_cnt ] );                            \
    if( FD_UNLIKELY( _err ) ) {                                                                                        \
      FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed when opening a %s frame (%i-%s); attempting to continue", \
                       name, path, #frame_style, _err, fd_checkpt_strerror( _err ) ));                                 \
      err_fail = FD_WKSP_ERR_FAIL;                                                                                     \
      goto fail;                                                                                                       \
    }                                                                                                                  \
  } while(0)

# define CHECKPT_CLOSE() do {                                                                                       \
    frame_cnt++;                                                                                                    \
    int   _err = fd_checkpt_close_advanced( checkpt, &frame_off[ frame_cnt ] ); /* logs details */                  \
    if( FD_UNLIKELY( _err ) ) {                                                                                     \
      FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed when closing a frame (%i-%s); attempting to continue", \
                       name, path, _err, fd_checkpt_strerror( _err ) ));                                            \
      err_fail = FD_WKSP_ERR_FAIL;                                                                                  \
      goto fail;                                                                                                    \
    }                                                                                                               \
  } while(0)

  /* Note: sz must be at most FD_CHECKPT_META_MAX */
# define CHECKPT_META( meta, sz ) do {                                                                                \
    ulong _sz  = (sz);                                                                                                \
    int   _err = fd_checkpt_meta( checkpt, (meta), _sz ); /* logs details */                                          \
    if( FD_UNLIKELY( _err ) ) {                                                                                       \
      FD_LOG_WARNING(( "checkpt to \"%s\" failed when writing %lu bytes metadata %s (%i-%s); attempting to continue", \
                       path, _sz, #meta, _err, fd_checkpt_strerror( _err ) ));                                        \
      err_fail = FD_WKSP_ERR_FAIL;                                                                                    \
      goto fail;                                                                                                      \
    }                                                                                                                 \
  } while(0)

  /* Note: data must exist and be unchanged until frame close */
# define CHECKPT_DATA( data, sz ) do {                                                                            \
    ulong _sz  = (sz);                                                                                            \
    int   _err = fd_checkpt_data( checkpt, (data), _sz ); /* logs details */                                      \
    if( FD_UNLIKELY( _err ) ) {                                                                                   \
      FD_LOG_WARNING(( "checkpt to \"%s\" failed when writing %lu bytes data %s (%i-%s); attempting to continue", \
                       path, _sz, #data, _err, fd_checkpt_strerror( _err ) ));                                    \
      err_fail = FD_WKSP_ERR_FAIL;                                                                                \
      goto fail;                                                                                                  \
    }                                                                                                             \
  } while(0)

  /* Checkpt the header */

  {
    fd_wksp_checkpt_v2_hdr_t hdr[1];

    hdr->magic                  = wksp->magic;
    hdr->style                  = FD_WKSP_CHECKPT_STYLE_V2;
    hdr->frame_style_compressed = frame_style_compressed;
    hdr->reserved               = 0U;
    memset( hdr->name, 0,    FD_SHMEM_NAME_MAX ); /* Make sure trailing zeros clear */
    memcpy( hdr->name, name, name_len          );
    hdr->seed                   = wksp->seed;
    hdr->part_max               = wksp->part_max;
    hdr->data_max               = wksp->data_max;

    CHECKPT_OPEN( FD_CHECKPT_FRAME_STYLE_RAW );
    CHECKPT_DATA( hdr, sizeof(fd_wksp_checkpt_v2_hdr_t) );
    CHECKPT_CLOSE();
  }

  /* Checkpt the info */

  {
    fd_wksp_checkpt_v2_info_t info[1];
    char                      buf[ 65536 ];
    char *                    p = buf;

    info->mode      = mode;
    info->wallclock = fd_log_wallclock();
    info->app_id    = fd_log_app_id   ();
    info->thread_id = fd_log_thread_id();
    info->host_id   = fd_log_host_id  ();
    info->cpu_id    = fd_log_cpu_id   ();
    info->group_id  = fd_log_group_id ();
    info->tid       = fd_log_tid      ();
    info->user_id   = fd_log_user_id  ();

#   define APPEND_CSTR( field, cstr, len ) do { \
      ulong _len = (len);                       \
      memcpy( p, (cstr), _len );                \
      p[ _len ] = '\0';                         \
      info->sz_##field = _len + 1UL;            \
      p += info->sz_##field;                    \
    } while(0)

    APPEND_CSTR( app,    fd_log_app(),    strlen( fd_log_app()    ) ); /* appends at most FD_LOG_NAME_MAX ~ 40 B */
    APPEND_CSTR( thread, fd_log_thread(), strlen( fd_log_thread() ) ); /* " */
    APPEND_CSTR( host,   fd_log_host(),   strlen( fd_log_host()   ) ); /* " */
    APPEND_CSTR( cpu,    fd_log_cpu(),    strlen( fd_log_cpu()    ) ); /* " */
    APPEND_CSTR( group,  fd_log_group(),  strlen( fd_log_group()  ) ); /* " */
    APPEND_CSTR( user,   fd_log_user(),   strlen( fd_log_user()   ) ); /* " */
    APPEND_CSTR( path,   path,            strlen( path            ) ); /* appends at most PATH_MAX-1 ~ 4 KiB */
    APPEND_CSTR( binfo,  binfo,           fd_cstr_nlen( binfo, FD_WKSP_CHECKPT_V2_BINFO_MAX-1UL ) ); /* appends at most 16 KiB */
    APPEND_CSTR( uinfo,  uinfo,           fd_cstr_nlen( uinfo, FD_WKSP_CHECKPT_V2_UINFO_MAX-1UL ) ); /* " */

#   undef APPEND_CSTR

    /* Write the info */

    CHECKPT_OPEN( frame_style_compressed );
    CHECKPT_DATA( info, sizeof(fd_wksp_checkpt_v2_info_t) );
    CHECKPT_DATA( buf,  (ulong)(p-buf)                    );
    CHECKPT_CLOSE();
  }

  /* Checkpt the volume cgroups.  Note: This implementation just
     checkpoints 1 volume with at most CGROUP_MAX cgroup_cnt groups.

     Note: this loop can be parallelized over multiple threads if
     willing to leave holes in the file (and then maybe do a second pass
     to compact the holes or maybe do a planning pass and then a real
     pass or maybe leave the holes and do a second pass of run length
     and entropy coding or maybe write to separate files and distribute
     as a multiple files or maybe use non-POSIX filesystem mojo to
     stitch together the separate files to appear as one file or ...) */

  for( ulong cgroup_idx=0UL; cgroup_idx<cgroup_cnt; cgroup_idx++ ) {

    CHECKPT_OPEN( frame_style_compressed );

    /* Write cgroup commands */

    fd_wksp_checkpt_v2_cmd_t cmd[1];

    ulong part_idx = fd_wksp_private_pinfo_idx( cgroup_head_cidx[ cgroup_idx ] );
    while( !fd_wksp_private_pinfo_idx_is_null( part_idx ) ) {

      /* Command: "meta (tag,gaddr_lo,gaddr_hi)" */

      cmd->meta.tag      = pinfo[ part_idx ].tag;      /* Note: non-zero */
      cmd->meta.gaddr_lo = pinfo[ part_idx ].gaddr_lo;
      cmd->meta.gaddr_hi = pinfo[ part_idx ].gaddr_hi;

      CHECKPT_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );

      part_idx = fd_wksp_private_pinfo_idx( pinfo[ part_idx ].stack_cidx );
    }

    /* Command: "corresponding data follows" */

    cmd->data.tag        = 0UL;
    cmd->data.cgroup_cnt = ULONG_MAX;
    cmd->data.frame_off  = ULONG_MAX;

    CHECKPT_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );

    /* Write cgroup partition data */

    part_idx = fd_wksp_private_pinfo_idx( cgroup_head_cidx[ cgroup_idx ] );
    while( !fd_wksp_private_pinfo_idx_is_null( part_idx ) ) {
      ulong gaddr_lo = pinfo[ part_idx ].gaddr_lo;
      ulong gaddr_hi = pinfo[ part_idx ].gaddr_hi;

      CHECKPT_DATA( fd_wksp_laddr_fast( wksp, gaddr_lo ), gaddr_hi - gaddr_lo );

      part_idx = fd_wksp_private_pinfo_idx( pinfo[ part_idx ].stack_cidx );
    }

    CHECKPT_CLOSE();

  }

  /* Checkpt the volume appendix.  This starts with a command that
     indicates this frame is an appendix for cgroup_cnt cgroups (this
     can be used in a streaming restore to tell when it has reached the
     appendix and in a parallel restore of the appendix so a parallel
     restore thread knows how much it needs to decompress), the offsets
     of each cgroup frame (so parallel restore threads can seek to the
     partitions assigned to them) and the number of partitions in each
     cgroup frame (so that the pinfo on restore can be partitioned over
     parallel restore threads upfront non-atomically and
     deterministically). */

  {
    fd_wksp_checkpt_v2_cmd_t cmd[1];

    /* Command: "appendix for a volume with cgroup_cnt frames and no
       previous volumes" */

    cmd->appendix.tag        = 0UL;
    cmd->appendix.cgroup_cnt = cgroup_cnt;
    cmd->appendix.frame_off  = 0UL;

    CHECKPT_OPEN( frame_style_compressed );
    CHECKPT_META( cmd,              sizeof(fd_wksp_checkpt_v2_cmd_t) ); /* Note: must be meta for restore */
    CHECKPT_DATA( frame_off+2UL,    cgroup_cnt*sizeof(ulong)         );
    CHECKPT_DATA( cgroup_alloc_cnt, cgroup_cnt*sizeof(ulong)         );
    CHECKPT_CLOSE();
  }

  /* Checkpt the volumes frame */

  {
    fd_wksp_checkpt_v2_cmd_t cmd[1];

    /* Command: "no more volumes */

    cmd->volumes.tag        = 0UL;
    cmd->volumes.cgroup_cnt = ULONG_MAX;
    cmd->volumes.frame_off  = frame_off[ frame_cnt-1 ];

    CHECKPT_OPEN( frame_style_compressed );
    CHECKPT_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );
    CHECKPT_CLOSE();
  }

  /* Checkpt the footer */

  {
    fd_wksp_checkpt_v2_ftr_t ftr[1];

    /* Command: "footer for a checkpt with cgroup_cnt total cgroup
       frames" */

    ftr->alloc_cnt                   = alloc_cnt;
    ftr->cgroup_cnt                  = cgroup_cnt;
    ftr->volume_cnt                  = 1UL;
    ftr->frame_off                   = frame_off[ frame_cnt-1U ];
    ftr->checkpt_sz                  = frame_off[ frame_cnt ] + sizeof(fd_wksp_checkpt_v2_ftr_t);
    ftr->data_max                    = wksp->data_max;
    ftr->part_max                    = wksp->part_max;
    ftr->seed                        = wksp->seed;
    memset( ftr->name, 0,    FD_SHMEM_NAME_MAX ); /* Make sure trailing zeros clear */
    memcpy( ftr->name, name, name_len          );
    ftr->reserved                    = 0U;
    ftr->frame_style_compressed      = frame_style_compressed;
    ftr->style                       = FD_WKSP_CHECKPT_STYLE_V2;
    ftr->unmagic                     = ~wksp->magic;

    CHECKPT_OPEN( FD_CHECKPT_FRAME_STYLE_RAW );
    CHECKPT_DATA( ftr, sizeof(fd_wksp_checkpt_v2_ftr_t) );
    CHECKPT_CLOSE();
  }

# undef CHECKPT_DATA
# undef CHECKPT_META
# undef CHECKPT_CLOSE
# undef CHECKPT_OPEN

  /* Finalize the checkpt */

  if( FD_UNLIKELY( !fd_checkpt_fini( checkpt ) ) ) { /* logs details */
    FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed when finalizing; attempting to continue", name, path ));
    checkpt  = NULL;
    err_fail = FD_WKSP_ERR_FAIL;
    goto fail;
  }

  /* Close the file */

  if( FD_UNLIKELY( close( fd ) ) ) {
    FD_LOG_WARNING(( "checkpt wksp \"%s\" to \"%s\" failed when closing; attempting to continue", name, path ));
    fd       = -1;
    err_fail = FD_WKSP_ERR_FAIL;
    goto fail;
  }

  /* Unlock the wksp */

  fd_wksp_private_unlock( wksp );
  locked = 0;

  return FD_WKSP_SUCCESS;

fail:

  /* Release resources that might be reserved */

  if( FD_LIKELY( checkpt ) ) {
    if( FD_UNLIKELY( fd_checkpt_in_frame( checkpt ) ) && FD_UNLIKELY( fd_checkpt_close( checkpt ) ) )
      FD_LOG_WARNING(( "fd_checkpt_close failed; attempting to continue" ));

    if( FD_UNLIKELY( !fd_checkpt_fini( checkpt ) ) ) /* logs details */
      FD_LOG_WARNING(( "fd_checkpt_fini failed; attempting to continue" ));
  }

  if( FD_LIKELY( fd!=-1 ) && FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( locked ) ) fd_wksp_private_unlock( wksp );

  return err_fail;
}
