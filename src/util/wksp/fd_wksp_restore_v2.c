#include "fd_wksp_private.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* This is an implementation detail and not strictly part of the v2
   specification. */

#define FD_WKSP_RESTORE_V2_CGROUP_MAX (1024UL)

/* Note: restore not in frame on entry, restore at off on exit.  Jumps
   to fail on error (logs details). */

#define RESTORE_SEEK(off) do {                                                          \
    ulong _off = (off);                                                                 \
    if( FD_UNLIKELY( fd_restore_seek( restore, _off ) ) ) goto fail; /* logs details */ \
  } while(0)

/* Note: restore not in frame and at start of frame on entry, restore in
   frame on exit.  Jumps to fail on error (logs details). */

#define RESTORE_OPEN(frame_style) do {                                                                                \
    if( FD_UNLIKELY( fd_restore_open_advanced( restore, (frame_style), &frame_off ) ) ) goto fail; /* logs details */ \
  } while(0)

/* Note: restore in frame on entry, restore just after frame on exit.
   Assumes frame fully processed.  Jumps to fail on error (logs
   details).  */

#define RESTORE_CLOSE() do {                                                                            \
    if( FD_UNLIKELY( fd_restore_close_advanced( restore, &frame_off ) ) ) goto fail; /* logs details */ \
  } while(0)

/* Note: restore in frame at meta and sz must be at most
   FD_RESTORE_META_MAX on entry, restore in frame at just past meta with
   meta ready on exit.  Jumps to fail on error (logs details). */

#define RESTORE_META( meta, sz ) do {                                        \
    ulong _sz  = (sz);                                                       \
    int   _err = fd_restore_meta( restore, (meta), _sz ); /* logs details */ \
    if( FD_UNLIKELY( _err ) ) {                                              \
      FD_LOG_WARNING(( "fd_restore_meta( %s, %lu ) failed (%i-%s)",          \
                       #meta, _sz, _err, fd_checkpt_strerror( _err ) ));     \
      goto fail;                                                             \
    }                                                                        \
  } while(0)

/* Note: restore in frame at data on entry, restore in frame just past
   data on exit, data potentially not ready until frame close and should
   exist untouched until then (logs details). */

#define RESTORE_DATA( data, sz ) do {                                        \
    ulong _sz  = (sz);                                                       \
    int   _err = fd_restore_data( restore, (data), _sz ); /* logs details */ \
    if( FD_UNLIKELY( _err ) ) {                                              \
      FD_LOG_WARNING(( "fd_restore_data( %s, %lu ) failed (%i-%s)",          \
                       #data, _sz, _err, fd_checkpt_strerror( _err ) ));     \
      goto fail;                                                             \
    }                                                                        \
  } while(0)

/* Note: jumps to fail if c is not true (logs details) */

#define RESTORE_TEST( c ) do {                          \
    if( FD_UNLIKELY( !(c) ) ) {                         \
      FD_LOG_WARNING(( "restore test %s failed", #c )); \
      goto fail;                                        \
    }                                                   \
  } while(0)

/* fd_wksp_restore_v2_hdr restores the header frame from a wksp checkpt.
   Assumes restore is valid and at the frame start and hdr is valid.  On
   success, returns SUCCESS, *hdr will be populated with a valid data
   and restore will be just after the frame end.  On failure, returns
   FAIL, *hdr is clobbered and the caller should not assume anything
   about the restore state. */

static int
fd_wksp_restore_v2_hdr( fd_restore_t *             restore,
                        fd_wksp_checkpt_v2_hdr_t * hdr ) {
  ulong frame_off;

  RESTORE_OPEN( FD_CHECKPT_FRAME_STYLE_RAW );
  RESTORE_DATA( hdr, sizeof(fd_wksp_checkpt_v2_hdr_t) );
  RESTORE_CLOSE();

  ulong name_len = fd_shmem_name_len( hdr->name );
  /* FIXME: CHECK TRAILING 0 OF NAME? */

  RESTORE_TEST( hdr->magic==FD_WKSP_MAGIC                                          );
  RESTORE_TEST( hdr->style==FD_WKSP_CHECKPT_STYLE_V2                               );
  RESTORE_TEST( fd_checkpt_frame_style_is_supported( hdr->frame_style_compressed ) );
  RESTORE_TEST( hdr->reserved==0U                                                  );
  RESTORE_TEST( name_len>0UL                                                       );
  /* ignore seed (arbitrary) */
  RESTORE_TEST( fd_wksp_footprint( hdr->part_max, hdr->data_max )>0UL              );

  return FD_WKSP_SUCCESS;

fail:
  return FD_WKSP_ERR_FAIL;
}

/* fd_wksp_restore_v2_info restores the info frame from a wksp checkpt.
   Assumes restore is valid and at the frame start, hdr has info from
   the corresponding header, info_buf has room for buf_max bytes and
   info_cstr is valid.  On success, returns SUCCESS, *info will be
   populated with a valid data, info_cstr will be populated with
   pointers into info_buf to valid info cstr (indexed in the same order
   as the info fields) and restore will be just after the frame end.  On
   failure, returns FAIL, info, info_buf and info might be clobbered and
   the restore state is unknown. */

static int
fd_wksp_restore_v2_info( fd_restore_t *                   restore,
                         fd_wksp_checkpt_v2_hdr_t const * hdr,
                         fd_wksp_checkpt_v2_info_t *      info,
                         char *                           info_buf,
                         ulong                            info_buf_max,
                         char const *                     info_cstr[ 9 ] ) {
  ulong frame_off;

  RESTORE_OPEN( hdr->frame_style_compressed );
  RESTORE_META( info, sizeof(fd_wksp_checkpt_v2_info_t) );
  ulong info_buf_sz = info->sz_app
                    + info->sz_thread
                    + info->sz_host
                    + info->sz_cpu
                    + info->sz_group
                    + info->sz_user
                    + info->sz_path
                    + info->sz_binfo
                    + info->sz_uinfo;
  RESTORE_TEST( info_buf_sz<=info_buf_max );
  RESTORE_DATA( info_buf, info_buf_sz );
  RESTORE_CLOSE();

  char const * p = info_buf;

# define NEXT( sz, max ) (__extension__({                   \
    char const * _cstr = p;                                 \
    ulong        _sz   = (sz);                              \
    ulong        _max  = (max);                             \
    RESTORE_TEST( (0UL<_sz) & (_sz<=_max) );                \
    RESTORE_TEST( fd_cstr_nlen( _cstr, _max )==(_sz-1UL) ); \
    p += _sz;                                               \
    _cstr;                                                  \
  }))

  info_cstr[0] = NEXT( info->sz_app,    FD_LOG_NAME_MAX              );
  info_cstr[1] = NEXT( info->sz_thread, FD_LOG_NAME_MAX              );
  info_cstr[2] = NEXT( info->sz_host,   FD_LOG_NAME_MAX              );
  info_cstr[3] = NEXT( info->sz_cpu,    FD_LOG_NAME_MAX              );
  info_cstr[4] = NEXT( info->sz_group,  FD_LOG_NAME_MAX              );
  info_cstr[5] = NEXT( info->sz_user,   FD_LOG_NAME_MAX              );
  info_cstr[6] = NEXT( info->sz_path,   PATH_MAX                     );
  info_cstr[7] = NEXT( info->sz_binfo,  FD_WKSP_CHECKPT_V2_BINFO_MAX );
  info_cstr[8] = NEXT( info->sz_uinfo,  FD_WKSP_CHECKPT_V2_UINFO_MAX );

# undef NEXT

  return FD_WKSP_SUCCESS;

fail:
  return FD_WKSP_ERR_FAIL;
}

/* fd_wksp_restore_v2_ftr restores the footer frame from a wksp checkpt.
   Assumes restore is valid and at the frame start, hdr has info from
   the corresponding hdr and ftr is valid.  On success, returns SUCCESS,
   *ftr will be populated with a valid data and restore will be just
   after the frame end.  On failure, returns FAIL, *ftr is clobbered and
   the caller should not assume anything about the restore state.

   IMPORTANT SAFETY TIP!  This only validates the ftr and hdr are
   compatible.  It is up to the caller to validate alloc_cnt,
   cgroup_cnt, volume_cnt, and frame_off as those may not have been
   known when hdr was written and ftr is restored. */

static int
fd_wksp_restore_v2_ftr( fd_restore_t *                   restore,
                        fd_wksp_checkpt_v2_hdr_t const * hdr,
                        fd_wksp_checkpt_v2_ftr_t *       ftr,
                        ulong                            checkpt_sz ) {
  ulong frame_off;

  RESTORE_OPEN( FD_CHECKPT_FRAME_STYLE_RAW );
  RESTORE_DATA( ftr, sizeof(fd_wksp_checkpt_v2_ftr_t) );
  RESTORE_CLOSE();

  RESTORE_TEST( frame_off      ==checkpt_sz );
  RESTORE_TEST( ftr->checkpt_sz==checkpt_sz );

  RESTORE_TEST( ftr->data_max                        ==hdr->data_max               );
  RESTORE_TEST( ftr->part_max                        ==hdr->part_max               );
  RESTORE_TEST( ftr->seed                            ==hdr->seed                   );
  RESTORE_TEST( !memcmp( ftr->name, hdr->name, FD_SHMEM_NAME_MAX )                 );
  RESTORE_TEST( ftr->reserved                        ==hdr->reserved               );
  RESTORE_TEST( ftr->frame_style_compressed          ==hdr->frame_style_compressed );
  RESTORE_TEST( ftr->style                           ==hdr->style                  );
  RESTORE_TEST( ftr->unmagic                         ==~hdr->magic                 );

  return FD_WKSP_SUCCESS;

fail:
  return FD_WKSP_ERR_FAIL;
}

/* fd_wksp_private_restore_v2_common does the common parts of a
   streaming and a parallel wksp restore (restores the header and info
   frames and pretty prints them to the log).  Assumes wksp and restore
   are valid and restore is on the first header byte.  On success,
   returns SUCCESS and the restore will have processed the header and
   info frames and will be positioned just after the info frame.  On
   failure, returns FAIL and restore and hdr will be in an indeterminant
   state. */

static int
fd_wksp_private_restore_v2_common( fd_wksp_checkpt_v2_hdr_t * hdr,
                                   fd_restore_t *             restore ) {

  FD_LOG_INFO(( "Restoring header and info (v2 frames 0:1)" ));

  RESTORE_TEST( !fd_wksp_restore_v2_hdr( restore, hdr ) );

  fd_wksp_checkpt_v2_info_t info[1];
  char                      info_buf[ 65536 ];
  char const *              info_cstr[9];

  RESTORE_TEST( !fd_wksp_restore_v2_info( restore, hdr, info, info_buf, 65536UL, info_cstr ) );

  /* Note: this mirrors printf below */

  char info_wallclock[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
  fd_log_wallclock_cstr( info->wallclock, info_wallclock );

  FD_LOG_INFO(( "\n"
                "\tstyle                  %-20i\n"       /* verbose 0 info */
                "\tname                   %s\n"
                "\tseed                   %-20u\n"
                "\tpart_max               %-20lu\n"
                "\tdata_max               %-20lu\n"
                "\tmagic                  %016lx\n"      /* verbose 1 info */
                "\twallclock              %-20li (%s)\n"
                "\tapp                    %-20lu (%s)\n"
                "\tthread                 %-20lu (%s)\n"
                "\thost                   %-20lu (%s)\n"
                "\tcpu                    %-20lu (%s)\n"
                "\tgroup                  %-20lu (%s)\n"
                "\ttid                    %-20lu\n"
                "\tuser                   %-20lu (%s)\n"
                "\tframe_style_compressed %-20i\n"       /* (v2 specific) */
                "\tmode                   %03lo",        /* (v2 specific) */
                hdr->style, hdr->name, hdr->seed, hdr->part_max, hdr->data_max,
                hdr->magic, info->wallclock, info_wallclock,
                info->app_id,    info_cstr[0],
                info->thread_id, info_cstr[1],
                info->host_id,   info_cstr[2],
                info->cpu_id,    info_cstr[3],
                info->group_id,  info_cstr[4],
                info->tid,
                info->user_id,   info_cstr[5],
                hdr->frame_style_compressed,
                info->mode ));

  /* The below info cstr are potentially long enough to be truncated by
     the logger.  So we break them into separate log messages to log as
     much detail as possible. */

  FD_LOG_INFO(( "path\n\t\t%s",  info_cstr[6] )); /* verbose 2 info (v2 specific) */
  FD_LOG_INFO(( "binfo\n\t\t%s", info_cstr[7] )); /* verbose 2 info */
  FD_LOG_INFO(( "uinfo\n\t\t%s", info_cstr[8] )); /* verbose 2 info */

  return FD_WKSP_SUCCESS;

fail:
  return FD_WKSP_ERR_FAIL;
}

/* fd_wksp_private_restore_v2_cgroup restores a cgroup's allocation into
   wksp.  hdr contains the corresponding restore header info, frame_off
   is where the cgroup frame to restore is located and partitions
   [part_lo,part_hi) are the wksp partition indices to use for this
   frame's allocations.  Assumes all inputs have already been validated.
   Returns SUCCESS (0) on success and FAIL (negative) on failure.  On
   return, in both cases, *_dirty will be 1/0 if wksp was/was not
   modified.  On error, the restore state is indeterminant. */

static int
fd_wksp_private_restore_v2_cgroup( fd_wksp_t *                      wksp,
                                   fd_restore_t *                   restore,
                                   fd_wksp_checkpt_v2_hdr_t const * hdr,
                                   ulong                            frame_off_lo,
                                   ulong                            frame_off_hi,
                                   ulong                            part_lo,
                                   ulong                            part_hi,
                                   int *                            _dirty ) {
  int dirty = 0;

  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );
  ulong                     data_lo  = wksp->gaddr_lo;
  ulong                     data_hi  = wksp->gaddr_hi;

  ulong hdr_data_lo = fd_wksp_private_data_off( hdr->part_max );
  ulong hdr_data_hi = hdr_data_lo + hdr->data_max;

  ulong frame_off;
  RESTORE_SEEK( frame_off_lo );
  RESTORE_OPEN( hdr->frame_style_compressed );

  /* For all cgroup allocation metadata */

  fd_wksp_checkpt_v2_cmd_t cmd[1];

  for( ulong part_idx=part_lo; part_idx<part_hi; part_idx++ ) {

    RESTORE_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );
    RESTORE_TEST( fd_wksp_checkpt_v2_cmd_is_meta( cmd ) );

    ulong tag      = cmd->meta.tag;      /* non-zero */
    ulong gaddr_lo = cmd->meta.gaddr_lo;
    ulong gaddr_hi = cmd->meta.gaddr_hi;

    RESTORE_TEST( (hdr_data_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=hdr_data_hi) );
    /* Note: disjoint [gaddr_lo,gaddr_hi) tested on rebuild */

    if( FD_UNLIKELY( !((data_lo<=gaddr_lo) & (gaddr_hi<=data_hi)) ) ) {
      FD_LOG_WARNING(( "restore failed because checkpt partition [0x%016lx,0x%016lx) tag %lu does not fit into current "
                       "wksp data region [0x%016lx,0x%016lx) (data_max checkpt %lu, wksp %lu)",
                       gaddr_lo, gaddr_hi, tag, data_lo, data_hi, hdr->data_max, wksp->data_max ));
      goto fail;
    }

    dirty = 1;
    pinfo[ part_idx ].gaddr_lo = gaddr_lo;
    pinfo[ part_idx ].gaddr_hi = gaddr_hi;
    pinfo[ part_idx ].tag      = tag;
  }

  /* Restore the data command */

  RESTORE_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );
  RESTORE_TEST( fd_wksp_checkpt_v2_cmd_is_data( cmd ) );

  /* For all cgroup allocation data */

  for( ulong part_idx=part_lo; part_idx<part_hi; part_idx++ ) {
    ulong gaddr_lo = pinfo[ part_idx ].gaddr_lo;
    ulong gaddr_hi = pinfo[ part_idx ].gaddr_hi;

    /* Restore the allocation into the wksp data region */

    dirty = 1;
    RESTORE_DATA( fd_wksp_laddr_fast( wksp, gaddr_lo ), gaddr_hi - gaddr_lo );
  }

  /* Close the frame */

  RESTORE_CLOSE();

  RESTORE_TEST( (frame_off_lo<frame_off) & (frame_off<=frame_off_hi) ); /* == hi if compactly stored */

  *_dirty = dirty;
  return FD_WKSP_SUCCESS;

fail:
  *_dirty = dirty;
  return FD_WKSP_ERR_FAIL;
}

/* fd_wksp_private_restore_v2_node dispatches cgroup restore work to
   tpool threads [t0,t1).  If any errors were encountered while
   restoring cgroups, returns the first error encountered on the lowest
   indexed thread in the int location pointed to by _err.  If any
   modifications were made to wksp (whether or not there were errors),
   the int location pointed to by _dirty will be set to 1.  Assumes
   caller is thread t0 and threads (t0,t1) are available.  Note that we
   could do this with FD_MAP_REDUCE but FD_MAP_REDUCE assumes that
   fd_scratch space is available and we can't guarantee that here.
   Likewise, we could use tpool_exec_all with a TASKQ model but
   reduction of results is less efficient. */

static void
fd_wksp_private_restore_v2_node( void * tpool,
                                 ulong  tpool_t0,
                                 ulong  tpool_t1,          /* Assumes t1>t0 */
                                 void * _wksp,
                                 void * _restore,
                                 ulong  _hdr,
                                 ulong  _cgroup_frame_off,
                                 ulong  _cgroup_pinfo_lo,
                                 ulong  _cgroup_nxt,
                                 ulong  cgroup_cnt,
                                 ulong  _err,
                                 ulong  _dirty ) {

  /* This node is responsible for threads [t0,t1).  If this range has
     more than one thread, split the range into left and right halves,
     have the first right half thread handle the right half, use this
     thread to handle the left half and then reduce the results from
     the two halves. */

  ulong tpool_cnt = tpool_t1 - tpool_t0;
  if( tpool_cnt>1UL ) {
    ulong tpool_ts = tpool_t0 + fd_tpool_private_split( tpool_cnt );

    int err0; int dirty0;
    int err1; int dirty1;

    fd_tpool_exec( tpool, tpool_ts, fd_wksp_private_restore_v2_node,
                   tpool, tpool_ts, tpool_t1, _wksp, _restore, _hdr, _cgroup_frame_off, _cgroup_pinfo_lo, _cgroup_nxt, cgroup_cnt,
                   (ulong)&err1, (ulong)&dirty1 );
    fd_wksp_private_restore_v2_node(
                   tpool, tpool_t0, tpool_ts, _wksp, _restore, _hdr, _cgroup_frame_off, _cgroup_pinfo_lo, _cgroup_nxt, cgroup_cnt,
                   (ulong)&err0, (ulong)&dirty0 );
    fd_tpool_wait( tpool, tpool_ts );

    *(int *)_err   = fd_int_if( !!err0, err0, err1 ); /* Return first error encountered */
    *(int *)_dirty = dirty0 | dirty1;                 /* Accumulate the dirty flag */
    return;
  }

  /* This node is responsible for a single thread.  Unpack the input
     arguments. */

  fd_wksp_t *                      wksp             = (fd_wksp_t *)               _wksp;
  fd_restore_t *                   restore          = (fd_restore_t *)            _restore; /* FIXME: CLONE RESTORE */
  fd_wksp_checkpt_v2_hdr_t const * hdr              = (fd_wksp_checkpt_v2_hdr_t *)_hdr;
  ulong const *                    cgroup_frame_off = (ulong *)                   _cgroup_frame_off;
  ulong const *                    cgroup_pinfo_lo  = (ulong *)                   _cgroup_pinfo_lo;

  int err   = FD_WKSP_SUCCESS;
  int dirty = 0;

  /* Since we can't have multiple threads operate concurrently on the
     same restore object, make a new restore object safe for use by this
     thread (technically could use restore directly on original thread
     t0). */

  fd_restore_t _restore_local[1];
  fd_restore_t * restore_local =
    fd_restore_init_mmio( _restore_local, fd_restore_mmio( restore ), fd_restore_mmio_sz( restore ) ); /* logs details */
  if( FD_UNLIKELY( !restore_local ) ) {
    err = FD_WKSP_ERR_FAIL;
    goto done;
  }

  for(;;) {

    /* Get the next cgroup to restore.  Use a dynamic task queue model
       here because we assume that restore a single cgroups requires a
       large amount of work and the amount of work is highly variable.
       Note that using an atomic increment for the cgroup_nxt counter
       assumes:

         cgroup_cnt << ULONG_MAX - TILE_MAX.

       We could use a slower atomic CAS based version instead if we want
       to insure that cgroup_nxt is never incremented beyond cgroup_cnt.
       We could also use a block partitioning or CUDA style striping if
       wanting to do a deterministic distribution but these might not
       load balance as well in various extreme circumstances. */

#   if FD_HAS_ATOMIC
    FD_COMPILER_MFENCE();
    ulong cgroup_idx = FD_ATOMIC_FETCH_AND_ADD( (ulong *)_cgroup_nxt, 1UL );
    FD_COMPILER_MFENCE();
#   else /* Note: this assumes platforms without HAS_ATOMIC will not be running this multithreaded */
    ulong cgroup_idx = (*(ulong *)_cgroup_nxt) + 1UL;
#   endif

    if( FD_UNLIKELY( cgroup_idx>=cgroup_cnt ) ) break; /* No more cgroups to process */

    /* Restore this cgroup */

    int dirty_cgroup;
    err = fd_wksp_private_restore_v2_cgroup( wksp, restore_local, hdr,
                                             cgroup_frame_off[ cgroup_idx ], cgroup_frame_off[ cgroup_idx+1UL ],
                                             cgroup_pinfo_lo [ cgroup_idx ], cgroup_pinfo_lo [ cgroup_idx+1UL ],
                                             &dirty_cgroup ); /* logs details */
    dirty |= dirty_cgroup;
    if( FD_UNLIKELY( err ) ) break; /* abort if we encountered an error */

  }

  fd_restore_fini( restore_local );

done:
  *(int *)_err   = err;
  *(int *)_dirty = dirty;
}

/* fd_wksp_private_restore_v2_mmio replaces all the allocations in a
   wksp with the allocations in the restore.  Assumes all inputs have
   are valid, restore is positioned on the first byte of the header, has
   the given size and is seekable.  Returns SUCCESS on success and the
   restore will be positioned just after the footer.  Returns FAIL if an
   error occurred before wksp was not modified and CORRUPT if an error
   occurred after.  On failure, the restore state is indeterminant.
   Uses tpool threads [t0,t1) to do the restore.  Assumes the caller is
   thread t0 and threads (t0,t1) are available for dispatch. */

static int
fd_wksp_private_restore_v2_mmio( fd_tpool_t *   tpool,
                                 ulong          t0,
                                 ulong          t1,
                                 fd_wksp_t *    wksp,
                                 fd_restore_t * restore,
                                 uint           new_seed ) {

  ulong frame_off;

  int locked = 0; /* is the wksp currently locked? */
  int dirty  = 0; /* has the wksp been modified? */

  /* Restore and validate the header, info, and footer.  In principle
     this could be parallelized but probably not worth it. */

  ulong restore_sz = fd_restore_sz( restore );

  ulong frame_off_hdr  = 0UL;
  ulong frame_off_info = frame_off_hdr + sizeof(fd_wksp_checkpt_v2_hdr_t);
  ulong frame_off_ftr  = restore_sz    - sizeof(fd_wksp_checkpt_v2_ftr_t);

  RESTORE_TEST( /*(0UL<=frame_off_hdr) &*/ (frame_off_hdr<frame_off_info) & (frame_off_info<frame_off_ftr) & (frame_off_ftr<restore_sz) );

  fd_wksp_checkpt_v2_hdr_t hdr[1];

//RESTORE_SEEK( frame_off_hdr );
  RESTORE_TEST( !fd_wksp_private_restore_v2_common( hdr, restore ) );

  FD_LOG_INFO(( "Restoring footer" ));

  fd_wksp_checkpt_v2_ftr_t ftr[1];

  RESTORE_SEEK( frame_off_ftr );
  RESTORE_TEST( !fd_wksp_restore_v2_ftr( restore, hdr, ftr, restore_sz ) );

  ulong frame_off_volumes = ftr->frame_off;

  RESTORE_TEST( (frame_off_info<frame_off_volumes) & (frame_off_volumes<frame_off_ftr) );

  if( FD_UNLIKELY( ftr->alloc_cnt>wksp->part_max ) ) {
    FD_LOG_WARNING(( "restore failed because there are too few wksp partitions to restore allocations into "
                     "(ftr alloc_cnt %lu, hdr part_max %lu, wksp part_max %lu)",
                     ftr->alloc_cnt, hdr->part_max, wksp->part_max ));
    goto fail;
  }

  FD_LOG_INFO(( "Restoring volumes" ));

  fd_wksp_checkpt_v2_cmd_t cmd[1];

  RESTORE_SEEK( frame_off_volumes );
  RESTORE_OPEN( hdr->frame_style_compressed );
  RESTORE_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );
  RESTORE_CLOSE();

  RESTORE_TEST( (cmd->volumes.tag==0UL) & (cmd->volumes.cgroup_cnt==ULONG_MAX) ); /* frame_off_appendix tested below */
  RESTORE_TEST( (frame_off_volumes<frame_off) & (frame_off<=frame_off_ftr) );     /* ==frame_off_ftr if compactly stored */

  FD_LOG_INFO(( "Locking wksp" ));

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) goto fail; /* logs details */
  locked = 1;

  /* For all volumes */

  ulong alloc_rem  = ftr->alloc_cnt;  /* Number of allocations remaining to process */
  ulong cgroup_rem = ftr->cgroup_cnt; /* Number of cgroups     remaining to process */
  ulong volume_rem = ftr->volume_cnt; /* Number of volumes     remaining to process */

  ulong frame_off_volume_lo = frame_off_info;
  ulong frame_off_volume_hi = frame_off_volumes;
  ulong frame_off_appendix  = cmd->volumes.frame_off;

  while( frame_off_appendix ) {

    /* Verify we still have volumes remaining and the appendix location
       is between the info frame and the next volume (or the footer if
       the last volume) */

    RESTORE_TEST( (volume_rem>0UL) & (frame_off_volume_lo<frame_off_appendix) & (frame_off_appendix<frame_off_volume_hi) );

    /* Now that we know where this volume's appendix is supposed to be,
       seek to it and then restore and validate it. */

    FD_LOG_INFO(( "Restoring volume appendix" ));

    RESTORE_SEEK( frame_off_appendix );

    ulong cgroup_frame_off[ FD_WKSP_RESTORE_V2_CGROUP_MAX+1UL ];
    ulong cgroup_pinfo_lo [ FD_WKSP_RESTORE_V2_CGROUP_MAX+1UL ];
    ulong cgroup_cnt;

    ulong frame_off_prev;

    {
      RESTORE_OPEN( hdr->frame_style_compressed );

      fd_wksp_checkpt_v2_cmd_t cmd[1];

      RESTORE_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );
      RESTORE_TEST( fd_wksp_checkpt_v2_cmd_is_appendix( cmd ) );

      cgroup_cnt     = cmd->appendix.cgroup_cnt;
      frame_off_prev = cmd->appendix.frame_off;

      if( FD_UNLIKELY( cgroup_cnt>FD_WKSP_RESTORE_V2_CGROUP_MAX ) ) {
        FD_LOG_WARNING(( "increase FD_WKSP_RESTORE_V2_CGROUP_MAX for this target" ));
        goto fail;
      }

      RESTORE_DATA( cgroup_frame_off, cgroup_cnt*sizeof(ulong) );
      RESTORE_DATA( cgroup_pinfo_lo,  cgroup_cnt*sizeof(ulong) ); /* cgroup_alloc_cnt now, pinfo cgroup partitioning later */
      RESTORE_CLOSE();

      /* Verify this cgroups frames are between the previous appendix frame
         (or the info frame if the first volume) and this appendix frame
         and ordered.  Also, verify the cgroup allocation counts,
         convert the counts into a partitioning of wksp's pinfo array
         and make sure we have enough partitions in the wksp to attempt
         the restore.  In principle, this loop could be parallelized but
         probably not worth it. */

      cgroup_frame_off[ cgroup_cnt ] = frame_off_appendix;
      cgroup_pinfo_lo [ cgroup_cnt ] = alloc_rem;

      for( ulong cgroup_rem=cgroup_cnt; cgroup_rem; cgroup_rem-- ) {

        ulong cgroup_idx = cgroup_rem - 1UL;
        RESTORE_TEST( cgroup_frame_off[ cgroup_idx ] < cgroup_frame_off[ cgroup_idx+1UL ] );

        ulong cgroup_alloc_cnt = cgroup_pinfo_lo[ cgroup_idx ];
        RESTORE_TEST( cgroup_alloc_cnt<=alloc_rem );
        alloc_rem -= cgroup_alloc_cnt;
        cgroup_pinfo_lo[ cgroup_idx ] = alloc_rem;

      }

      RESTORE_TEST( fd_ulong_max( frame_off_prev, frame_off_info ) < cgroup_frame_off[0] );
    }

    /* At this point, we know how to do an embarassingly parallel
       restore directly into the wksp.  Dispatch work to tpool threads
       [t0,t1).  This assumes we are tpool thread t0 and threads (t0,t1)
       are available for dispatch.  On return from the dispatch, err
       will contain the error code from the lowest indexed cgroup_idx
       that encountered an error (if any error was encountered, some
       cgroups might not have been processed) and dirty_node will
       contain non-zero if the wksp was modified. */

    FD_LOG_INFO(( "Restoring volume cgroups" ));

    ulong cgroup_nxt[1];

    FD_COMPILER_MFENCE();
    FD_VOLATILE( cgroup_nxt[0] ) = 0UL;
    FD_COMPILER_MFENCE();

    int err;
    int dirty_node;
    fd_wksp_private_restore_v2_node( (void *)tpool, t0, t1,
                                     (void *)wksp, (void *)restore, (ulong)hdr, (ulong)cgroup_frame_off, (ulong)cgroup_pinfo_lo,
                                     (ulong)cgroup_nxt, cgroup_cnt, (ulong)&err, (ulong)&dirty_node );
    dirty |= dirty_node;
    if( FD_UNLIKELY( err ) ) goto fail;

    /* Advance to the next volume */

    cgroup_rem -= cgroup_cnt;
    volume_rem--;
    /* frame_off_volume_lo unchanged */
    frame_off_volume_hi = cgroup_frame_off[ 0 ];
    frame_off_appendix  = frame_off_prev;
  }

  /* Make sure we got all volumes and all cgroups and position the
     restore at the location it would have been at in a streaming
     restore. */

  RESTORE_TEST( alloc_rem ==0UL );
  RESTORE_TEST( cgroup_rem==0UL );
  RESTORE_TEST( volume_rem==0UL );

  RESTORE_SEEK( restore_sz );

  /* Free any remaining old allocations and rebuild the wksp with our
     freshly restored allocations.  In principle the free loop can be
     parallelized but it is probably not worth it. */

  FD_LOG_INFO(( "Rebuilding wksp" ));

  dirty = 1;

  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );
  ulong                     part_max = wksp->part_max;

  for( ulong part_idx=ftr->alloc_cnt; part_idx<part_max; part_idx++ ) pinfo[ part_idx ].tag = 0UL;

  if( FD_UNLIKELY( fd_wksp_rebuild( wksp, new_seed ) ) ) goto fail; /* logs details */

  FD_LOG_INFO(( "Unlocking wksp" ));

  fd_wksp_private_unlock( wksp );

  return FD_WKSP_SUCCESS;

fail: /* Release resources that might be reserved */

  if( FD_LIKELY( locked ) ) fd_wksp_private_unlock( wksp );

  return fd_int_if( dirty, FD_WKSP_ERR_CORRUPT, FD_WKSP_ERR_FAIL );
}

/* fd_wksp_private_restore_v2_stream is identical to
   fd_wksp_private_restore_v2_mmio (above) but usable when restore is
   not using memory mapped i/o under the hood.  This includes when the
   restore is from a non-seekable file descriptor (e.g. when the restore
   is from a pipe or socket but this will work fine if used on mmio
   restores too).  Restore must be compactly stored.  Exact same
   behaviors. */

static int
fd_wksp_private_restore_v2_stream( fd_wksp_t *    wksp,
                                   fd_restore_t * restore,
                                   uint           new_seed ) {
  ulong frame_off;

  int locked = 0; /* is the wksp currently locked */
  int dirty  = 0; /* has the wksp been modified? */

  fd_wksp_checkpt_v2_hdr_t hdr[1];

  RESTORE_TEST( !fd_wksp_private_restore_v2_common( hdr, restore ) );

  FD_LOG_INFO(( "Locking wksp" ));

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) goto fail; /* logs details */
  locked = 1;

  fd_wksp_private_pinfo_t * pinfo    = fd_wksp_private_pinfo( wksp );
  ulong                     part_max = wksp->part_max;
  ulong                     data_max = wksp->data_max;
  ulong                     data_lo  = wksp->gaddr_lo;
  ulong                     data_hi  = wksp->gaddr_hi;

  ulong hdr_data_max = hdr->data_max;
  ulong hdr_data_lo  = fd_wksp_private_data_off( hdr->part_max );
  ulong hdr_data_hi  = hdr_data_lo + hdr_data_max;

  /* For all volumes in the checkpt */

  ulong ftr_alloc_cnt  = 0UL;
  ulong ftr_cgroup_cnt = 0UL;
  ulong ftr_volume_cnt = 0UL;
  ulong frame_off_prev = 0UL;

  for(;;) {

    FD_LOG_INFO(( "Restoring volume %lu", ftr_volume_cnt ));

    ulong vol_cgroup_cnt = 0UL;

    ulong vol_cgroup_frame_off[ FD_WKSP_RESTORE_V2_CGROUP_MAX ];
    ulong vol_cgroup_alloc_cnt[ FD_WKSP_RESTORE_V2_CGROUP_MAX ];

    ulong vol_appendix_frame_off[ FD_WKSP_RESTORE_V2_CGROUP_MAX ];
    ulong vol_appendix_alloc_cnt[ FD_WKSP_RESTORE_V2_CGROUP_MAX ];

    /* For all cgroups in the volume */

    for(;;) {

      ulong part_lo = ftr_alloc_cnt;

      /* Open the frame and read the leading command to determine if the
         frame is a cgroup, appendix (which ends the volume) or an end
         of volumes frame (which ends the checkpt).  If it is an
         appendix, validate and close the frame and proceed to the next
         volume.  If it is the end of volumes, validate and close the
         frame and proceed to footer processing.  Otherwise, proceed to
         processing a cgroup frame. */

      RESTORE_OPEN( hdr->frame_style_compressed );

      fd_wksp_checkpt_v2_cmd_t cmd[1];

      RESTORE_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );

      if( FD_UNLIKELY( fd_wksp_checkpt_v2_cmd_is_appendix( cmd ) ) ) {
        RESTORE_TEST( cmd->appendix.frame_off==frame_off_prev );
        frame_off_prev = frame_off;

        RESTORE_DATA( vol_appendix_frame_off, vol_cgroup_cnt*sizeof(ulong) );
        RESTORE_DATA( vol_appendix_alloc_cnt, vol_cgroup_cnt*sizeof(ulong) );
        RESTORE_CLOSE();

        RESTORE_TEST( !memcmp( vol_appendix_frame_off, vol_cgroup_frame_off, vol_cgroup_cnt*sizeof(ulong) ) );
        RESTORE_TEST( !memcmp( vol_appendix_alloc_cnt, vol_cgroup_alloc_cnt, vol_cgroup_cnt*sizeof(ulong) ) );

        break;
      }

      if( FD_UNLIKELY( fd_wksp_checkpt_v2_cmd_is_volumes( cmd ) ) ) {
        RESTORE_TEST( cmd->volumes.frame_off==frame_off_prev );
        frame_off_prev = frame_off;

        RESTORE_CLOSE();

        goto restore_footer;
      }

      /* At this point, we have read the leading command of a cgroup frame.
         Restore the cgroup allocation metadata. */

      if( FD_UNLIKELY( vol_cgroup_cnt>=FD_WKSP_RESTORE_V2_CGROUP_MAX ) ) {
        FD_LOG_WARNING(( "increase FD_WKSP_RESTORE_V2_CGROUP_MAX" ));
        goto fail;
      }

      vol_cgroup_frame_off[ vol_cgroup_cnt ] = frame_off;

      for(;;) {
        if( FD_UNLIKELY( fd_wksp_checkpt_v2_cmd_is_data( cmd ) ) ) break;
        RESTORE_TEST( fd_wksp_checkpt_v2_cmd_is_meta( cmd ) );

        ulong tag      = cmd->meta.tag;      /* non-zero */
        ulong gaddr_lo = cmd->meta.gaddr_lo;
        ulong gaddr_hi = cmd->meta.gaddr_hi;

        RESTORE_TEST( (hdr_data_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=hdr_data_hi) );
        /* Note: disjoint [gaddr_lo,gaddr_hi) tested on rebuild */

        if( FD_UNLIKELY( !((data_lo<=gaddr_lo) & (gaddr_hi<=data_hi)) ) ) {
          FD_LOG_WARNING(( "restore failed because checkpt allocation [0x%016lx,0x%016lx) tag %lu does not fit into the wksp "
                           "data region [0x%016lx,0x%016lx) (hdr_data_max %lu, wksp_data_max %lu)",
                           gaddr_lo, gaddr_hi, tag, data_lo, data_hi, hdr_data_max, data_max ));
          goto fail;
        }

        if( FD_UNLIKELY( ftr_alloc_cnt>=part_max ) ) {
          FD_LOG_WARNING(( "restore failed because there are too few wksp partitions to restore allocations into "
                           "(alloc_cnt %lu, hdr_part_max %lu, wksp_part_max %lu)",
                           ftr_alloc_cnt, hdr->part_max, wksp->part_max ));
          goto fail;
        }

        dirty = 1;
        pinfo[ ftr_alloc_cnt ].gaddr_lo = gaddr_lo;
        pinfo[ ftr_alloc_cnt ].gaddr_hi = gaddr_hi;
        pinfo[ ftr_alloc_cnt ].tag      = tag;
        ftr_alloc_cnt++;

        RESTORE_META( cmd, sizeof(fd_wksp_checkpt_v2_cmd_t) );
      }

      /* At this point, we have restored all cgroup allocation metadata
         into the pinfo array at [part_lo,ftr_alloc_cnt).  Restore the
         corresponding cgroup allocation data. */

      for( ulong part_idx=part_lo; part_idx<ftr_alloc_cnt; part_idx++ ) {
        ulong gaddr_lo = pinfo[ part_idx ].gaddr_lo;
        ulong gaddr_hi = pinfo[ part_idx ].gaddr_hi;

        dirty = 1;
        RESTORE_DATA( fd_wksp_laddr_fast( wksp, gaddr_lo ), gaddr_hi - gaddr_lo );
      }

      /* Close the cgroup frame */

      RESTORE_CLOSE();

      /* Update verification info */

      vol_cgroup_alloc_cnt[ vol_cgroup_cnt ] = ftr_alloc_cnt - part_lo;
      vol_cgroup_cnt++;

    }

    /* Update verification info */

    ftr_cgroup_cnt += vol_cgroup_cnt;
    ftr_volume_cnt++;
  }

restore_footer:

  /* At this point, the checkpt is positioned at the start of the
     footer.  Restore and validate it.  Note that checkpt data has been
     fully decompressed into the wksp pinfo and data region but the wksp
     indexing structures have not been rebuilt.  Further note that
     restoring the footer is pure validation. */

  FD_LOG_INFO(( "Restoring footer" ));

  fd_wksp_checkpt_v2_ftr_t ftr[1];

  RESTORE_TEST( !fd_wksp_restore_v2_ftr( restore, hdr, ftr, frame_off + sizeof(fd_wksp_checkpt_v2_ftr_t) ) );

  RESTORE_TEST( ftr->alloc_cnt ==ftr_alloc_cnt  );
  RESTORE_TEST( ftr->cgroup_cnt==ftr_cgroup_cnt );
  RESTORE_TEST( ftr->volume_cnt==ftr_volume_cnt );
  RESTORE_TEST( ftr->frame_off ==frame_off_prev );

  FD_LOG_INFO(( "Rebuilding wksp" ));

  /* Free any remaining old allocations and rebuild the wksp with
     the freshly restored allocations */

  dirty = 1;
  for( ulong part_idx=ftr_alloc_cnt; part_idx<part_max; part_idx++ ) pinfo[ part_idx ].tag = 0UL;

  if( FD_UNLIKELY( fd_wksp_rebuild( wksp, new_seed ) ) ) goto fail; /* logs details */

  FD_LOG_INFO(( "Unlocking wksp" ));

  fd_wksp_private_unlock( wksp );

  return FD_WKSP_SUCCESS;

fail: /* Release resources that might be reserved */

  if( FD_LIKELY( locked ) ) fd_wksp_private_unlock( wksp );

  return fd_int_if( dirty, FD_WKSP_ERR_CORRUPT, FD_WKSP_ERR_FAIL );
}

int
fd_wksp_private_restore_v2( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            uint         new_seed ) {

  FD_LOG_INFO(( "Restoring checkpt \"%s\" into wksp \"%s\" (seed %u)", path, wksp->name, new_seed ));

  int            fd      = -1;
  void const *   mmio    = NULL;
  ulong          mmio_sz = 0UL;
  fd_restore_t * restore = NULL;

  fd_restore_t   _restore[ 1 ];
  uchar          rbuf[ FD_RESTORE_RBUF_MIN ];

  FD_LOG_INFO(( "Opening checkpt" ));

  fd = open( path, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  int err = fd_io_mmio_init( fd, FD_IO_MMIO_MODE_READ_ONLY, &mmio, &mmio_sz );
  if( FD_LIKELY( !err ) ) {

    FD_LOG_INFO(( "Restoring checkpt with mmio" ));

    /* FIXME: consider trimming off prefix / suffix here (i.e. scan for
       MAGIC / ~MAGIC) */

    restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); /* logs details */
    if( FD_UNLIKELY( !restore ) ) goto fail;

    err = fd_wksp_private_restore_v2_mmio( tpool, t0, t1, wksp, restore, new_seed ); /* logs details */
    if( FD_UNLIKELY( err ) ) goto fail;

  } else {

    FD_LOG_INFO(( "\"%s\" does not appear to support mmio (%i-%s); restoring checkpt with streaming",
                  path, err, fd_io_strerror( err ) ));

    /* FIXME: consider trimming off prefix (i.e. scan for MAGIC) here */

    restore = fd_restore_init_stream( _restore, fd, rbuf, FD_RESTORE_RBUF_MIN ); /* logs details */
    if( FD_UNLIKELY( !restore ) ) goto fail;

    err = fd_wksp_private_restore_v2_stream( wksp, restore, new_seed ); /* logs details */
    if( FD_UNLIKELY( err ) ) goto fail;

  }

  FD_LOG_INFO(( "Closing checkpt" ));

  if( FD_UNLIKELY( !fd_restore_fini( restore ) ) ) /* logs details */
    FD_LOG_WARNING(( "fd_restore_fini failed; attempting to continue" ));

  if( FD_LIKELY( mmio_sz ) ) fd_io_mmio_fini( mmio, mmio_sz );

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  return err;

fail:

  if( FD_LIKELY( restore ) ) {
    if( FD_UNLIKELY( fd_restore_in_frame( restore ) ) && FD_UNLIKELY( fd_restore_close( restore ) ) )
      FD_LOG_WARNING(( "fd_restore_close failed; attempting to continue" ));

    if( FD_UNLIKELY( !fd_restore_fini( restore ) ) ) /* logs details */
      FD_LOG_WARNING(( "fd_restore_fini failed; attempting to continue" ));
  }

  if( FD_LIKELY( mmio_sz ) ) fd_io_mmio_fini( mmio, mmio_sz );

  if( FD_LIKELY( fd!=-1 ) && FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  return FD_WKSP_ERR_FAIL;
}

int
fd_wksp_private_printf_v2( int          out,
                           char const * path,
                           int          verbose ) {

  int ret = 0;
# define TRAP(x) do { int _err = (x); if( FD_UNLIKELY( _err<0 ) ) { ret = _err; goto fail; } ret += _err; } while(0)

  int            fd      = -1;
  fd_restore_t * restore = NULL;

  fd_restore_t _restore[ 1 ];
  uchar        rbuf[ FD_RESTORE_RBUF_MIN ];

  /* Print the header and metadata */

  if( verbose>=1 ) {

     /* Open the restore */

    fd = open( path, O_RDONLY, (mode_t)0 );
    if( FD_UNLIKELY( fd==-1 ) ) {
      FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      goto fail;
    }

    restore = fd_restore_init_stream( _restore, fd, rbuf, FD_RESTORE_RBUF_MIN ); /* logs details */
    if( FD_UNLIKELY( !restore ) ) goto fail;

    /* Restore the header */

    fd_wksp_checkpt_v2_hdr_t hdr[1];

    RESTORE_TEST( !fd_wksp_restore_v2_hdr( restore, hdr ) );

    /* Restore the info */

    fd_wksp_checkpt_v2_info_t info[1];
    char                      info_buf[ 65536 ];
    char const *              info_cstr[ 9 ];

    RESTORE_TEST( !fd_wksp_restore_v2_info( restore, hdr, info, info_buf, 65536UL, info_cstr ) );

    char info_wallclock[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    fd_log_wallclock_cstr( info->wallclock, info_wallclock );

    /* Pretty print the header and info */

    TRAP( dprintf( out,
                 //"\tstyle                  %-20i\n"        /* verbose 0 info (already printed) */
                 //"\tname                   %s\n"
                 //"\tseed                   %-20u\n"
                 //"\tpart_max               %-20lu\n"
                 //"\tdata_max               %-20lu\n"
                   "\tmagic                  %016lx\n"      /* verbose 1 info */
                   "\twallclock              %-20li (%s)\n"
                   "\tapp                    %-20lu (%s)\n"
                   "\tthread                 %-20lu (%s)\n"
                   "\thost                   %-20lu (%s)\n"
                   "\tcpu                    %-20lu (%s)\n"
                   "\tgroup                  %-20lu (%s)\n"
                   "\ttid                    %-20lu\n"
                   "\tuser                   %-20lu (%s)\n"
                   "\tframe_style_compressed %-20i\n",      /* (v2 specific) */
                   hdr->magic,
                   info->wallclock, info_wallclock,
                   info->app_id,    info_cstr[0],
                   info->thread_id, info_cstr[1],
                   info->host_id,   info_cstr[2],
                   info->cpu_id,    info_cstr[3],
                   info->group_id,  info_cstr[4],
                   info->tid,
                   info->user_id,   info_cstr[5],
                   hdr->frame_style_compressed ) );

    if( verbose>=2 )
      TRAP( dprintf( out, "\tmode                   %03lo\n" /* (v2 specific) */
                          "\tpath\n\t\t%s\n"                 /* (v2 specific) */
                          "\tbinfo\n\t\t%s\n"
                          "\tuinfo\n\t\t%s\n",
                          info->mode, info_cstr[6], info_cstr[7], info_cstr[8] ) );

    /* FIXME: consider implement handling of verbose>=3.  Since data in a
       compressed frame can't be easily skipped over (due to sequential
       dependencies between compressed data bufs inherently induced by
       compression algos), we would:

       Use stat to get the size of the checkpt, seek to the end of the
       file and restore the footer frame to get the appendix frame
       location, seek to the appendix frame, and restore it to get the
       cgroup frame offsets and partition counts.  Then, for each cgroup,
       seek to the cgruop frame, init a streaming restore, open the frame,
       restore the partition count and partition metadata (which is
       conveniently located at the start of a cgroup frame), close it and
       fini the restore.  Omitting for now as this isn't particularly
       important functionality. */

    /* Finish restoring */

    if( FD_UNLIKELY( !fd_restore_fini( restore ) ) ) /* logs details */
      FD_LOG_WARNING(( "fd_restore_fini failed; attempting to continue" ));

    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));
  }

# undef TRAP

  return ret;

fail: /* Release resources that might be reserved */

  if( FD_LIKELY( restore ) ) {
    if( FD_UNLIKELY( fd_restore_in_frame( restore ) ) && FD_UNLIKELY( fd_restore_close( restore ) ) )
      FD_LOG_WARNING(( "fd_restore_close failed; attempting to continue" ));

    if( FD_UNLIKELY( !fd_restore_fini( restore ) ) ) /* logs details */
      FD_LOG_WARNING(( "fd_restore_fini failed; attempting to continue" ));
  }

  if( FD_LIKELY( fd!=-1 ) && FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

  return ret;
}

#undef RESTORE_TEST
#undef RESTORE_DATA
#undef RESTORE_META
#undef RESTORE_CLOSE
#undef RESTORE_OPEN
#undef RESTORE_SEEK
