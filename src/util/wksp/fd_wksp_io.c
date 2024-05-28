#include "fd_wksp_private.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int
fd_wksp_checkpt( fd_wksp_t *  wksp,
                 char const * path,
                 ulong        mode,
                 int          style,
                 char const * uinfo ) { /* TODO: CONSIDER ALLOWING SUBSET OF TAGS */

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return FD_WKSP_ERR_INVAL;
  }

  if( FD_UNLIKELY( !path ) ) {
    FD_LOG_WARNING(( "NULL path" ));
    return FD_WKSP_ERR_INVAL;
  }

  if( FD_UNLIKELY( mode!=(ulong)(mode_t)mode ) ) {
    FD_LOG_WARNING(( "bad mode" ));
    return FD_WKSP_ERR_INVAL;
  }

  style = fd_int_if( !!style, style, FD_WKSP_CHECKPT_STYLE_DEFAULT );

  if( FD_UNLIKELY( !uinfo ) ) uinfo = "";

  switch( style ) {

  case FD_WKSP_CHECKPT_STYLE_RAW: {

  //FD_LOG_INFO(( "Checkpt wksp \"%s\" to \"%s\" (mode 0%03lo), style %i, uinfo \"%s\"", wksp->name, path, mode, style, uinfo ));

    mode_t old_mask = umask( (mode_t)0 );
    int fd = open( path, O_CREAT|O_EXCL|O_WRONLY, (mode_t)mode );
    umask( old_mask );
    if( FD_UNLIKELY( fd==-1 ) ) {
      FD_LOG_WARNING(( "open(\"%s\",O_CREAT|O_EXCL|O_WRONLY,0%03lo) failed (%i-%s)", path, mode, errno, fd_io_strerror( errno ) ));
      return FD_WKSP_ERR_FAIL;
    }

#   define WBUF_ALIGN     ( 4096UL)
#   define WBUF_FOOTPRINT (65536UL)

    uchar                    wbuf[ WBUF_FOOTPRINT ] __attribute__((aligned(WBUF_ALIGN)));
    fd_io_buffered_ostream_t checkpt[ 1 ];
    fd_io_buffered_ostream_init( checkpt, fd, wbuf, WBUF_FOOTPRINT );

    int     err;
    uchar * prep;

    err = fd_wksp_private_lock( wksp ); if( FD_UNLIKELY( err ) ) goto fini; /* logs details */

    /* Do basic wksp checks (TODO: CONSIDER RUNNING VERIFY ON WKSP
       HERE AND ELIMINATING THIS CHECK AND THE CHECKS BELOW) */

    ulong data_lo = wksp->gaddr_lo;
    ulong data_hi = wksp->gaddr_hi;
    if( FD_UNLIKELY( !((0UL<data_lo) & (data_lo<=data_hi)) ) ) goto corrupt_wksp;

  //FD_LOG_INFO(( "Checkpt header and metadata" ));

    prep = fd_wksp_private_checkpt_prepare( checkpt, WBUF_FOOTPRINT, &err ); if( FD_UNLIKELY( !prep ) ) goto io_err;
    prep = fd_wksp_private_checkpt_ulong( prep, wksp->magic                                                          );
    prep = fd_wksp_private_checkpt_ulong( prep, (ulong)(uint)style                                                   );
    prep = fd_wksp_private_checkpt_ulong( prep, (ulong)wksp->seed                                                    );
    prep = fd_wksp_private_checkpt_ulong( prep, wksp->part_max                                                       );
    prep = fd_wksp_private_checkpt_ulong( prep, wksp->data_max                                                       );
    prep = fd_wksp_private_checkpt_ulong( prep, (ulong)fd_log_wallclock()                                            );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_app_id()                                                      );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_thread_id()                                                   );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_host_id()                                                     );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_cpu_id()                                                      );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_group_id()                                                    );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_tid()                                                         );
    prep = fd_wksp_private_checkpt_ulong( prep, fd_log_user_id()                                                     );
    prep = fd_wksp_private_checkpt_buf  ( prep, wksp->name,        strlen( wksp->name      )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_app(),      strlen( fd_log_app()    )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_thread(),   strlen( fd_log_thread() )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_host(),     strlen( fd_log_host()   )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_cpu(),      strlen( fd_log_cpu()    )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_group(),    strlen( fd_log_group()  )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_user(),     strlen( fd_log_user()   )                         );
    prep = fd_wksp_private_checkpt_buf  ( prep, fd_log_build_info, fd_ulong_min( fd_log_build_info_sz-1UL, 16383UL ) );
    prep = fd_wksp_private_checkpt_buf  ( prep, uinfo,             fd_cstr_nlen( uinfo, 16383UL )                    );
    fd_wksp_private_checkpt_publish( checkpt, prep );

  //FD_LOG_INFO(( "Checkpt allocations" ));

    ulong part_max = wksp->part_max;
    fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

    ulong cycle_tag = wksp->cycle_tag++;

    ulong gaddr_last = data_lo;

    ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
    while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
      if( FD_UNLIKELY( i>=part_max ) || FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) goto corrupt_wksp;
      pinfo[ i ].cycle_tag = cycle_tag; /* mark i as visited */

      /* Do basic partition checks */

      ulong gaddr_lo = pinfo[ i ].gaddr_lo;
      ulong gaddr_hi = pinfo[ i ].gaddr_hi;
      ulong tag      = pinfo[ i ].tag;

      if( FD_UNLIKELY( !((gaddr_last==gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=data_hi)) ) ) goto corrupt_wksp;

      gaddr_last = gaddr_hi;

      /* If an allocated partition, checkpt it */

      if( tag ) { /* ~50/50 */

        ulong sz = gaddr_hi - gaddr_lo;
        void * laddr_lo = fd_wksp_laddr_fast( wksp, gaddr_lo );

        #if FD_HAS_DEEPASAN
        /* Copy the entire wksp over. This includes regions that may have been
           poisoned at one point. */
        fd_asan_unpoison( laddr_lo, sz );
        #endif

        /* Checkpt partition header */

        prep = fd_wksp_private_checkpt_prepare( checkpt, 3UL*9UL, &err ); if( FD_UNLIKELY( !prep ) ) goto io_err;
        prep = fd_wksp_private_checkpt_ulong( prep, tag      );
        prep = fd_wksp_private_checkpt_ulong( prep, gaddr_lo );
        prep = fd_wksp_private_checkpt_ulong( prep, sz       );
        fd_wksp_private_checkpt_publish( checkpt, prep );

        /* Checkpt partition data */

        err = fd_wksp_private_checkpt_write( checkpt, laddr_lo, sz ); if( FD_UNLIKELY( err ) ) goto io_err;
      }

      /* Advance to next partition */

      i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
    }

  //FD_LOG_INFO(( "Checkpt footer" ));

    prep = fd_wksp_private_checkpt_prepare( checkpt, 1UL*9UL, &err ); if( FD_UNLIKELY( !prep ) ) goto io_err;
    prep = fd_wksp_private_checkpt_ulong( prep, 0UL ); /* tags are never 0 above */
    fd_wksp_private_checkpt_publish( checkpt, prep );

    err = fd_io_buffered_ostream_flush( checkpt ); if( FD_UNLIKELY( err ) ) goto io_err;

    fd_wksp_private_unlock( wksp );

  //FD_LOG_INFO(( "Checkpt successful" ));

    /* note: err == 0 at this point */

  fini: /* note: wksp unlocked at this point */
    fd_io_buffered_ostream_fini( checkpt );
    if( FD_UNLIKELY( err ) && FD_UNLIKELY( unlink( path ) ) )
      FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));
    return err;

  io_err: /* Failed due to I/O error ... clean up and log (note: wksp locked at this point) */
    fd_wksp_private_unlock( wksp );
    FD_LOG_WARNING(( "Checkpt wksp \"%s\" to \"%s\" failed due to I/O error (%i-%s)",
                     wksp->name, path, err, fd_io_strerror( err ) ));
    err = FD_WKSP_ERR_FAIL;
    goto fini;

  corrupt_wksp: /* Failed due to wksp corruption ... clean up and log (note: wksp locked at this point) */
    fd_wksp_private_unlock( wksp );
    FD_LOG_WARNING(( "Checkpt wksp \"%s\" to \"%s\" failed due to wksp corruption", wksp->name, path ));
    err = FD_WKSP_ERR_CORRUPT;
    goto fini;

#   undef WBUF_FOOTPRINT
#   undef WBUF_ALIGN

  } /* FD_WKSP_CHECKPT_STYLE_RAW */

  default:
    break;
  }

  FD_LOG_WARNING(( "unsupported style" ));
  return FD_WKSP_ERR_INVAL;
}

/*********************************************************************/

int
fd_wksp_private_restore_ulong( fd_io_buffered_istream_t * in,
                               ulong *                    _val ) {
  ulong         csz;
  uchar const * buf;
  uchar         _buf[9UL];

  /* Read the encoded val */

  ulong peek_sz = fd_io_buffered_istream_peek_sz( in );

  if( FD_LIKELY( peek_sz>=9UL ) ) { /* encoded val already prefetched */
    buf = fd_io_buffered_istream_peek( in );
    csz = fd_ulong_svw_dec_sz( buf );
    fd_io_buffered_istream_seek( in, csz );
  } else { /* encoded val not guaranteed prefetched (this will also implicitly prefetch for future restores) */
    int err;
    err = fd_io_buffered_istream_read( in, _buf,     1UL     ); if( FD_UNLIKELY( err ) ) { *_val = 0UL; return err; }
    csz = fd_ulong_svw_dec_sz( _buf );
    err = fd_io_buffered_istream_read( in, _buf+1UL, csz-1UL ); if( FD_UNLIKELY( err ) ) { *_val = 0UL; return err; }
    buf = _buf;
  }

  /* Decode encoded val */

  *_val = fd_ulong_svw_dec_fixed( buf, csz );
  return 0;
}

int
fd_wksp_private_restore_buf( fd_io_buffered_istream_t * in,
                             void *                     buf,
                             ulong                      buf_max,
                             ulong *                    _buf_sz ) {

  /* Restore buf_sz */

  ulong buf_sz;
  int   err = fd_wksp_private_restore_ulong( in, &buf_sz );
  if( FD_UNLIKELY( (!!err) | (buf_sz>buf_max) ) ) { /* I/O error, unexpected EOF, or buf_max too small */
    if( !!err ) err = EPROTO; /* cmov */
    *_buf_sz = 0UL;
    return err;
  }

  /* Restore buf */

  err = fd_io_buffered_istream_read( in, buf, buf_sz );
  *_buf_sz = fd_ulong_if( !err, buf_sz, 0UL );
  return err;
}

/* TODO: CONSIDER ALLOWING RANGE OF TAGS?  CONSIDER OPS LIKE KEEPING
   EXISTING PARTITIONS / REPLACE CONFLICTING / ETC? */

int
fd_wksp_restore( fd_wksp_t *  wksp,
                 char const * path,
                 uint         new_seed ) {

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return FD_WKSP_ERR_INVAL;
  }

  if( FD_UNLIKELY( !path ) ) {
    FD_LOG_WARNING(( "NULL path" ));
    return FD_WKSP_ERR_INVAL;
  }

  FD_LOG_INFO(( "Restore checkpt \"%s\" into wksp \"%s\" (seed %u)", path, wksp->name, new_seed ));

  int fd = open( path, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return FD_WKSP_ERR_FAIL;
  }

# define RBUF_ALIGN     (4096UL)
# define RBUF_FOOTPRINT (65536UL)

  uchar                    rbuf[ RBUF_FOOTPRINT ] __attribute__((aligned( RBUF_ALIGN )));
  fd_io_buffered_istream_t restore[1];
  fd_io_buffered_istream_init( restore, fd, rbuf, RBUF_FOOTPRINT );

  int err;

  err = fd_wksp_private_lock( wksp ); if( FD_UNLIKELY( err ) ) goto fini; /* logs details */

  ulong                     wksp_part_max = wksp->part_max;
  ulong                     wksp_data_max = wksp->data_max;
  ulong                     wksp_data_lo  = wksp->gaddr_lo;
  ulong                     wksp_data_hi  = wksp->gaddr_hi;
  fd_wksp_private_pinfo_t * wksp_pinfo    = fd_wksp_private_pinfo( wksp );
  int                       wksp_dirty    = 0;

  char const * err_info;

# define RESTORE_ULONG(v) do {                               \
    err = fd_wksp_private_restore_ulong( restore, &v );      \
    if( FD_UNLIKELY( err ) ) { err_info = #v; goto io_err; } \
  } while(0)

# define RESTORE_CSTR(v,max) do {                                         \
    err = fd_wksp_private_restore_buf( restore, v, (max)-1UL, &v##_len ); \
    if( FD_UNLIKELY( err ) ) { err_info = #v; goto io_err; }              \
    v[v##_len] = '\0';                                                    \
  } while(0)

# define TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { err_info = #c; goto stream_err; } } while(0)

  FD_LOG_INFO(( "Restore header" ));

  ulong magic;    RESTORE_ULONG( magic    );                                  TEST( magic   ==FD_WKSP_MAGIC      );
  ulong style_ul; RESTORE_ULONG( style_ul ); int style = (int)(uint)style_ul; TEST( style_ul==(ulong)(uint)style );

  FD_LOG_INFO(( "checkpt_magic  %016lx", magic ));
  FD_LOG_INFO(( "checkpt_style  %i",     style ));

  switch( style ) {

  case FD_WKSP_CHECKPT_STYLE_RAW: {

    FD_LOG_INFO(( "Restore metadata" ));

    ulong seed_ul;   RESTORE_ULONG( seed_ul   ); uint seed = (uint)seed_ul; TEST( seed_ul==(ulong)seed                    );
    ulong part_max;  RESTORE_ULONG( part_max  );
    ulong data_max;  RESTORE_ULONG( data_max  );                            TEST( fd_wksp_footprint( part_max, data_max ) );

    ulong ts_ul;     RESTORE_ULONG( ts_ul     ); long ts = (long)ts_ul;     TEST( ts_ul==(ulong)ts                        );
    ulong app_id;    RESTORE_ULONG( app_id    );
    ulong thread_id; RESTORE_ULONG( thread_id );
    ulong host_id;   RESTORE_ULONG( host_id   );
    ulong cpu_id;    RESTORE_ULONG( cpu_id    );
    ulong group_id;  RESTORE_ULONG( group_id  );                            TEST( group_id>=2UL                           );
    ulong tid;       RESTORE_ULONG( tid       );
    ulong user_id;   RESTORE_ULONG( user_id   );

    char name[ FD_SHMEM_NAME_MAX ]; ulong name_len; RESTORE_CSTR( name, FD_SHMEM_NAME_MAX );
    TEST( fd_shmem_name_len( name )==name_len );

    char app   [ FD_LOG_NAME_MAX ]; ulong app_len;    RESTORE_CSTR( app,    FD_LOG_NAME_MAX ); TEST( strlen( app    )==app_len    );
    char thread[ FD_LOG_NAME_MAX ]; ulong thread_len; RESTORE_CSTR( thread, FD_LOG_NAME_MAX ); TEST( strlen( thread )==thread_len );
    char host  [ FD_LOG_NAME_MAX ]; ulong host_len;   RESTORE_CSTR( host,   FD_LOG_NAME_MAX ); TEST( strlen( host   )==host_len   );
    char cpu   [ FD_LOG_NAME_MAX ]; ulong cpu_len;    RESTORE_CSTR( cpu,    FD_LOG_NAME_MAX ); TEST( strlen( cpu    )==cpu_len    );
    char group [ FD_LOG_NAME_MAX ]; ulong group_len;  RESTORE_CSTR( group,  FD_LOG_NAME_MAX ); TEST( strlen( group  )==group_len  );
    char user  [ FD_LOG_NAME_MAX ]; ulong user_len;   RESTORE_CSTR( user,   FD_LOG_NAME_MAX ); TEST( strlen( user   )==user_len   );

    char ts_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ]; fd_log_wallclock_cstr( ts, ts_cstr );

    FD_LOG_INFO(( "checkpt_ts     %-20li \"%s\"", ts,        ts_cstr ));
    FD_LOG_INFO(( "checkpt_app    %-20lu \"%s\"", app_id,    app     ));
    FD_LOG_INFO(( "checkpt_thread %-20lu \"%s\"", thread_id, thread  ));
    FD_LOG_INFO(( "checkpt_host   %-20lu \"%s\"", host_id,   host    ));
    FD_LOG_INFO(( "checkpt_cpu    %-20lu \"%s\"", cpu_id,    cpu     ));
    FD_LOG_INFO(( "checkpt_group  %-20lu \"%s\"", group_id,  group   ));
    FD_LOG_INFO(( "checkpt_tid    %-20lu",        tid                ));
    FD_LOG_INFO(( "checkpt_user   %-20lu \"%s\"", user_id,   user    ));

    char buf[ 16384 ]; ulong buf_len;

    RESTORE_CSTR( buf, 16384UL ); TEST( strlen( buf )==buf_len );
    FD_LOG_INFO(( "checkpt_build\n\t%s", buf ) );

    RESTORE_CSTR( buf, 16384UL ); TEST( strlen( buf )==buf_len );
    FD_LOG_INFO(( "checkpt_info\n\t%s", buf ));

    FD_LOG_INFO(( "shmem_name     \"%s\"", name     ));
    FD_LOG_INFO(( "seed           %-20u",  seed     ));
    FD_LOG_INFO(( "part_max       %-20lu", part_max ));
    FD_LOG_INFO(( "data_max       %-20lu", data_max ));

    ulong data_lo = fd_wksp_private_data_off( part_max );
    ulong data_hi = data_lo + data_max;

    FD_LOG_INFO(( "Restore allocations" ));

    ulong wksp_part_cnt = 0UL;

    for(;;) {

      /* Restore the allocation header */

      ulong tag;      RESTORE_ULONG( tag      ); if( FD_UNLIKELY( !tag ) ) break; /* Optimize for lots of partitions */
      ulong gaddr_lo; RESTORE_ULONG( gaddr_lo );
      ulong sz;       RESTORE_ULONG( sz       );

      ulong gaddr_hi = gaddr_lo + sz;

      TEST( (data_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=data_hi) );

      if( FD_UNLIKELY( wksp_part_cnt>=wksp_part_max ) ) {
        FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because too few wksp partitions (part_max checkpt %lu, wksp %lu)",
                         path, wksp->name, part_max, wksp_part_max ));
        goto unlock;
      }

        // FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because checkpt partition [0x%016lx,0x%016lx) tag %lu "
        //                  "does not fit into wksp data region [0x%016lx,0x%016lx) (data_max checkpt %lu, wksp %lu)",
        //                  path, wksp->name, gaddr_lo, gaddr_hi, tag, wksp_data_lo, wksp_data_hi, data_max, wksp_data_max ));
      if( FD_UNLIKELY( !((wksp_data_lo<=gaddr_lo) & (gaddr_hi<=wksp_data_hi)) ) ) {
        FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because checkpt partition [0x%016lx,0x%016lx) tag %lu "
                         "does not fit into wksp data region [0x%016lx,0x%016lx) (data_max checkpt %lu, wksp %lu)",
                         path, wksp->name, gaddr_lo, gaddr_hi, tag, wksp_data_lo, wksp_data_hi, data_max, wksp_data_max ));
        goto unlock;
      }

      /* Restore the allocation payload into the wksp and record this
         allocation in the wksp */

      wksp_dirty = 1;

      #if FD_HAS_DEEPASAN
      fd_asan_unpoison( fd_wksp_laddr_fast( wksp, gaddr_lo ), sz );
      #endif

      err = fd_io_buffered_istream_read( restore, fd_wksp_laddr_fast( wksp, gaddr_lo ), sz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because of I/O error (%i-%s)",
                         path, wksp->name, err, fd_io_strerror( err ) ));
        goto unlock;
      }

      wksp_pinfo[ wksp_part_cnt ].gaddr_lo = gaddr_lo;
      wksp_pinfo[ wksp_part_cnt ].gaddr_hi = gaddr_hi;
      wksp_pinfo[ wksp_part_cnt ].tag      = tag;
      wksp_part_cnt++;
    }

    FD_LOG_INFO(( "Rebuilding wksp with restored allocations" ));

    wksp_dirty = 1;

    for( ulong i=wksp_part_cnt; i<wksp_part_max; i++ ) wksp_pinfo[ i ].tag = 0UL; /* Remove all remaining old allocations */
    err = fd_wksp_rebuild( wksp, new_seed ); /* logs details */
    if( FD_UNLIKELY( err ) ) { /* wksp dirty */
      FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because of rebuild error", path, wksp->name ));
      goto unlock;
    }

    wksp_dirty = 0;

    FD_LOG_INFO(( "Restore successful" ));
    break;

  } /* FD_WKSP_CHECKPT_STYLE_RAW */

  default:
    err_info = "unsupported style";
    goto stream_err;
  }

  /* err = 0 at this point */

unlock: /* note: wksp locked at this point */

  /* If wksp is not clean, reset it to get it back to a clean state
     (TODO: consider FD_LOG_CRIT here if rebuild fails though it
     shouldn't) */

  if( wksp_dirty ) {
    FD_LOG_WARNING(( "wksp \"%s\" dirty; attempting to reset it and continue", wksp->name ));
    for( ulong i=0UL; i<wksp_part_max; i++ ) wksp_pinfo[ i ].tag = 0UL;
    fd_wksp_rebuild( wksp, new_seed ); /* logs details */
    err = FD_WKSP_ERR_CORRUPT;
  }

  fd_wksp_private_unlock( wksp );

fini: /* Note: wksp unlocked at this point */

  fd_io_buffered_istream_fini( restore );

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  return err;

io_err: /* Note: wksp locked at this point */

  FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed (%s) due to I/O error (%i-%s)",
                   path, wksp->name, err_info, err, fd_io_strerror( err ) ));
  err = FD_WKSP_ERR_FAIL;

  goto unlock;

stream_err: /* Note: wksp locked at this point */

  FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed due to checkpt format error (%s)", path, wksp->name, err_info ));
  err = FD_WKSP_ERR_FAIL;

  goto unlock;

# undef TEST
# undef RESTORE_CSTR
# undef RESTORE_ULONG
# undef RBUF_FOOTPRINT
# undef RBUF_ALIGN
}

int
fd_wksp_restore_preview( char const * path,
                         uint *       out_seed,
                         ulong *      out_part_max,
                         ulong *      out_data_max ) {
  if( FD_UNLIKELY( !path ) ) {
    FD_LOG_WARNING(( "NULL path" ));
    return FD_WKSP_ERR_INVAL;
  }

  int fd = open( path, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return FD_WKSP_ERR_FAIL;
  }

# define RBUF_ALIGN     (4096UL)
# define RBUF_FOOTPRINT (65536UL)

  uchar                    rbuf[ RBUF_FOOTPRINT ] __attribute__((aligned( RBUF_ALIGN )));
  fd_io_buffered_istream_t restore[1];
  fd_io_buffered_istream_init( restore, fd, rbuf, RBUF_FOOTPRINT );

  int err = FD_WKSP_SUCCESS;

# define RESTORE_ULONG(v) do {                               \
    err = fd_wksp_private_restore_ulong( restore, &v );      \
    if( FD_UNLIKELY( err ) ) { goto io_err; } \
  } while(0)

  ulong magic;    RESTORE_ULONG( magic    );
  if( magic!=FD_WKSP_MAGIC ) { err = FD_WKSP_ERR_FAIL; goto io_err; }
  ulong style_ul; RESTORE_ULONG( style_ul ); int style = (int)(uint)style_ul;

  switch( style ) {
  case FD_WKSP_CHECKPT_STYLE_RAW: {
    ulong tseed_ul;   RESTORE_ULONG( tseed_ul  ); *out_seed = (uint)tseed_ul;
    ulong tpart_max;  RESTORE_ULONG( tpart_max ); *out_part_max = tpart_max;
    ulong tdata_max;  RESTORE_ULONG( tdata_max ); *out_data_max = tdata_max;
    break;
  } /* FD_WKSP_CHECKPT_STYLE_RAW */

  default:
    err = FD_WKSP_ERR_FAIL;
    break;
  }

 io_err:
  fd_io_buffered_istream_fini( restore );

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  return err;

#undef RESTORE_ULONG
}
