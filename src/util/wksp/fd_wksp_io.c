#include "fd_wksp_private.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* fd_wksp_private_checkpt_read reads up to the leading buf_max bytes at
   path into buf.  On success, returns 0 and *_buf_sz will contain the
   number of bytes read.  Returns a fd_io_strerror compatible error code
   on failure and *_buf_sz will be unchanged (buf might have been
   clobbered). */

static int
fd_wksp_private_checkpt_read( char const * path,       /* Assumes valid */
                              void *       buf,        /* Assumes valid */
                              ulong        buf_max,    /* Assumes buf_max>=12 */
                              ulong *      _buf_sz ) { /* Assumes non-NULL */

  int fd = open( path, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) return errno;

  int err = fd_io_read( fd, buf, 12UL, buf_max, _buf_sz );

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  return err;
}

int
fd_wksp_preview( char const *        path,
                 fd_wksp_preview_t * _opt_preview ) {

  /* Check input args */

  if( FD_UNLIKELY( !path ) ) return FD_WKSP_ERR_INVAL;

  fd_wksp_preview_t stack_preview[1];
  if( !_opt_preview ) _opt_preview = stack_preview; /* cmov */

  /* Read the wksp checkpt header.  165 is large enough to
     handle decoding an arbitrarily corrupted V1 header (14 worst case
     SVW encoded ulongs at 9 bytes each followed by a worst case
     non-'\0' bytes of name at 39==FD_SHMEM_NAME_MAX-1 bytes) and an
     arbitrarily corrupted V2 header (a 80 byte struct stored
     uncompressed). */

  uchar buf[ 165 ];
  ulong buf_sz;
  int   err = fd_wksp_private_checkpt_read( path, buf, 165UL, &buf_sz );
  if( FD_UNLIKELY( err ) ) return FD_WKSP_ERR_FAIL;

  /* If we read a supported valid V2 header, return the requested
     preview info */

  fd_wksp_checkpt_v2_hdr_t * v2 = (fd_wksp_checkpt_v2_hdr_t *)buf;

  ulong name_len = fd_shmem_name_len( v2->name ); /* tail reading safe */

  if( FD_LIKELY( (sizeof(fd_wksp_checkpt_v2_hdr_t)<=buf_sz                         ) &     /* header not truncated */
                 (v2->magic==FD_WKSP_MAGIC                                         ) &     /* with valid magic */
                 (v2->style==FD_WKSP_CHECKPT_STYLE_V2                              ) &     /* with valid style */
                 (fd_checkpt_frame_style_is_supported( v2->frame_style_compressed )) &     /* with supported compression */
                 (v2->reserved==0U                                                 ) &     /* with expected reserved */
                 (name_len>0UL                                                     ) &     /* with valid name */
                 /* ignore seed (arbitrary) */
                 (fd_wksp_footprint( v2->part_max, v2->data_max )>0UL              ) ) ) { /* with valid part_max / data_max */
    _opt_preview->style    = v2->style;
    _opt_preview->seed     = v2->seed;
    _opt_preview->part_max = v2->part_max;
    _opt_preview->data_max = v2->data_max;
    memcpy( _opt_preview->name, v2->name, name_len+1UL );
    return FD_WKSP_SUCCESS;
  }

  /* Otherwise, if we read a supported valid V1 header, return the
     requested preview info */

  uchar const * cur = buf;

  ulong magic;     cur = fd_ulong_svw_dec( cur, &magic     ); /* safe to tail read */
  ulong style_ul;  cur = fd_ulong_svw_dec( cur, &style_ul  ); /* " */
  ulong seed_ul;   cur = fd_ulong_svw_dec( cur, &seed_ul   ); /* " */
  ulong part_max;  cur = fd_ulong_svw_dec( cur, &part_max  ); /* " */
  ulong data_max;  cur = fd_ulong_svw_dec( cur, &data_max  ); /* " */
  ulong ts_ul;     cur = fd_ulong_svw_dec( cur, &ts_ul     ); /* " */
  ulong app_id;    cur = fd_ulong_svw_dec( cur, &app_id    ); /* " */
  ulong thread_id; cur = fd_ulong_svw_dec( cur, &thread_id ); /* " */
  ulong host_id;   cur = fd_ulong_svw_dec( cur, &host_id   ); /* " */
  ulong cpu_id;    cur = fd_ulong_svw_dec( cur, &cpu_id    ); /* " */
  ulong group_id;  cur = fd_ulong_svw_dec( cur, &group_id  ); /* " */
  ulong tid;       cur = fd_ulong_svw_dec( cur, &tid       ); /* " */
  ulong user_id;   cur = fd_ulong_svw_dec( cur, &user_id   ); /* " */
  /* name_len */   cur = fd_ulong_svw_dec( cur, &name_len  ); /* " */

  char  name[ FD_SHMEM_NAME_MAX ];
  ulong name_len_safe = fd_ulong_min( name_len, FD_SHMEM_NAME_MAX-1UL );
  memcpy( name, cur, name_len_safe );
  name[ name_len_safe ] = '\0';

  if( FD_LIKELY( (((ulong)(cur-buf))<=buf_sz                            ) &     /* header not truncated */
                 (magic   ==FD_WKSP_MAGIC                               ) &     /* with valid magic */
                 (style_ul==(ulong)FD_WKSP_CHECKPT_STYLE_V1             ) &     /* with valid style */
                 (seed_ul ==(ulong)(uint)seed_ul                        ) &     /* with valid seed */
                 (fd_wksp_footprint( part_max, data_max )>0UL           ) &     /* with valid part_max / data_max */
                 /* ignore ts_ul     (metadata) */
                 /* ignore app_id    (metadata) */
                 /* ignore thread_id (metadata) */
                 /* ignore host_id   (metadata) */
                 /* ignore cpu_id    (metadata) */
                 /* ignore group_id  (metadata) */
                 /* ignore tid_id    (metadata) */
                 /* ignore user_id   (metadata) */
                 ((name_len>0UL) & (fd_shmem_name_len( name )==name_len)) ) ) { /* with valid name */
    _opt_preview->style    = (int)style_ul;
    _opt_preview->seed     = (uint)seed_ul;
    _opt_preview->part_max = part_max;
    _opt_preview->data_max = data_max;
    memcpy( _opt_preview->name, name, name_len+1UL );
    return FD_WKSP_SUCCESS;
  }

  /* Otherwise, this is not a supported valid wksp checkpt header */

  return FD_WKSP_ERR_CORRUPT;
}

int
fd_wksp_checkpt_tpool( fd_tpool_t * tpool,
                       ulong        t0,
                       ulong        t1,
                       fd_wksp_t *  wksp,
                       char const * path,
                       ulong        mode,
                       int          style,
                       char const * uinfo ) { /* TODO: CONSIDER ALLOWING SUBSET OF TAGS */

  /* Check input args */

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

  style = fd_int_if( !!style, style, FD_HAS_LZ4 ? FD_WKSP_CHECKPT_STYLE_V3 : FD_WKSP_CHECKPT_STYLE_V2 );

  if( FD_UNLIKELY( !uinfo ) ) uinfo = "";

  char const * binfo = fd_log_build_info;
  if( FD_UNLIKELY( !binfo ) ) binfo = "";

  /* Checkpt with the appropriate style */

  switch( style ) {
  case FD_WKSP_CHECKPT_STYLE_V1: return fd_wksp_private_checkpt_v1( tpool, t0, t1, wksp, path, mode, uinfo );
  case FD_WKSP_CHECKPT_STYLE_V2: return fd_wksp_private_checkpt_v2( tpool, t0, t1, wksp, path, mode, uinfo,
                                                                    FD_CHECKPT_FRAME_STYLE_RAW );
  case FD_WKSP_CHECKPT_STYLE_V3: return fd_wksp_private_checkpt_v2( tpool, t0, t1, wksp, path, mode, uinfo,
                                                                    FD_CHECKPT_FRAME_STYLE_LZ4 );
  break;
  }

  FD_LOG_WARNING(( "unsupported style" ));
  return FD_WKSP_ERR_INVAL;
}

int
fd_wksp_restore_tpool( fd_tpool_t * tpool,
                       ulong        t0,
                       ulong        t1,
                       fd_wksp_t *  wksp,
                       char const * path,
                       uint         new_seed ) {

  /* Check input args */

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return FD_WKSP_ERR_INVAL;
  }

  if( FD_UNLIKELY( !path ) ) {
    FD_LOG_WARNING(( "NULL path" ));
    return FD_WKSP_ERR_INVAL;
  }

  /* new_seed arbitrary */

  /* Determine which version to use */

  fd_wksp_preview_t preview[1];
  int err = fd_wksp_preview( path, preview );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "\"%s\" does not appear to be a supported wksp checkpt", path ));
    return err;
  }

  /* Restore with the appropriate version */

  switch( preview->style ) {
  case FD_WKSP_CHECKPT_STYLE_V1: return fd_wksp_private_restore_v1( tpool, t0, t1, wksp, path, new_seed );
  case FD_WKSP_CHECKPT_STYLE_V2: return fd_wksp_private_restore_v2( tpool, t0, t1, wksp, path, new_seed );
  /* note: v3 is really v2 with compressed frames */
  default: break; /* never get here (preview already checked) */
  }

  FD_LOG_WARNING(( "unsupported style" ));
  return FD_WKSP_ERR_CORRUPT;
}

int
fd_wksp_printf( int          fd,
                char const * path,
                int          verbose ) {

  int ret = 0;
# define TRAP(expr) do { int _err = (expr); if( FD_UNLIKELY( _err<0 ) ) { return _err; } ret += _err; } while(0)

  if( verbose<0 ) return ret;

  TRAP( dprintf( fd, "checkpt %s (verbose %i)\n", path, verbose ) );

  fd_wksp_preview_t preview[1];
  int err = fd_wksp_preview( path, preview );
  if( FD_UNLIKELY( err ) )
    TRAP( dprintf( fd, "\tinvalid or unsupported (%i-%s)\n", err, fd_wksp_strerror( err ) ) );
  else
    TRAP( dprintf( fd, "\tstyle                  %-20i\n"
                       "\tname                   %s\n"
                       "\tseed                   %-20u\n"
                       "\tpart_max               %-20lu\n"
                       "\tdata_max               %-20lu\n",
                       preview->style, preview->name, preview->seed, preview->part_max, preview->data_max ) );

  if( verbose<1 ) return ret;

  switch( preview->style ) {
  case FD_WKSP_CHECKPT_STYLE_V1: TRAP( fd_wksp_private_printf_v1( fd, path, verbose ) ); break;
  case FD_WKSP_CHECKPT_STYLE_V2: TRAP( fd_wksp_private_printf_v2( fd, path, verbose ) ); break;
  /* note: v3 is really v2 with compressed frames */
  default: /* never get here (preview already checked) */
    TRAP( dprintf( fd, "unsupported style" ) );
    break;
  }

# undef TRAP

  return ret;
}
