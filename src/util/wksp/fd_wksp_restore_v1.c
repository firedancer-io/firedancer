#include "fd_wksp_private.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* fd_wksp_private_restore_ulong restores a ulong from the stream in.
   Returns 0 on success and, on return, *_val will contain the restored
   val.  Returns non-zero on failure (will be an errno compat error
   code) and, on failure, *_val will be zero.  This will implicitly read
   ahead for future restores. */

static int
fd_wksp_private_restore_v1_ulong( fd_io_buffered_istream_t * in,
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

/* fd_wksp_private_restore_buf restores a variable length buffer buf of
   maximum size buf_max from the stream in.  Returns 0 on success and,
   on success, buf will contain the buffer and *_buf_sz will contain the
   buffer's size (will be in [0,buf_max]).  Returns non-zero on failure
   (will be an errno compat error code) and, on failure, buf will be
   clobbered and *_buf_sz will be zero.  This will implicitly read ahead
   for future restores.  Zero buf_max is fine (and NULL buf is fine if
   buf_max is zero). */

static int
fd_wksp_private_restore_v1_buf( fd_io_buffered_istream_t * in,
                                void *                     buf,
                                ulong                      buf_max,
                                ulong *                    _buf_sz ) {

  /* Restore buf_sz */

  ulong buf_sz;
  int   err = fd_wksp_private_restore_v1_ulong( in, &buf_sz );
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

#define RESTORE_ULONG(v) do {                                \
    err = fd_wksp_private_restore_v1_ulong( restore, &v );   \
    if( FD_UNLIKELY( err ) ) { err_info = #v; goto io_err; } \
  } while(0)

/* Note: on success, v_len==strlen( v ) and will be in [0,max).  Assumes
   max is positive. */

#define RESTORE_CSTR(v,max) do {                                              \
    err = fd_wksp_private_restore_v1_buf( restore, v, (max)-1UL, &v##_len );  \
    if( FD_UNLIKELY( err ) ) { err_info = #v; goto io_err; }                  \
    v[v##_len] = '\0'; /* v##_len in [0,max) at this point */                 \
    if( FD_UNLIKELY( strlen( v )!=v##_len ) ) { err_info = #v; goto io_err; } \
  } while(0)

#define RBUF_ALIGN     (4096UL)
#define RBUF_FOOTPRINT (65536UL)

int
fd_wksp_private_restore_v1( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            uint         new_seed ) {
  (void)tpool; (void)t0; (void)t1; /* Note: Thread parallel v1 checkpoint not supported */

  FD_LOG_INFO(( "Restore checkpt \"%s\" into wksp \"%s\" (seed %u)", path, wksp->name, new_seed ));

  int fd = open( path, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return FD_WKSP_ERR_FAIL;
  }

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

# define RESTORE_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { err_info = #c; goto stream_err; } } while(0)

  ulong orig_part_max;
  ulong orig_data_max;

  {
    FD_LOG_INFO(( "Restore header (v1)" ));

    ulong magic;     RESTORE_ULONG( magic     );
    ulong style_ul;  RESTORE_ULONG( style_ul  );
    ulong seed_ul;   RESTORE_ULONG( seed_ul   );
    ulong part_max;  RESTORE_ULONG( part_max  );
    ulong data_max;  RESTORE_ULONG( data_max  );
    ulong ts_ul;     RESTORE_ULONG( ts_ul     ); /* considered metadata */
    ulong app_id;    RESTORE_ULONG( app_id    ); /* " */
    ulong thread_id; RESTORE_ULONG( thread_id ); /* " */
    ulong host_id;   RESTORE_ULONG( host_id   ); /* " */
    ulong cpu_id;    RESTORE_ULONG( cpu_id    ); /* " */
    ulong group_id;  RESTORE_ULONG( group_id  ); /* " */
    ulong tid;       RESTORE_ULONG( tid       ); /* " */
    ulong user_id;   RESTORE_ULONG( user_id   ); /* " */

    char name[ FD_SHMEM_NAME_MAX ]; ulong name_len; RESTORE_CSTR( name, FD_SHMEM_NAME_MAX );

    RESTORE_TEST( magic==FD_WKSP_MAGIC                                   );
    RESTORE_TEST( style_ul==(ulong)FD_WKSP_CHECKPT_STYLE_V1              );
    RESTORE_TEST( seed_ul==(ulong)(uint)seed_ul                          );
    RESTORE_TEST( fd_wksp_footprint( part_max, data_max )>0UL            );
    RESTORE_TEST( (name_len>0UL) & (fd_shmem_name_len( name )==name_len) );

    FD_LOG_INFO(( "Restore metadata (v1)" ));

    char ts_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    fd_log_wallclock_cstr( (long)ts_ul, ts_cstr );

    char app   [ FD_LOG_NAME_MAX              ]; ulong app_len;    RESTORE_CSTR( app,    FD_LOG_NAME_MAX              );
    char thread[ FD_LOG_NAME_MAX              ]; ulong thread_len; RESTORE_CSTR( thread, FD_LOG_NAME_MAX              );
    char host  [ FD_LOG_NAME_MAX              ]; ulong host_len;   RESTORE_CSTR( host,   FD_LOG_NAME_MAX              );
    char cpu   [ FD_LOG_NAME_MAX              ]; ulong cpu_len;    RESTORE_CSTR( cpu,    FD_LOG_NAME_MAX              );
    char group [ FD_LOG_NAME_MAX              ]; ulong group_len;  RESTORE_CSTR( group,  FD_LOG_NAME_MAX              );
    char user  [ FD_LOG_NAME_MAX              ]; ulong user_len;   RESTORE_CSTR( user,   FD_LOG_NAME_MAX              );
    char binfo [ FD_WKSP_CHECKPT_V1_BINFO_MAX ]; ulong binfo_len;  RESTORE_CSTR( binfo,  FD_WKSP_CHECKPT_V1_BINFO_MAX );
    char uinfo [ FD_WKSP_CHECKPT_V1_UINFO_MAX ]; ulong uinfo_len;  RESTORE_CSTR( uinfo,  FD_WKSP_CHECKPT_V1_UINFO_MAX );

    /* Note: this mirrors v2 */

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
                  "\tbinfo\n\t\t%s\n"                     /* verbose 2 info */
                  "\tuinfo\n\t\t%s",
                  (int)style_ul, name, (uint)seed_ul, part_max, data_max,
                  magic, (long)ts_ul, ts_cstr,
                  app_id,    app,
                  thread_id, thread,
                  host_id,   host,
                  cpu_id,    cpu,
                  group_id,  group,
                  tid,
                  user_id,   user,
                  binfo,
                  uinfo ));

    orig_part_max = part_max;
    orig_data_max = data_max;
  }

  FD_LOG_INFO(( "Restore allocations" ));

  ulong orig_data_lo  = fd_wksp_private_data_off( orig_part_max );
  ulong orig_data_hi  = orig_data_lo + orig_data_max;
  ulong wksp_part_cnt = 0UL;

  for(;;) {

    /* Restore the allocation header */

    ulong tag;      RESTORE_ULONG( tag      ); if( FD_UNLIKELY( !tag ) ) break; /* Optimize for lots of partitions */
    ulong gaddr_lo; RESTORE_ULONG( gaddr_lo );
    ulong sz;       RESTORE_ULONG( sz       );

    ulong gaddr_hi = gaddr_lo + sz;

    RESTORE_TEST( (orig_data_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=orig_data_hi) );

    if( FD_UNLIKELY( wksp_part_cnt>=wksp_part_max ) ) {
      FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because too few wksp partitions (part_max checkpt %lu, wksp %lu)",
                       path, wksp->name, orig_part_max, wksp_part_max ));
      goto unlock;
    }

    if( FD_UNLIKELY( !((wksp_data_lo<=gaddr_lo) & (gaddr_hi<=wksp_data_hi)) ) ) {
      FD_LOG_WARNING(( "Restore \"%s\" to wksp \"%s\" failed because checkpt partition [0x%016lx,0x%016lx) tag %lu "
                       "does not fit into wksp data region [0x%016lx,0x%016lx) (data_max checkpt %lu, wksp %lu)",
                       path, wksp->name, gaddr_lo, gaddr_hi, tag, wksp_data_lo, wksp_data_hi, orig_data_max, wksp_data_max ));
      goto unlock;
    }

    /* Restore the allocation payload into the wksp and record this
       allocation in the wksp */

    wksp_dirty = 1;

    #if FD_HAS_DEEPASAN
    /* Poison the restored allocations. Potentially under poison to respect
       manual poisoning alignment requirements. Don't poison if the allocation
       is smaller than FD_ASAN_ALIGN. */
    ulong laddr_lo = (ulong)fd_wksp_laddr_fast( wksp, gaddr_lo );
    ulong laddr_hi = laddr_lo + sz;
    ulong aligned_laddr_lo = fd_ulong_align_up( laddr_lo, FD_ASAN_ALIGN );
    ulong aligned_laddr_hi = fd_ulong_align_dn( laddr_hi, FD_ASAN_ALIGN );
    if( aligned_laddr_lo < aligned_laddr_hi ) {
      fd_asan_poison( (void*)aligned_laddr_lo, aligned_laddr_hi - aligned_laddr_lo );
    }
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

  /* err = 0 at this point */

unlock: /* note: wksp locked at this point */

  /* If wksp is not clean, reset it to get it back to a clean state */

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

# undef RESTORE_TEST
}

int
fd_wksp_private_printf_v1( int          out,
                           char const * path,
                           int          verbose ) {

# define TRAP(x)         do { err = (x); if( FD_UNLIKELY( err<0 ) ) { ret = err; goto done; } ret += err; } while(0)
# define RESTORE_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { err_info = #c; goto stream_err; } } while(0)

  int                        fd      = -1;
  fd_io_buffered_istream_t * restore = NULL;
  int                        ret     = 0;
  int                        err;
  char const *               err_info;
  uchar                      rbuf[ RBUF_FOOTPRINT ] __attribute__((aligned( RBUF_ALIGN )));
  fd_io_buffered_istream_t   _restore[1];

  fd = open( path, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) TRAP( dprintf( out, "\topen(O_RDONLY) failed (%i-%s)\n", errno, fd_io_strerror( errno ) ) );

  restore = fd_io_buffered_istream_init( _restore, fd, rbuf, RBUF_FOOTPRINT );

  /* Print the header and metadata (note: fd_wksp_private_printf
     already printed the preview info and verbose is at least 1) */

  ulong orig_part_max;
  ulong orig_data_max;

  {
    ulong magic;     RESTORE_ULONG( magic     );
    ulong style_ul;  RESTORE_ULONG( style_ul  );
    ulong seed_ul;   RESTORE_ULONG( seed_ul   );
    ulong part_max;  RESTORE_ULONG( part_max  );
    ulong data_max;  RESTORE_ULONG( data_max  );
    ulong ts_ul;     RESTORE_ULONG( ts_ul     ); /* considered metadata */
    ulong app_id;    RESTORE_ULONG( app_id    ); /* " */
    ulong thread_id; RESTORE_ULONG( thread_id ); /* " */
    ulong host_id;   RESTORE_ULONG( host_id   ); /* " */
    ulong cpu_id;    RESTORE_ULONG( cpu_id    ); /* " */
    ulong group_id;  RESTORE_ULONG( group_id  ); /* " */
    ulong tid;       RESTORE_ULONG( tid       ); /* " */
    ulong user_id;   RESTORE_ULONG( user_id   ); /* " */

    char name[ FD_SHMEM_NAME_MAX ]; ulong name_len; RESTORE_CSTR( name, FD_SHMEM_NAME_MAX );

    RESTORE_TEST( magic==FD_WKSP_MAGIC                                   );
    RESTORE_TEST( style_ul==(ulong)FD_WKSP_CHECKPT_STYLE_V1              );
    RESTORE_TEST( seed_ul==(ulong)(uint)seed_ul                          );
    RESTORE_TEST( fd_wksp_footprint( part_max, data_max )>0UL            );
    RESTORE_TEST( (name_len>0UL) & (fd_shmem_name_len( name )==name_len) );

    char app   [ FD_LOG_NAME_MAX              ]; ulong app_len;    RESTORE_CSTR( app,    FD_LOG_NAME_MAX              );
    char thread[ FD_LOG_NAME_MAX              ]; ulong thread_len; RESTORE_CSTR( thread, FD_LOG_NAME_MAX              );
    char host  [ FD_LOG_NAME_MAX              ]; ulong host_len;   RESTORE_CSTR( host,   FD_LOG_NAME_MAX              );
    char cpu   [ FD_LOG_NAME_MAX              ]; ulong cpu_len;    RESTORE_CSTR( cpu,    FD_LOG_NAME_MAX              );
    char group [ FD_LOG_NAME_MAX              ]; ulong group_len;  RESTORE_CSTR( group,  FD_LOG_NAME_MAX              );
    char user  [ FD_LOG_NAME_MAX              ]; ulong user_len;   RESTORE_CSTR( user,   FD_LOG_NAME_MAX              );
    char binfo [ FD_WKSP_CHECKPT_V1_BINFO_MAX ]; ulong binfo_len;  RESTORE_CSTR( binfo,  FD_WKSP_CHECKPT_V1_BINFO_MAX );
    char uinfo [ FD_WKSP_CHECKPT_V1_UINFO_MAX ]; ulong uinfo_len;  RESTORE_CSTR( uinfo,  FD_WKSP_CHECKPT_V1_UINFO_MAX );

    char ts_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    fd_log_wallclock_cstr( (long)ts_ul, ts_cstr );

    /* Note: this mirrors v2 printf */

    if( verbose>=1 )
      TRAP( dprintf( out,
                   //"\tstyle                  %-20i\n"        /* verbose 0 info (already printed) */
                   //"\tname                   %s\n"
                   //"\tseed                   %-20u\n"
                   //"\tpart_max               %-20lu\n"
                   //"\tdata_max               %-20lu\n"
                     "\tmagic                  %016lx\n"       /* verbose 1 info */
                     "\twallclock              %-20li (%s)\n"
                     "\tapp                    %-20lu (%s)\n"
                     "\tthread                 %-20lu (%s)\n"
                     "\thost                   %-20lu (%s)\n"
                     "\tcpu                    %-20lu (%s)\n"
                     "\tgroup                  %-20lu (%s)\n"
                     "\ttid                    %-20lu\n"
                     "\tuser                   %-20lu (%s)\n",
                     magic,
                     (long)ts_ul, ts_cstr,
                     app_id,      app,
                     thread_id,   thread,
                     host_id,     host,
                     cpu_id,      cpu,
                     group_id,    group,
                     tid,
                     user_id,     user ) );
    if( verbose>=2 )
      TRAP( dprintf( out, "\tbinfo\n\t\t%s\n"
                          "\tuinfo\n\t\t%s\n", binfo, uinfo ) ); /* verbose 2 info */

    orig_part_max = part_max;
    orig_data_max = data_max;
  }

  if( verbose>=3 ) {

    ulong orig_data_lo = fd_wksp_private_data_off( orig_part_max );
    ulong orig_data_hi = orig_data_lo + orig_data_max;

    ulong alloc_tot = 0UL;
    ulong alloc_cnt = 0UL;
    ulong alloc_big = 0UL;

    if( verbose>=4 ) TRAP( dprintf( out, "\tgaddr          [0x%016lx,0x%016lx)\n", orig_data_lo, orig_data_hi ) );

    for(;;) {

      /* Print partition metadata */

      ulong tag;      RESTORE_ULONG( tag      ); if( !tag ) break; /* no more partitions */
      ulong gaddr_lo; RESTORE_ULONG( gaddr_lo );
      ulong sz;       RESTORE_ULONG( sz       );

      ulong gaddr_hi = gaddr_lo + sz;

      RESTORE_TEST( (orig_data_lo<=gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=orig_data_hi) );

      if( verbose>=4 ) TRAP( dprintf( out, "\tpartition      [0x%016lx,0x%016lx) sz %20lu tag %20lu\n", gaddr_lo, gaddr_hi, sz, tag ) );

      alloc_cnt += 1UL;
      alloc_tot += sz;
      alloc_big  = fd_ulong_max( alloc_big, sz );

      /* Skip partition data (TODO: add verbose 5 for pretty printing
         the raw partition data too). */

      int err = fd_io_buffered_istream_skip( restore, sz );
      if( FD_UNLIKELY( err ) ) { err_info = "partition data"; goto io_err; }
    }

    TRAP( dprintf( out, "\t%20lu bytes used (%20lu blocks, largest %20lu bytes)\n"
                        "\t%20lu bytes free (%20s blocks, largest %20s bytes)\n"
                        "\t%20lu errors detected\n"
                        , alloc_tot, alloc_cnt, alloc_big, orig_data_max-alloc_tot, "-", "-", 0UL /* no err if we got here */ ) );

  }

done:
  if( FD_LIKELY( restore ) ) fd_io_buffered_istream_fini( restore );
  if( FD_LIKELY( fd!=-1  ) ) close( fd ); /* TODO: Consider trapping (but we might be in a dprintf err) */
  return ret;

io_err:
  if( err<0 ) TRAP( dprintf( out, "\tFAIL: io: %s (unexpected end of file)\n", err_info ) );
  else        TRAP( dprintf( out, "\tFAIL: io: %s (%i-%s)\n", err_info, err, fd_io_strerror( err ) ) );
  goto done;

stream_err:
  TRAP( dprintf( fd, "\tFAIL: stream: %s\n", err_info ) );
  goto done;

# undef RESTORE_TEST
# undef TRAP
}

#undef RBUF_FOOTPRINT
#undef RBUF_ALIGN

#undef RESTORE_CSTR
#undef RESTORE_ULONG
