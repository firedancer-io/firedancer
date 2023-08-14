#include "../fd_util.h"

#if FD_HAS_HOSTED

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

FD_IMPORT_CSTR( fd_pod_ctl_help, "src/util/pod/fd_pod_ctl_help" );

static int
supported_val_type( int val_type ) {
  return (val_type==FD_POD_VAL_TYPE_CSTR  ) | (val_type==FD_POD_VAL_TYPE_CHAR  )
       | (val_type==FD_POD_VAL_TYPE_SCHAR ) | (val_type==FD_POD_VAL_TYPE_SHORT )
       | (val_type==FD_POD_VAL_TYPE_INT   ) | (val_type==FD_POD_VAL_TYPE_LONG  )
       | (val_type==FD_POD_VAL_TYPE_UCHAR ) | (val_type==FD_POD_VAL_TYPE_USHORT)
       | (val_type==FD_POD_VAL_TYPE_UINT  ) | (val_type==FD_POD_VAL_TYPE_ULONG )
       | (val_type==FD_POD_VAL_TYPE_FLOAT )
#      if FD_HAS_DOUBLE
       | (val_type==FD_POD_VAL_TYPE_DOUBLE)
#      endif
  ;
}

static ulong
insert_val( uchar *      pod,
            char const * path,
            int          val_type,
            char const * val ) {
  ulong off;
  switch( val_type ) {
  case FD_POD_VAL_TYPE_CSTR:   off = fd_pod_insert_cstr  ( pod, path, fd_cstr_to_cstr  ( val ) ); break;
  case FD_POD_VAL_TYPE_CHAR:   off = fd_pod_insert_char  ( pod, path, fd_cstr_to_char  ( val ) ); break;
  case FD_POD_VAL_TYPE_SCHAR:  off = fd_pod_insert_schar ( pod, path, fd_cstr_to_schar ( val ) ); break;
  case FD_POD_VAL_TYPE_SHORT:  off = fd_pod_insert_short ( pod, path, fd_cstr_to_short ( val ) ); break;
  case FD_POD_VAL_TYPE_INT:    off = fd_pod_insert_int   ( pod, path, fd_cstr_to_int   ( val ) ); break;
  case FD_POD_VAL_TYPE_LONG:   off = fd_pod_insert_long  ( pod, path, fd_cstr_to_long  ( val ) ); break;
  case FD_POD_VAL_TYPE_UCHAR:  off = fd_pod_insert_uchar ( pod, path, fd_cstr_to_uchar ( val ) ); break;
  case FD_POD_VAL_TYPE_USHORT: off = fd_pod_insert_ushort( pod, path, fd_cstr_to_ushort( val ) ); break;
  case FD_POD_VAL_TYPE_UINT:   off = fd_pod_insert_uint  ( pod, path, fd_cstr_to_uint  ( val ) ); break;
  case FD_POD_VAL_TYPE_ULONG:  off = fd_pod_insert_ulong ( pod, path, fd_cstr_to_ulong ( val ) ); break;
  case FD_POD_VAL_TYPE_FLOAT:  off = fd_pod_insert_float ( pod, path, fd_cstr_to_float ( val ) ); break;
# if FD_HAS_DOUBLE
  case FD_POD_VAL_TYPE_DOUBLE: off = fd_pod_insert_double( pod, path, fd_cstr_to_double( val ) ); break;
# endif
  default: FD_LOG_ERR(( "never get here" ));
  }
  return off;
}

static inline int
issingleprint( int c ) {
  return isalnum( c ) | ispunct( c ) | (c==' ');
}

static void
printf_path( fd_pod_info_t const * info ) {
  if( FD_UNLIKELY( !info ) ) return;

  fd_pod_info_t const * node = info;
  ulong                 sz   = 0UL;
  do {
    ulong key_sz = node->key_sz;
    if( FD_UNLIKELY( !key_sz ) ) return;
    sz   += key_sz;
    node  = node->parent;
  } while( node );

  char * buf = malloc( sz );
  if( !buf ) return;

  char * p      = buf + sz;
  int    subpod = 0;
  node = info;
  do {
    ulong key_sz = node->key_sz;
    p -= key_sz;
    strcpy( p, node->key );
    if( subpod ) p[ key_sz-1UL ] = '.';
    subpod = 1;
    node = node->parent;
  } while( node );

  printf( "%s", buf );
  free( buf );
}

static void
printf_val( fd_pod_info_t const * info ) {
  switch( info->val_type ) {

  case FD_POD_VAL_TYPE_SUBPOD: {
    uchar * subpod = (uchar *)info->val;
    printf( "max %lu bytes, used %lu bytes, kcnt %lu keys", fd_pod_max( subpod ), fd_pod_used( subpod ), fd_pod_cnt( subpod ) );
    break;
  }

  default:
  case FD_POD_VAL_TYPE_BUF: {
    uchar const * buf = (uchar const *)info->val;
    ulong         sz  = info->val_sz;
    printf( "sz %lu", sz );
    for( ulong off=0UL; off<sz; off++ ) {
      ulong col = off & 15UL;
      /* FIXME: USER SPECIFIED INDENT AND CONFIGURE OFF WIDTH BASED ON SZ */
      if( FD_UNLIKELY( col==0UL ) ) printf( "\n\t\t%04lx: ", off );
      if( FD_UNLIKELY( col==8UL ) ) putc( ' ', stdout );
      printf( "%02x ", (uint)buf[ off ] );
      if( FD_UNLIKELY( (col==15UL) | ((off+1UL)==sz) ) ) { /* End of row */
        /* Output whitespace to align 2nd column */
        for( ulong rem=48UL-3UL*col; rem; rem-- ) putc( ' ', stdout );
        /* Output single character friendly bytes from row in 2nd column */
        char const * p = (char const *)(buf + (off & ~15UL));
        for( ulong rem=col+1UL; rem; rem-- ) { int c = (int)*(p++); putc( issingleprint( c ) ? c : '.', stdout ); }
      }
    }
    break;
  }

  case FD_POD_VAL_TYPE_CSTR: {
    if( !info->val_sz ) printf( "(null)" );
    else                printf( "\"%s\"", (char const *)info->val );
    break;
  }

  case FD_POD_VAL_TYPE_CHAR: {
    int c = (int)*(char *)info->val;
    if( issingleprint( c ) ) printf( "'%c'", c );
    else                     printf( "0x%02x", (uint)(uchar)c );
    break;
  }

  case FD_POD_VAL_TYPE_UCHAR:  { uint  u = (uint)*(uchar *)info->val; printf( "%u", u ); break; }
  case FD_POD_VAL_TYPE_USHORT:
  case FD_POD_VAL_TYPE_UINT:
  case FD_POD_VAL_TYPE_ULONG:  { ulong u; fd_ulong_svw_dec( info->val, &u ); printf( "%lu", u ); break; }

  case FD_POD_VAL_TYPE_SCHAR:  { int   i = (int) *(schar *)info->val; printf( "%i", i ); break; }
  case FD_POD_VAL_TYPE_SHORT:
  case FD_POD_VAL_TYPE_INT: 
  case FD_POD_VAL_TYPE_LONG:   { ulong u; fd_ulong_svw_dec( info->val, &u ); printf( "%li", fd_long_zz_dec( u ) ); break; }

# if FD_HAS_INT128
  case FD_POD_VAL_TYPE_INT128: {
    union { ulong w[2]; uint128 u; } tmp;
    fd_ulong_svw_dec( fd_ulong_svw_dec( (uchar const *)info->val, tmp.w ), tmp.w+1 );
    tmp.u = (uint128)fd_int128_zz_dec( tmp.u ); /* FIXME: INT128 decimal pretty printer */
    printf( "0x%016lx%016lx", (ulong)(tmp.u>>64), (ulong)tmp.u );
    break;
  }

  case FD_POD_VAL_TYPE_UINT128: {
    union { ulong w[2]; uint128 u; } tmp;
    fd_ulong_svw_dec( fd_ulong_svw_dec( (uchar const *)info->val, tmp.w ), tmp.w+1 );
    /* FIXME: UINT128 decimal pretty printer */
    printf( "0x%016lx%016lx", (ulong)(tmp.u>>64), (ulong)tmp.u );
    break;
  }
# endif

  case FD_POD_VAL_TYPE_FLOAT:  { float  f = *(float  *)info->val; printf( "%.21e", (double)f ); break; }
# if FD_HAS_DOUBLE
  case FD_POD_VAL_TYPE_DOUBLE: { double f = *(double *)info->val; printf( "%.21e", f );         break; }
# endif

  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1); 

  ulong tag = 1UL;

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      fputs( fd_pod_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "tag" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      tag = fd_cstr_to_ulong( argv[0] );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, tag ));
      SHIFT(1);

    } else if( !strcmp( cmd, "new" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name =                   argv[0];
      ulong        max  = fd_cstr_to_ulong( argv[1] ); if( !max ) max = 4096UL;

      ulong align     = fd_pod_align();
      ulong footprint = fd_pod_footprint( max );

      if( FD_UNLIKELY( !footprint ) )
        FD_LOG_ERR(( "%i: %s: bad max (%lu)\n\tDo %s help for help", cnt, cmd, max, bin ));

      fd_wksp_t * wksp = fd_wksp_attach( name );
      if( FD_UNLIKELY( !wksp ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, name, bin ));

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, name, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) { /* should be impossible given fd_wksp_alloc success */
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, name, gaddr, bin ));
      }

      if( FD_UNLIKELY( !fd_pod_new( shmem, max ) ) ) {;
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_pod_new( \"%s:%lu\", %lu ) failed\n\tDo %s help for help", cnt, cmd, name, gaddr, max, bin ));
      }

      char cstr[ FD_WKSP_CSTR_MAX ];
      if( FD_UNLIKELY( !fd_wksp_cstr( wksp, gaddr, cstr ) ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_pod_cstr( \"%s:%lu\" ) failed\n\tDo %s help for help", cnt, cmd, name, gaddr, bin ));
      }

      printf( "%s\n", cstr );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, name, max ));
      SHIFT(2);

    } else if( !strcmp( cmd, "delete" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      if( FD_UNLIKELY( !fd_pod_delete( shmem ) ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      fd_wksp_free_laddr( shmem );
      fd_wksp_unmap( shmem );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, cstr ));
      SHIFT(1);

    } else if( !strcmp( cmd, "reset" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      fd_pod_reset( pod );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, cstr ));
      SHIFT(1);

    } else if( !strcmp( cmd, "list" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      fd_pod_info_t * info;
      ulong info_cnt = fd_pod_cnt_recursive( pod );
      if( FD_UNLIKELY( !info_cnt ) ) info = NULL;
      else { 
        info = (fd_pod_info_t *)aligned_alloc( alignof(fd_pod_info_t), info_cnt*sizeof(fd_pod_info_t) );
        if( FD_UNLIKELY( !info ) ) {
          fd_wksp_unmap( fd_pod_leave( pod ) );
          FD_LOG_ERR(( "%i: %s: aligned_alloc failed\n\tDo %s help for help", cnt, cmd, bin ));
        }
        if( FD_UNLIKELY( !fd_pod_list_recursive( pod, info ) ) ) {
          free( info );
          fd_wksp_unmap( fd_pod_leave( pod ) );
          FD_LOG_ERR(( "%i: %s: fd_pod_list_recursive( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
        }
      }

      printf( "pod %s\n", cstr );
      printf( "\tmax   %20lu bytes  used  %20lu bytes  avail %20lu bytes\n",
              fd_pod_max( pod ), fd_pod_used ( pod ), fd_pod_avail( pod ) );
      printf( "\tkcnt  %20lu keys   icnt  %20lu paths\n", fd_pod_cnt( pod ), info_cnt );
      for( ulong info_idx=0UL; info_idx<info_cnt; info_idx++ ) {
        fd_pod_info_t * node = &info[ info_idx ];
        char type[ FD_POD_VAL_TYPE_CSTR_MAX ]; fd_pod_val_type_to_cstr( node->val_type, type );
        printf( "\t%s %s ", cstr, type );
        printf_path( node );
        printf( " " );
        printf_val(  node );
        printf( "\n" );
      }

      if( FD_LIKELY( info ) ) free( info );
      fd_wksp_unmap( fd_pod_leave( pod ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, cstr ));
      SHIFT(1);

    } else if( !strcmp( cmd, "insert" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];
      char const * type = argv[1];
      char const * path = argv[2];
      char const * val  = argv[3];

      int val_type = fd_cstr_to_pod_val_type( type );
      if( FD_UNLIKELY( !supported_val_type( val_type ) ) )
        FD_LOG_ERR(( "%i: %s: unsupported type %s\n\tDo %s help for help", cnt, cmd, type, bin ));

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      ulong off = insert_val( pod, path, val_type, val );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      if( FD_UNLIKELY( !off ) )
        FD_LOG_ERR(( "%i: %s: fd_pod_insert_%s( \"%s\", \"%s\", \"%s\" ) failed\n\tDo %s help for help",
                     cnt, cmd, type, cstr, path, val, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s %s %s: success", cnt, cmd, cstr, type, path, val ));
      SHIFT(4);

    } else if( !strcmp( cmd, "insert-file" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];
      char const * path = argv[1];
      char const * file = argv[2];

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      int fd = open( file, O_RDONLY );
      if( FD_UNLIKELY( fd == -1 ) )
        FD_LOG_ERR(( "%i: %s: open( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, file, bin ));

      struct stat st;
      if( FD_UNLIKELY( fstat( fd, &st ) == -1 ) )
        FD_LOG_ERR(( "%i: %s: fstat( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, file, bin ));
      ulong buf_sz = (ulong)st.st_size;

      ulong off = fd_pod_alloc( pod, path, FD_POD_VAL_TYPE_BUF, buf_sz );
      if( FD_UNLIKELY( !off ) )
        FD_LOG_ERR(( "%i: %s: fd_pod_alloc( \"%s\", \"%s\", FD_POD_VAL_TYPE_BUF, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, cstr, path, buf_sz, bin ));

      if( FD_UNLIKELY( read( fd, pod + off, buf_sz )!=(long)buf_sz ) ) {
        if( FD_UNLIKELY( fd_pod_remove( pod, path ) ) )
          FD_LOG_WARNING(( "%i: %s: fd_pod_remove( \"%s\", \"%s\" ) failed; pod likely corrupt", cnt, cmd, cstr, path ));
        FD_LOG_ERR(( "%i: %s: read( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, file, bin ));
      }

      if( FD_UNLIKELY( close( fd ) ) )
        FD_LOG_WARNING(( "%i: %s: close( \"%s\" ) failed; attempting to continue", cnt, cmd, file ));

      fd_wksp_unmap( fd_pod_leave( pod ) );

      FD_LOG_NOTICE(( "%i: %s %s %s %s: success", cnt, cmd, cstr, path, file ));
      SHIFT(3);

    } else if( !strcmp( cmd, "remove" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];
      char const * path = argv[1];

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      int err = fd_pod_remove( pod, path );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s: fd_pod_remove( \"%s\", \"%s\" ) failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, cstr, path, err, fd_pod_strerror( err ), bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, cstr, path ));
      SHIFT(2);

    } else if( !strcmp( cmd, "update" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];
      char const * type = argv[1];
      char const * path = argv[2];
      char const * val  = argv[3];

      int val_type = fd_cstr_to_pod_val_type( type );
      if( FD_UNLIKELY( !supported_val_type( val_type ) ) )
        FD_LOG_ERR(( "%i: %s: unsupported type %s\n\tDo %s help for help", cnt, cmd, type, bin ));

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      fd_pod_info_t info[1];
      int err = fd_pod_query( pod, path, info );
      if( FD_UNLIKELY( !!err ) ) {
        fd_wksp_unmap( fd_pod_leave( pod ) );
        FD_LOG_ERR(( "%i: %s: no path %s to type (%i-%s) in pod %s (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, path, val_type, type, cstr, err, fd_pod_strerror( err ), bin ));
      }

      if( FD_UNLIKELY( info->val_type!=val_type ) ) {
        fd_wksp_unmap( fd_pod_leave( pod ) );
        char buf[ FD_POD_VAL_TYPE_CSTR_MAX ];
        FD_LOG_ERR(( "%i: %s: type (%i-%s) at %s %s does not match requested type (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, info->val_type, fd_pod_val_type_to_cstr( info->val_type, buf ),
                     cstr, path, val_type, type, bin ));
      }

      err = fd_pod_remove( pod, path );
      if( FD_UNLIKELY( err ) ) {
        fd_wksp_unmap( fd_pod_leave( pod ) );
        FD_LOG_ERR(( "%i: %s: fd_pod_remove( \"%s\", \"%s\" ) failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, cstr, path, err, fd_pod_strerror( err ), bin ));
      }

      ulong off = insert_val( pod, path, val_type, val );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      if( FD_UNLIKELY( !off ) )
        FD_LOG_ERR(( "%i: %s: fd_pod_insert_%s( \"%s\", \"%s\", \"%s\" ) failed\n\tDo %s help for help",
                     cnt, cmd, type, cstr, path, val, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s %s %s: success", cnt, cmd, cstr, type, path, val ));
      SHIFT(4);

    } else if( !strcmp( cmd, "set" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];
      char const * type = argv[1];
      char const * path = argv[2];
      char const * val  = argv[3];

      int val_type = fd_cstr_to_pod_val_type( type );
      if( FD_UNLIKELY( !supported_val_type( val_type ) ) )
        FD_LOG_ERR(( "%i: %s: unsupported type %s\n\tDo %s help for help", cnt, cmd, type, bin ));

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      fd_pod_info_t info[1];
      int err = fd_pod_query( pod, path, info );
      if( FD_LIKELY( !err ) ) {

        if( FD_UNLIKELY( info->val_type!=val_type ) ) {
          fd_wksp_unmap( fd_pod_leave( pod ) );
          char buf[ FD_POD_VAL_TYPE_CSTR_MAX ];
          FD_LOG_ERR(( "%i: %s: type (%i-%s) at %s %s does not match requested type (%i-%s)\n\tDo %s help for help",
                       cnt, cmd, info->val_type, fd_pod_val_type_to_cstr( info->val_type, buf ),
                       cstr, path, val_type, type, bin ));
        }

        err = fd_pod_remove( pod, path );
        if( FD_UNLIKELY( err ) ) {
          fd_wksp_unmap( fd_pod_leave( pod ) );
          FD_LOG_ERR(( "%i: %s: fd_pod_remove( \"%s\", \"%s\" ) failed (%i-%s)\n\tDo %s help for help",
                       cnt, cmd, cstr, path, err, fd_pod_strerror( err ), bin ));
        }

      } else if( FD_UNLIKELY( err!=FD_POD_ERR_RESOLVE ) ) {

        fd_wksp_unmap( fd_pod_leave( pod ) );
        FD_LOG_ERR(( "%i: %s: fd_pod_query( \"%s\", \"%s\" ) failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, cstr, path, err, fd_pod_strerror( err ), bin ));

      }

      ulong off = insert_val( pod, path, val_type, val );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      if( FD_UNLIKELY( !off ) )
        FD_LOG_ERR(( "%i: %s: fd_pod_insert_%s( \"%s\", \"%s\", \"%s\" ) failed\n\tDo %s help for help",
                     cnt, cmd, type, cstr, path, val, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s %s %s: success", cnt, cmd, cstr, type, path, val ));
      SHIFT(4);


    } else if( !strcmp( cmd, "compact" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr =                 argv[0];
      int          full = fd_cstr_to_int( argv[1] );

      void * shmem = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shmem ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));

      uchar * pod = fd_pod_join( shmem );
      if( FD_UNLIKELY( !pod ) ) {
        fd_wksp_unmap( shmem );
        FD_LOG_ERR(( "%i: %s: fd_pod_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, cstr, bin ));
      }

      ulong new_max = fd_pod_compact( pod, full );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      if( FD_UNLIKELY( !new_max ) )
        FD_LOG_ERR(( "%i: %s: fd_pod_compact( \"%s\", %i ) failed\n\tDo %s help for help", cnt, cmd, cstr, full, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, cstr, full ));
      SHIFT(2);

    } else if( !strcmp( cmd, "query-root" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * what = argv[0];
      char const * cstr = argv[1];

      void *  shmem = NULL;
      uchar * pod   = NULL;
      int     err   = FD_POD_ERR_INVAL;

      shmem = fd_wksp_map( cstr );
      if( FD_LIKELY( shmem ) ) {
        pod = fd_pod_join( shmem );
        if( FD_LIKELY( pod ) ) err = 0;
      }

      if(      !strcmp( what, "test"       ) ) printf( "%i\n",  err );
      else if( !strcmp( what, "max"        ) ) printf( "%lu\n", FD_LIKELY(!err) ? fd_pod_max          ( pod ) : 0UL );
      else if( !strcmp( what, "used"       ) ) printf( "%lu\n", FD_LIKELY(!err) ? fd_pod_used         ( pod ) : 0UL );
      else if( !strcmp( what, "avail"      ) ) printf( "%lu\n", FD_LIKELY(!err) ? fd_pod_avail        ( pod ) : 0UL );
      else if( !strcmp( what, "cnt"        ) ) printf( "%lu\n", FD_LIKELY(!err) ? fd_pod_cnt          ( pod ) : 0UL );
      else if( !strcmp( what, "recursive"  ) ) printf( "%lu\n", FD_LIKELY(!err) ? fd_pod_cnt_recursive( pod ) : 0UL );
      else if( !strcmp( what, "subpod-cnt" ) ) printf( "%lu\n", FD_LIKELY(!err) ? fd_pod_cnt_subpod   ( pod ) : 0UL );
      else                                     FD_LOG_ERR(( "unknown query %s", what ));

      if( FD_LIKELY( pod   ) ) fd_pod_leave( pod );
      if( FD_LIKELY( shmem ) ) fd_wksp_unmap( shmem );
      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, what, cstr ));
      SHIFT(2);

    } else if( !strcmp( cmd, "query" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * what = argv[0];
      char const * cstr = argv[1];
      char const * path = argv[2];

      void *        shmem = NULL;
      uchar *       pod   = NULL;
      int           err   = FD_POD_ERR_INVAL;
      fd_pod_info_t info[1];
      char          type[ FD_POD_VAL_TYPE_CSTR_MAX ];
      int           is_subpod = 0;

      shmem = fd_wksp_map( cstr );
      if( FD_LIKELY( shmem ) ) {
        pod = fd_pod_join( shmem );
        if( FD_LIKELY( pod ) ) {
          err = fd_pod_query( pod, path, info );
          if( FD_LIKELY( !err ) ) {
            is_subpod = (info->val_type==FD_POD_VAL_TYPE_SUBPOD);
            if( FD_UNLIKELY( !fd_pod_val_type_to_cstr( info->val_type, type ) ) ) { /* only possible if corruption */
              err = FD_POD_ERR_INVAL;
            }
          }
        }
      }

      if(      !strcmp( what, "test"       ) ) printf( "%i\n",  err );
      else if( !strcmp( what, "type"       ) ) printf( "%s\n",  FD_LIKELY( !err )      ? type : "void" );
      else if( !strcmp( what, "val"        ) ) {
        if( FD_UNLIKELY( err ) ) printf( "void\n" );
        else {
          printf_val( info );
          printf( "\n" );
        }
      }
      else if( !strcmp( what, "max"        ) ) printf( "%lu\n", FD_LIKELY( is_subpod ) ? fd_pod_max          ( info->val ) : 0UL );
      else if( !strcmp( what, "used"       ) ) printf( "%lu\n", FD_LIKELY( is_subpod ) ? fd_pod_used         ( info->val ) : 0UL );
      else if( !strcmp( what, "avail"      ) ) printf( "%lu\n", FD_LIKELY( is_subpod ) ? fd_pod_avail        ( info->val ) : 0UL );
      else if( !strcmp( what, "cnt"        ) ) printf( "%lu\n", FD_LIKELY( is_subpod ) ? fd_pod_cnt          ( info->val ) : 0UL );
      else if( !strcmp( what, "recursive"  ) ) printf( "%lu\n", FD_LIKELY( is_subpod ) ? fd_pod_cnt_recursive( info->val ) : 0UL );
      else if( !strcmp( what, "subpod-cnt" ) ) printf( "%lu\n", FD_LIKELY( is_subpod ) ? fd_pod_cnt_subpod   ( info->val ) : 0UL );
      else if( !strcmp( what, "gaddr" ) ) {
        char buf[ FD_WKSP_CSTR_MAX ];
        printf( "%s\n", (FD_LIKELY( !err ) && FD_LIKELY( fd_wksp_cstr_laddr( info->val, buf ) )) ? buf : "null" );
      }
      else if( !strcmp( what, "full"         ) ) {
        if( FD_UNLIKELY( err ) ) printf( "%s void %s void\n", cstr, path );
        else {
          printf( "%s %s %s ", cstr, type, path );
          printf_val( info );
          printf( "\n" );
        }
      }
      else                                       FD_LOG_ERR(( "unknown query %s", what ));

      if( FD_LIKELY( pod   ) ) fd_pod_leave( pod );
      if( FD_LIKELY( shmem ) ) fd_wksp_unmap( shmem );
      FD_LOG_NOTICE(( "%i: %s %s %s %s: success", cnt, cmd, what, cstr, path ));
      SHIFT(3);

    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  if( FD_UNLIKELY( cnt<1 ) ) FD_LOG_NOTICE(( "processed %i commands\n\tDo %s help for help", cnt, bin ));
  else                       FD_LOG_NOTICE(( "processed %i commands", cnt ));

# undef SHIFT
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "No arguments" ));
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_pod_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif

