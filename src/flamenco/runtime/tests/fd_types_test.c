#include "fd_types_test.h"
#include "../../types/fd_type_names.c"

static int
fd_flamenco_type_lookup( char const *       type,
                         fd_types_funcs_t * t ) {
  char fp[255];

#pragma GCC diagnostic ignored "-Wpedantic"
  sprintf( fp, "%s_footprint", type );
  t->footprint_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_align", type );
  t->align_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_new", type );
  t->new_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_decode_footprint", type );
  t->decode_footprint_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_decode", type );
  t->decode_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_walk", type );
  t->walk_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_encode", type );
  t->encode_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_destroy", type );
  t->destroy_fun = dlsym( RTLD_DEFAULT, fp );

  sprintf( fp, "%s_size", type );
  t->size_fun = dlsym( RTLD_DEFAULT, fp );

  if(( t->footprint_fun == NULL ) ||
     ( t->align_fun == NULL ) ||
     ( t->new_fun == NULL ) ||
     ( t->decode_footprint_fun == NULL ) ||
     ( t->decode_fun == NULL ) ||
     ( t->walk_fun == NULL ) ||
     ( t->encode_fun == NULL ) ||
     ( t->destroy_fun == NULL ) ||
     ( t->size_fun == NULL ))
    return -1;
  return 0;
}

struct CustomerSerializer {
  void * file;
};
typedef struct CustomerSerializer CustomerSerializer;

void
custom_serializer_walk( void *       _self,
                        void const * arg,
                        char const * name,
                        int          type,
                        char const * type_name,
                        uint         level ) {
  (void)name;
  (void)type;
  (void)type_name;
  (void)level;

  CustomerSerializer * self = (CustomerSerializer *)_self;
  FILE * file = self->file;

  switch( type ) {
    case FD_FLAMENCO_TYPE_MAP:
    case FD_FLAMENCO_TYPE_MAP_END:
    case FD_FLAMENCO_TYPE_ENUM:
    case FD_FLAMENCO_TYPE_ENUM_END:
    case FD_FLAMENCO_TYPE_ARR:
    case FD_FLAMENCO_TYPE_ARR_END:
      break;
    case FD_FLAMENCO_TYPE_NULL:
      fprintf( file, "null," );
      break;
    case FD_FLAMENCO_TYPE_BOOL:
      fprintf( file, "%s,", (*(uchar const *)arg) ? "true" : "false" );
      break;
    case FD_FLAMENCO_TYPE_UCHAR:
      if (arg) fprintf( file, "%u,", *(uchar const *)arg );
      break;
    case FD_FLAMENCO_TYPE_SCHAR:
      fprintf( file, "%d,", *(schar const *)arg );
      break;
    case FD_FLAMENCO_TYPE_USHORT:
      fprintf( file, "%u,", *(ushort const *)arg );
      break;
    case FD_FLAMENCO_TYPE_SSHORT:
      fprintf( file, "%d,", *(short const *)arg );
      break;
    case FD_FLAMENCO_TYPE_UINT:
      fprintf( file, "%u,", *(uint const *)arg );
      break;
    case FD_FLAMENCO_TYPE_SINT:
      fprintf( file, "%d,", *(int const *)arg );
      break;
    case FD_FLAMENCO_TYPE_ULONG:
      fprintf( file, "%lu,", *(ulong const *)arg );
      break;
    case FD_FLAMENCO_TYPE_SLONG:
      fprintf( file, "%ld,", *(long const *)arg );
      break;
  # if FD_HAS_INT128
    case FD_FLAMENCO_TYPE_UINT128:
    case FD_FLAMENCO_TYPE_SINT128: {
      uint128 v = *(uint128 const *)arg;
      // fprintf( file, "%s: 0x%016lx%016lx\n", name,
      //           (ulong)(v>>64), (ulong)v );
      if( v <= ULONG_MAX ) {
        fprintf( file, "%lu,", (ulong)v );
      } else {
        char str[40] = {0};
        char *p = str + sizeof(str) - 1;

        if( v == 0 ) {
            *--p = '0';
        } else {
            while( v != 0 ) {
                *--p = (char)('0' + (int)( v % 10 ));
                v /= 10;
            }
        }
        fprintf( file, "%s,", p );
      }
      break;
    }
  # endif
    case FD_FLAMENCO_TYPE_FLOAT: {
      double f = (double)( *(float const *)arg );
      for( ulong i=0; i < sizeof(f); ++i ) {
        fprintf( file, "0x%02X,", ((uchar *)&f)[i] );
      }
      break;
    }
    case FD_FLAMENCO_TYPE_DOUBLE: {
      double f = *(double const *)arg;
      for( ulong i=0; i < sizeof(f); ++i ) {
        fprintf( file, "0x%02X,", ((uchar *)&f)[i] );
      }
      break;
    }
    case FD_FLAMENCO_TYPE_HASH256: {
      for( ulong i=0; i < 32; ++i ) {
        fprintf( file, "%u,", ((uchar *)arg)[i] );
      }
      break;
    }
    case FD_FLAMENCO_TYPE_HASH1024:
      for( ulong i=0; i < 128; ++i ) {
        fprintf( file, "%u,", ((uchar *)arg)[i] );
      }
      break;
    case FD_FLAMENCO_TYPE_HASH16384:
      for( ulong i=0; i < 2048; ++i ) {
        fprintf( file, "%u,", ((uchar *)arg)[i] );
      }
      break;
    case FD_FLAMENCO_TYPE_SIG512: {
      for( ulong i=0; i < 64; ++i ) {
        fprintf( file, "%u,", ((uchar *)arg)[i] );
      }
      break;
    }
    case FD_FLAMENCO_TYPE_CSTR:
      fprintf( file, "'%s',", (char const *)arg );
      break;
    case FD_FLAMENCO_TYPE_ENUM_DISC: {
      char lowercase_variant[128];
      memset(lowercase_variant, 0, 128);

      for( ulong i=0; name[i]; ++i ) {
        lowercase_variant[i] = (char) tolower(name[i]);
      }
      fprintf( file, "'%s',", lowercase_variant );
      break;
    }
    default:
      FD_LOG_CRIT(( "unknown type %#x", (uint)type ));
      break;
    }
}

int
sol_compat_decode_type( fd_spad_t *   spad,
                        uchar const * input,
                        ulong         input_sz,
                        uchar *       output,
                        ulong *       output_sz ) {

  char const * type_name = fd_type_names[input[0] % FD_TYPE_NAME_COUNT];

  fd_types_funcs_t type_meta;
  if( fd_flamenco_type_lookup( type_name, &type_meta ) != 0 ) {
    fprintf(stderr,  "Failed to lookup type %s (%d)", type_name, input[0]);
    FD_LOG_ERR (( "Failed to lookup type %s", type_name ));
  }

  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = input + 1,
    .dataend = (void *) ( (ulong) input + input_sz ),
  };

  ulong total_sz = 0UL;
  int   err      = type_meta.decode_footprint_fun( &decode_ctx, &total_sz );
  __asm__ volatile( "" : "+m,r"(err) : : "memory" ); /* prevent optimization */

  if (err != FD_BINCODE_SUCCESS) {
    return 0;
  }

  void * decoded = fd_spad_alloc( spad, 1UL, total_sz );
  FD_TEST( total_sz <= fd_spad_alloc_max( spad, 1UL ) );
  type_meta.decode_fun( decoded, &decode_ctx );

  // Serialize the memory representation
  ulong rem_sz = *output_sz - sizeof(ulong);
  FILE * file = fmemopen( output+sizeof(ulong), rem_sz, "w" );
  CustomerSerializer serializer = {
    .file = file,
  };

  type_meta.walk_fun( &serializer, decoded, custom_serializer_walk, type_name, 0 );
  FD_TEST( 0==ferror( file ) );
  long serialized_sz = ftell(  file );
  FD_TEST( 0==fclose( file ) );

  *(ulong *)output = (ulong)serialized_sz;
  rem_sz -= (ulong) serialized_sz;

  // YAML for debugging
  file = fmemopen( output + sizeof(ulong) + serialized_sz, rem_sz, "w" );

  void * yaml_mem = fd_spad_alloc( spad, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
  fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

  type_meta.walk_fun( yaml, decoded, fd_flamenco_yaml_walk, type_name, 0 );
  FD_TEST( 0==ferror( file ) );
  long yaml_sz = ftell(  file );
  FD_TEST( yaml_sz>0 );
  FD_TEST( 0==fclose( file ) );

  *output_sz = sizeof(ulong) + (ulong) serialized_sz + (ulong) yaml_sz;

  return 1;
}