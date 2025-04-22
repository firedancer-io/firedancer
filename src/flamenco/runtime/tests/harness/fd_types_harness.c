#include "fd_types_harness.h"
#include "../../../types/fd_type_names.c"

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
      if( arg==NULL ) {
        fprintf( file, "," );
      } else {
        fprintf( file, "'%s',", (char const *)arg );
      }
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

static int
fd_runtime_fuzz_decode_type_run( fd_runtime_fuzz_runner_t * runner,
                                 uchar const *              input,
                                 ulong                      input_sz,
                                 uchar *                    output,
                                 ulong *                    output_sz ) {

  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    if( input_sz < 1 ) {
      *output_sz = 0;
      return 0;
    }

    // First byte is the type ID
    uchar type_id = input[0];
    if( type_id >= FD_TYPE_NAME_COUNT ) {
      FD_LOG_WARNING(( "Invalid type ID: %d", type_id ));
      *output_sz = 0;
      return 0;
    }

    // Get the type name from the type ID
    char const * type_name = fd_type_names[type_id];

    // Look up the type functions
    fd_types_funcs_t type_meta;
    if( fd_flamenco_type_lookup( type_name, &type_meta ) == -1 ) {
      FD_LOG_ERR(( "Failed to lookup type %s (%d)", type_name, type_id ));
      *output_sz = 0;
      return 0;
    }

    // Set up decode context
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = input + 1,
      .dataend = (void *)( (ulong)input + input_sz ),
    };

    // Get the size needed for the decoded object
    ulong total_sz = 0UL;
    int err = type_meta.decode_footprint_fun( &decode_ctx, &total_sz );
    if( err != FD_BINCODE_SUCCESS ) {
      *output_sz = 0;
      return 0;
    }

    // Allocate memory for the decoded object
    void * decoded = fd_spad_alloc( runner->spad, 1UL, total_sz );
    if( !decoded ) {
      *output_sz = 0;
      return 0;
    }

    // Decode the object
    void* result = type_meta.decode_fun(decoded, &decode_ctx);
    if (result == NULL) {
      *output_sz = 0;
      return 0;
    }

    // Output buffer structure:
    // - serialized_sz (ulong)
    // - serialized data (bytes)
    // - yaml data (bytes)

    uchar * output_ptr = output;
    ulong remaining_sz = *output_sz;

    // Skip serialized_sz for now (we'll write it after serialization)
    uchar * serialized_sz_ptr = output_ptr;
    output_ptr += sizeof(ulong);
    remaining_sz -= sizeof(ulong);

    // Serialize the memory representation
    uchar * serialized_data_ptr = output_ptr;
    FILE * file = fmemopen( serialized_data_ptr, remaining_sz, "w" );
    if( !file ) {
      *output_sz = 0;
      return 0;
    }

    CustomerSerializer serializer = {
      .file = file,
    };

    // Walk the decoded object and serialize it
    type_meta.walk_fun( &serializer, decoded, custom_serializer_walk, type_name, 0 );
    if( ferror( file ) ) {
      fclose( file );
      *output_sz = 0;
      return 0;
    }
    long serialized_sz = ftell( file );
    fclose( file );

    // Write serialized_sz
    *(ulong *)serialized_sz_ptr = (ulong)serialized_sz;

    // Update output_ptr and remaining_sz
    output_ptr += serialized_sz;
    remaining_sz -= (ulong)serialized_sz;

    // Generate YAML representation
    uchar * yaml_data_ptr = output_ptr;
    file = fmemopen( yaml_data_ptr, remaining_sz, "w" );
    if( !file ) {
      *output_sz = 0;
      return 0;
    }

    void * yaml_mem = fd_spad_alloc( runner->spad, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() );
    fd_flamenco_yaml_t * yaml = fd_flamenco_yaml_init( fd_flamenco_yaml_new( yaml_mem ), file );

    // Walk the decoded object and generate YAML
    type_meta.walk_fun( yaml, decoded, fd_flamenco_yaml_walk, type_name, 0 );
    if( ferror( file ) ) {
      fclose( file );
      *output_sz = 0;
      return 0;
    }

    long yaml_sz = ftell( file );
    fclose( file );

    // Update output_ptr and remaining_sz
    output_ptr += yaml_sz;
    remaining_sz -= (ulong)yaml_sz;

    // Calculate total size
    *output_sz = (ulong)(output_ptr - output);
    return 1;
  } FD_SPAD_FRAME_END;

  *output_sz = 0;
  return 0;
}

ulong
fd_runtime_fuzz_type_run( fd_runtime_fuzz_runner_t * runner,
                          void const *               input_,
                          void **                    output_,
                          void *                     output_buf,
                          ulong                      output_bufsz ) {
  fd_exec_test_type_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_type_effects_t **      output = fd_type_pun( output_ );

  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT(l, output_buf);

  fd_exec_test_type_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND(l, alignof(fd_exec_test_type_effects_t),
                            sizeof(fd_exec_test_type_effects_t));
  if (FD_UNLIKELY(_l > output_end)) {
    return 0UL;
  }

  if( input == NULL || input->content == NULL ) {
    return 0UL;
  }

  if(input->content->size == 0) {
    return 0UL;
  }

  // Initialize effects
  effects->result = 0;
  effects->representation = NULL;
  effects->yaml = NULL;

  // Decode the type
  ulong   max_content_size = output_bufsz - (_l - (ulong)output_buf);
  uchar * temp_buffer = (uchar *)_l;
  if (FD_UNLIKELY(_l > output_end)) {
    return 0UL;
  }

  ulong decoded_sz = max_content_size;
  int success = fd_runtime_fuzz_decode_type_run( runner,
                                                 input->content->bytes,
                                                 input->content->size,
                                                 temp_buffer,
                                                 &decoded_sz);

  if (!success || decoded_sz == 0) {
    effects->result = 1;
  } else {
    effects->result = 0;

    // The decoded data contains:
    // - serialized_sz (ulong)
    // - serialized data (bytes)
    // - yaml data (bytes)

    // Extract serialized_sz
    ulong serialized_sz = *(ulong*)temp_buffer;

    // Allocate and copy the representation (serialized data)
    effects->representation = FD_SCRATCH_ALLOC_APPEND(l, alignof(pb_bytes_array_t),
                                                    PB_BYTES_ARRAY_T_ALLOCSIZE(serialized_sz));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }
    effects->representation->size = (pb_size_t)serialized_sz;
    fd_memcpy(effects->representation->bytes, temp_buffer + sizeof(ulong), serialized_sz);

    // Allocate and copy the yaml data
    ulong yaml_sz = decoded_sz - sizeof(ulong) - serialized_sz;
    effects->yaml = FD_SCRATCH_ALLOC_APPEND(l, alignof(pb_bytes_array_t),
                                          PB_BYTES_ARRAY_T_ALLOCSIZE(yaml_sz));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }
    effects->yaml->size = (pb_size_t)yaml_sz;
    fd_memcpy(effects->yaml->bytes, temp_buffer + sizeof(ulong) + serialized_sz, yaml_sz);
  }

  ulong actual_end = FD_SCRATCH_ALLOC_FINI(l, 1UL);
  *output = effects;
  return actual_end - (ulong)output_buf;
}
