#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../util/sanitize/fd_fuzz.h"
#include "fd_types_reflect.h"
#include "../fd_flamenco.h"

#include "fd_fuzz_types.h"


static const char *blacklist[] = {
  "fd_pubkey",
  // fd_tower_sync_t encoding function is unimplemented
  "fd_tower_sync",
  "fd_tower_sync_switch",
};

static int
is_blacklisted( char const * type_name ) {
  if( !type_name ) return 1;

  for( ulong i=0; i < (sizeof(blacklist) / sizeof(blacklist[0])); ++i ) {
    if( strcmp( blacklist[i], type_name ) == 0 ) return 1;
  }
  return 0;
}

static int
encode_type( fd_types_vt_t const * type_meta,
             void *                from,
             void *                to,
             size_t const          capacity,
             size_t *              written ) {
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = to,
    .dataend = (void *) ((ulong) to + capacity),
  };
  int err = type_meta->encode( from, &encode_ctx );

  *written = (size_t) encode_ctx.data - (size_t)to;
  return err;
}

static int
decode_type( fd_types_vt_t const * type_meta,
             void const *          from,
             void **               to,
             size_t const          capacity,
             size_t *              written ) {
  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = from,
    .dataend = (void *) ((ulong) from + capacity),
  };

  ulong total_sz = 0UL;
  int   err      = type_meta->decode_footprint( &decode_ctx, &total_sz );
  if (err != FD_BINCODE_SUCCESS) {
    return err;
  }

  *written = total_sz;

  if( FD_UNLIKELY( !fd_scratch_alloc_is_safe( type_meta->align, total_sz ) ) ) {
    return -1004;
  }
  void * decoded = fd_scratch_alloc( type_meta->align, total_sz );

  *to = type_meta->decode( decoded, &decode_ctx );

  return FD_BINCODE_SUCCESS;
}

static inline void
fd_scratch_detach_null( void ) {
  fd_scratch_detach( NULL );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );

  static uchar scratch_mem [ 1UL<<30 ];  /* 1 GB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<30, 4UL );

  atexit( fd_halt );
  atexit( fd_scratch_detach_null );
  return 0;
}

static void
fd_decode_fuzz_data( fd_types_vt_t const * type_meta,
                     uchar const *         data,
                     ulong                 size ) {


  FD_SCRATCH_SCOPE_BEGIN {

    void * decoded = NULL;
    ulong  written = 0UL;
    int err = decode_type( type_meta, data, &decoded, size, &written );
    if( err != FD_BINCODE_SUCCESS ) {
      return;
    }

    char const * type_name = type_meta->name;
    void * encoded_buffer = fd_scratch_alloc( 1, 100000 );
    err = encode_type( type_meta, decoded, encoded_buffer, 100000, &written );
    if ( err != FD_BINCODE_SUCCESS ) {
      FD_LOG_CRIT(( "encoding failed for: %s (err: %d)", type_name, err ));
    }

    void * decoded_normalized = NULL;
    ulong  written_normalized = 0UL;
    int err_normalized = decode_type( type_meta, encoded_buffer, &decoded_normalized, written, &written_normalized );
    if( err_normalized != FD_BINCODE_SUCCESS ) {
      return;
    }

    void * encoded_buffer_normalized = fd_scratch_alloc( 1, 50000 );

    err = encode_type( type_meta, decoded_normalized, encoded_buffer_normalized, 50000, &written_normalized );
    if ( err != FD_BINCODE_SUCCESS ) {
      FD_LOG_CRIT(( "encoding failed for: %s (err: %d)", type_name, err ));
    }

    if( written_normalized > written ) {
      FD_LOG_HEXDUMP_WARNING(( "normalized data", encoded_buffer, written ));
      FD_LOG_HEXDUMP_WARNING(( "encoded", encoded_buffer_normalized, written_normalized ));
      FD_LOG_CRIT(( "encoded size (%lu) > data size (%lu) after decode-encode for: %s", written_normalized, written, type_name ));
    }
    if( memcmp( encoded_buffer, encoded_buffer_normalized, written ) != 0 ) {
      FD_LOG_HEXDUMP_WARNING(( "normalized data", encoded_buffer, written ));
      FD_LOG_HEXDUMP_WARNING(( "encoded", encoded_buffer_normalized, written ));
      FD_LOG_CRIT(( "encoded data differs from the original data after decode-encode for: %s", type_name ));
    }

  } FD_SCRATCH_SCOPE_END;

}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  if( FD_UNLIKELY( size == 0 ) ) return 0;

  assert( fd_types_vt_list_cnt < 256 );
  if( FD_UNLIKELY( data[0]>=fd_types_vt_list_cnt ) ) return -1;
  fd_types_vt_t const * type_meta = &fd_types_vt_list[ data[0] ];
  data = data + 1;
  size = size - 1;

  /* fd_pubkey is a #define alias for fd_hash.  It is therefore already
     fuzzed. Furthermore, dlsym will not be able to find a #define. */
  if( FD_UNLIKELY( 0==strcmp( type_meta->name, "fd_pubkey" ) ) ) {
    return -1;
  } else if( strcmp( "fd_vote_instruction", type_meta->name ) == 0 && size >= sizeof(uint) ) {
    uint discriminant = *(uint *)data;
    if (discriminant == 14 || discriminant == 15) {
      return -1;
    }
  }

  if( is_blacklisted( type_meta->name ) ) {
    return -1;
  }

  fd_decode_fuzz_data( type_meta, data, size );

  return 0;
}

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   size,
                         ulong   max_size,
                         uint    seed ) {

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  int use_generate = fd_rng_uchar( rng ) % 2 == 0;

  fd_types_vt_t const * type_meta;
  if( !use_generate ) {

    ulong mutated_size = LLVMFuzzerMutate( data, size, max_size );
    data[0] %= (uchar)fd_types_vt_list_cnt;
    type_meta = &fd_types_vt_list[ data[0] ];

    // dont bother bruteforcing replace with a structured input
    int use_generate = is_blacklisted( type_meta->name );
    if( strcmp( "fd_vote_instruction", type_meta->name ) == 0 ) {
      uint discriminant = *(uint *)(data+1);
      use_generate = (discriminant == 14 || discriminant == 15) ? 1 : 0;
    }

    if( !use_generate ) return mutated_size;
  }

  // generate inputs
  void *(*generate_fun)(void *, void **, fd_rng_t *) = NULL;

  // lookup callbacks
  do {
    generate_fun = NULL;

    data[0] = (uchar)( (uchar)fd_rng_uchar( rng ) % (uchar)fd_types_vt_list_cnt );
    type_meta = &fd_types_vt_list[ data[0] ];
    if( is_blacklisted( type_meta->name ) ) continue;

    char fp[255];
    sprintf( fp, "%s_generate", type_meta->name );
    generate_fun = (void *(*)(void *, void **, fd_rng_t *))(ulong)dlsym( RTLD_DEFAULT, fp );

  } while ( !generate_fun || !type_meta->encode );

  FD_SCRATCH_SCOPE_BEGIN {

    void * smem = fd_scratch_alloc( 1, 16384 );
    void * mem = smem;

    // generate and encode the payload
    void * type = generate_fun( mem, &mem, rng );

    size_t written;
    int err = encode_type( type_meta, type, data + 1, max_size - 1, &written );
    if( err != FD_BINCODE_SUCCESS ) {
      if( err == FD_BINCODE_ERR_OVERFLOW ) {
        FD_LOG_DEBUG(( "encoding failed for: %s (err: %d)", type_meta->name, err ));
        // This type is just too large to fit in the max_size (4095 byte) buffer
        return 0;
      }
      FD_LOG_CRIT(( "encoding failed for: %s (err: %d)", type_meta->name, err ));
    }
    size = written;

  } FD_SCRATCH_SCOPE_END;

  return size;
}
