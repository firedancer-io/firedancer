#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sol_compat_harness_ctx.h"
#include "../../nanopb/pb_decode.h"
#include "generated/metadata.pb.h"
#include "../../../util/fd_util.h"

/* Fixture executor that dynamically determines
   which sol_compat harness to execute based on
   fixture metadata. */

static void * sol_compat_handle = NULL;

#define METADATA_TAG 1

typedef void (*sol_compat_init_fn_t)(int log_lvl);
typedef void (*sol_compat_fini_fn_t)(void);
typedef int  (*sol_compat_protobuf_call_v1)(uint8_t *out, uint64_t *out_sz,
                                            uint8_t const *in, uint64_t in_sz);


/* CSV iterator code. This should probably go in utils */
typedef struct {
    char *input_str;     // The input comma-separated string
    char *current_pos;   // The current position in the string
    char delimiter;      // Delimiter (space in this case)
} csv_iter_t;

csv_iter_t* filepath_iter = NULL;

csv_iter_t* csv_iter_init(const char* input_str, char delimiter) {
    // Allocate memory for the iterator
    csv_iter_t* iterator = (csv_iter_t*)malloc(sizeof(csv_iter_t));
    if (!iterator) {
        return NULL; // Memory allocation failed
    }

    // Duplicate the input string so we can modify it safely
    iterator->input_str = strdup(input_str); // need to free this later
    iterator->current_pos = iterator->input_str;
    iterator->delimiter = delimiter;

    return iterator;
}

char* csv_iter_next(csv_iter_t* iterator) {
    if (!iterator->current_pos || *iterator->current_pos == '\0') {
        return NULL; // No more values
    }

    // Find the next delimiter (or the end of the string)
    char* next_delim = strchr(iterator->current_pos, iterator->delimiter);

    // If no more delimiters, return the remaining part of the string
    if (!next_delim) {
        char* value = iterator->current_pos;
        iterator->current_pos = NULL; // Mark the end of iteration
        return value;
    }

    // Null-terminate the current filepath
    *next_delim = '\0';
    char* value = iterator->current_pos;

    // Move the current position to the next filepath (past the delimiter)
    iterator->current_pos = next_delim + 1;

    return value;
}

void csv_iter_free(csv_iter_t* iterator) {
    if (iterator) {
        free(iterator->input_str); // Free the duplicated string
        free(iterator); // Free the iterator
    }
}

int
setup( int argc, char ** argv ) {
  if( FD_UNLIKELY( argc==1 ) ) {
      return 1;
  }

  fd_boot( &argc, &argv );

  char const * sol_compat_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--target-path", "TARGET_PATH", NULL );
  char const * fixture_paths = fd_env_strip_cmdline_cstr( &argc, &argv, "--fixture-paths", NULL, NULL );
  if( sol_compat_path == NULL ) {
    FD_LOG_ERR(( "No target path specified" ));
    return 1;
  }

  if( fixture_paths == NULL ) {
    FD_LOG_ERR(( "No fixture paths specified" ));
    return 1;
  }

  /* FIXME: Can we statically link fd_exec_sol_compat and use `dlopen(0, RTLD_LAZY)` instead? */
  sol_compat_handle = dlopen( sol_compat_path, RTLD_LAZY );
  if( sol_compat_handle == NULL ) {
    FD_LOG_ERR(( "Failed to open sol_compat shared library: %s", dlerror() ));
    return 1;
  }

  sol_compat_init_fn_t sol_compat_init_fn = (sol_compat_init_fn_t)dlsym( sol_compat_handle, "sol_compat_init" );

  if( sol_compat_init_fn == NULL ) {
    FD_LOG_ERR(( "Failed to find sol_compat_init function: %s", dlerror() ));
    return 1;
  }

  sol_compat_init_fn( 5 );
  filepath_iter = csv_iter_init(fixture_paths, ' ');

  return 0;
}

int
teardown( void ) {
  if( sol_compat_handle ) {
    sol_compat_fini_fn_t sol_compat_fini_fn = (sol_compat_fini_fn_t)dlsym( sol_compat_handle, "sol_compat_fini" );
    if( sol_compat_fini_fn ) {
      sol_compat_fini_fn();
    }
    dlclose( sol_compat_handle );
  }

  csv_iter_free(filepath_iter);
  fd_halt();

  return 0;
}

/* On success, stream will point to start of field value.

   IIRC Protobuf doesn't make guarantees about field ordering
   based on tag number, so this means you likely need to
   reset the stream to the start of the buffer before
   calling this function. Else you might be past the field
   you want to advance to.

   For submsg fields, you can pass the stream to make_string_substream */
int
advance_stream_to_field( pb_istream_t* stream, uint32_t tag ) {
  while( stream->bytes_left ){
    uint32_t t;
    pb_wire_type_t wire_type;
    bool eof;

    if ( !pb_decode_tag( stream, &wire_type, &t, &eof ) ){
      if ( eof ){
        break;
      } else {
        FD_LOG_ERR(( "Failed to decode tag" ));
        return 1;
      }
    }
    if( t == tag ){
      return 0;
    }

    if( !pb_skip_field( stream, wire_type ) ){
      FD_LOG_ERR(( "Failed to skip field" ));
      return 1;
    }
  }
  // Field not found
  return 1;
}

int
extract_metadata( pb_istream_t* fixture_stream, fd_exec_test_fixture_metadata_t* metadata ) {
  if( advance_stream_to_field( fixture_stream, METADATA_TAG ) ){
    FD_LOG_ERR(( "Failed to advance stream to metadata tag" ));
    return 1;
  }

  pb_istream_t metadata_stream;
  if( !pb_make_string_substream( fixture_stream, &metadata_stream ) ){
    FD_LOG_ERR(( "Failed to make string substream" ));
    return 1;
  }

  if( !pb_decode( &metadata_stream, &fd_exec_test_fixture_metadata_t_msg, metadata ) ){
    FD_LOG_ERR(( "Failed to decode metadata" ));
    return 1;
  }

  // this advances the stream to the end of the substream!
  if( !pb_close_string_substream( fixture_stream, &metadata_stream ) ){
    FD_LOG_ERR(( "Failed to close string substream" ));
    return 1;
  }

  return 0;
}

/* We could do a blind execution, but that sounds extremely unsafe.
   This function serves the more important purpose of validation.
   TODO: Look into using FD Perfect Hash here */
int
harness_ctx_from_metadata( fd_exec_test_fixture_metadata_t* metadata, const sol_compat_harness_ctx_t** h_ctx ) {
  const char *entrypoint = metadata->fn_entrypoint;
  if( strcmp( entrypoint, "sol_compat_instr_execute_v1" ) == 0 ){
    *h_ctx = &instr_harness_ctx;
  } else if( strcmp( entrypoint, "sol_compat_vm_validate_v1" ) == 0 ){
    *h_ctx = &vm_validate_harness_ctx;
  } else if( strcmp( entrypoint, "sol_compat_txn_execute_v1" ) == 0 ){
    *h_ctx = &txn_harness_ctx;
  } else if( strcmp( entrypoint, "sol_compat_elf_loader_v1" ) == 0 ){
    *h_ctx = &elf_loader_harness_ctx;
  } else if( strcmp( entrypoint, "sol_compat_vm_syscall_execute_v1" ) == 0 ){
    *h_ctx = &syscall_harness_ctx;
  } else if( strcmp( entrypoint, "sol_compat_vm_cpi_syscall_v1" ) == 0 ){
    *h_ctx = &syscall_harness_ctx;
  } else if( strcmp( entrypoint, "sol_compat_vm_interp_v1" ) == 0 ){
    *h_ctx = &syscall_harness_ctx;
  } else {
    FD_LOG_ERR(( "Unknown entrypoint: %s", entrypoint ));
    return 1;
  }
  return 0;
}

int
compare_effects( pb_istream_t* expected_effects,
                 pb_istream_t* actual_effects,
                 sol_compat_harness_ctx_t const* harness_ctx ) {
  /* TODO: use descriptor for more granular diffs */
  (void)harness_ctx;

  if( expected_effects->bytes_left != actual_effects->bytes_left ){
    FD_LOG_ERR(( "Size mismatch: %lu != %lu", expected_effects->bytes_left, actual_effects->bytes_left ));
    return 1;
  }

  if( !fd_memeq( expected_effects->state, actual_effects->state, expected_effects->bytes_left ) ){
    FD_LOG_ERR(( "Binary cmp failed" ));
    return 1;
  }

  return 0;
}

/* Return 1 on failure */
int
exec_fixture( const char *path ) {
  /* Read file contents to memory */
  int file = open( path, O_RDONLY );
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(%s): %s", path, fd_io_strerror( errno ) ));
    return 0;
  }

  ulong file_sz = (ulong)st.st_size;
  uchar * buf = malloc( file_sz );
  // Create output buffer for effects (128MB)
  uint64_t out_sz = 1UL << 27;
  uint8_t *out = malloc( out_sz );

  FD_TEST( 0==fd_io_read( file, buf, file_sz, file_sz, &file_sz ) );
  FD_TEST( 0==close( file ) );

  // Extract FixtureMetadata
  fd_exec_test_fixture_metadata_t metadata[1] = {0};
  pb_istream_t tmp = pb_istream_from_buffer( buf, file_sz );
  if( extract_metadata( &tmp, metadata ) ){
    FD_LOG_ERR(( "Failed to extract metadata" ));
    return 1;
  }
  FD_LOG_INFO(( "Extracted metadata: %s", metadata->fn_entrypoint ));
  const sol_compat_harness_ctx_t * harness_ctx = NULL;
  if( harness_ctx_from_metadata( metadata, &harness_ctx ) ){
    FD_LOG_ERR(( "Failed to get fixture descriptor" ));
    return 1;
  }

  // Extract context to pass to harness entrypoint
  tmp = pb_istream_from_buffer( buf, file_sz ); // Reset stream
  if( advance_stream_to_field( &tmp, harness_ctx->context_submsg_tag ) ){
    FD_LOG_ERR(( "Failed to advance stream to context tag" ));
    return 1;
  }

  pb_istream_t context_stream;
  if( !pb_make_string_substream( &tmp, &context_stream ) ){
    FD_LOG_ERR(( "Failed to make string substream" ));
    return 1;
  }

  // Call the harness entrypoint
  sol_compat_protobuf_call_v1 sol_compat_protobuf_call_fn = (sol_compat_protobuf_call_v1)dlsym( sol_compat_handle, metadata->fn_entrypoint );
  if( sol_compat_protobuf_call_fn == NULL ) {
    FD_LOG_ERR(( "Failed to find sol_compat_protobuf_call function: %s", dlerror() ));
    return 1;
  }

  // Remember entrypoints return 1 on success
  if( !sol_compat_protobuf_call_fn( out, &out_sz, context_stream.state, context_stream.bytes_left ) ){
    FD_LOG_ERR(( "Failed to call sol_compat_protobuf_call" ));
    return 1;
  }

  pb_close_string_substream( &tmp, &context_stream );

  // Compare effects from output buffer with expected effects (byte-by-byte)
  // First get the expected effects
  tmp = pb_istream_from_buffer( buf, file_sz ); // Reset stream
  if( advance_stream_to_field( &tmp, harness_ctx->effects_submsg_tag ) ){
    FD_LOG_ERR(( "Failed to advance stream to effects tag" ));
    return 1;
  }

  pb_istream_t effects_stream;
  if( !pb_make_string_substream( &tmp, &effects_stream ) ){
    FD_LOG_ERR(( "Failed to make string substream" ));
    return 1;
  }

  // Make istream from out buffer
  pb_istream_t out_istream = pb_istream_from_buffer( out, out_sz );

  // Compare effects
  if( compare_effects( &effects_stream, &out_istream, harness_ctx ) ){
    FD_LOG_ERR(( "Failed to compare effects" ));
    return 1;
  }

  pb_close_string_substream( &tmp, &effects_stream );

  free( buf );
  free( out );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  if( setup( argc, argv ) ) {
    teardown();
    return 1;
  }

  char *fixture_path = NULL;

  ulong num_failures = 0;
  while( (fixture_path = csv_iter_next(filepath_iter)) ) {
    num_failures += (ulong)exec_fixture( fixture_path );
  }

  teardown();
  return num_failures ? 1 : 0;
}
