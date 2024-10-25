#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../nanopb/pb_firedancer.h"
#include "../../nanopb/pb_common.h"
#include "../../nanopb/pb_decode.h"
#include "generated/metadata.pb.h"
#include "../../../util/fd_util.h"
#include "nanopb/pb.h"

#include "generated/vm.pb.h"
#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/elf.pb.h"

static void * sol_compat_handle = NULL;

typedef void (*sol_compat_init_fn_t)(int log_lvl);
typedef void (*sol_compat_fini_fn_t)(void);
typedef int  (*sol_compat_protobuf_call_v1)(uint8_t *out, uint64_t *out_sz,
                                            uint8_t const *in, uint64_t in_sz);

typedef struct {
    char *input_str;     // The input comma-separated string 
    char *current_pos;   // The current position in the string
    char delimiter;      // Delimiter (comma in this case)
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
  filepath_iter = csv_iter_init(fixture_paths, ',');

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

  return 0;
}

int
extract_metadata( pb_istream_t* fixture_stream, fd_exec_test_fixture_metadata_t* metadata ) {
  // fd_exec_test_fixture_base_t base = FD_EXEC_TEST_FIXTURE_BASE_DEFAULT;
  // pb_field_iter_t iter;

  // if( !pb_field_iter_begin( &iter, &fd_exec_test_fixture_base_t_msg, &base ) ){
  //   FD_LOG_ERR(( "Failed to begin field iteration" ));
  //   return 1;
  // }

  // // This should be a NO-OP since metadata is the first field, but just in case
  // if ( !pb_field_iter_find( &iter, FD_EXEC_TEST_FIXTURE_BASE_METADATA_TAG ) ){
  //   FD_LOG_ERR(( "Failed to find metadata field" ));
  //   return 1;
  // }

  while( fixture_stream->bytes_left ){
    uint32_t tag;
    pb_wire_type_t wire_type;
    bool eof;

    if ( !pb_decode_tag( fixture_stream, &wire_type, &tag, &eof ) ){
      if ( eof ){
        break;
      } else {
        FD_LOG_ERR(( "Failed to decode tag" ));
        return 1;
      }
    }
    if( tag == FD_EXEC_TEST_FIXTURE_BASE_METADATA_TAG ){
      break;
    }

    if( !pb_skip_field( fixture_stream, wire_type ) ){
      FD_LOG_ERR(( "Failed to skip field" ));
      return 1;
    }
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

/* TODO: We could do a blind execution, but that sounds extremely unsafe.
         This function serves the more important purpose of validation, but
         it is quite slow... a hash table would be nice */
int
fixture_desc_from_metadata( fd_exec_test_fixture_metadata_t* metadata, pb_msgdesc_t* desc ) {
  const char *entrypoint = metadata->fn_entrypoint;
  if( strcmp( entrypoint, "sol_compat_instr_execute_v1" ) == 0 ){
    *desc = fd_exec_test_instr_fixture_t_msg;
  } else if( strcmp( entrypoint, "sol_compat_vm_validate_v1" ) == 0 ){
    *desc = fd_exec_test_validate_vm_fixture_t_msg;
  } else if( strcmp( entrypoint, "sol_compat_txn_execute_v1" ) == 0 ){
    *desc = fd_exec_test_txn_fixture_t_msg;
  } else if( strcmp( entrypoint, "sol_compat_elf_loader_v1" ) == 0 ){
    *desc = fd_exec_test_elf_loader_fixture_t_msg;
  } else if( strcmp( entrypoint, "sol_compat_vm_syscall_execute_v1" ) == 0 ){
    *desc = fd_exec_test_syscall_fixture_t_msg;
  } else if( strcmp( entrypoint, "sol_compat_vm_cpi_syscall_v1" ) == 0 ){
    *desc = fd_exec_test_syscall_fixture_t_msg;
  } else if( strcmp( entrypoint, "sol_compat_vm_interp_v1" ) == 0 ){
    *desc = fd_exec_test_syscall_fixture_t_msg;
  } else {
    FD_LOG_ERR(( "Unknown entrypoint: %s", entrypoint ));
    return 1;
  }
  return 0;
}

/* Return 1 on failure */
int
exec_fixture( const char *path ) {
  /* Read file content to memory */
  int file = open( path, O_RDONLY );
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(%s): %s", path, fd_io_strerror( errno ) ));
    return 0;
  }

  ulong file_sz = (ulong)st.st_size;
  uchar * buf = malloc( file_sz );
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
  pb_msgdesc_t fixture_desc[1] = {0};
  if( fixture_desc_from_metadata( metadata, fixture_desc ) ){
    FD_LOG_ERR(( "Failed to get fixture descriptor" ));
    return 1;
  }
  
  
  free( buf );
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

  while( (fixture_path = csv_iter_next(filepath_iter)) ) {
    exec_fixture( fixture_path );
  }

  teardown();
  return 0;
}
