#include "configure.h"

#include <stdio.h>

static void
init_perm( security_t *     security,
           config_t * const config ) {
  (void)config;
  check_root( security, "large-pages", "write to a system control file `/proc/sys/vm/nr_hugepages`" );
}

uint
read_uint_file( const char * path, const char * errmsg_enoent ) {
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) ) {
    if( errno == ENOENT)
      FD_LOG_ERR(( "%s fopen failed `%s` (%i-%s)",
                   errmsg_enoent, path, errno, fd_io_strerror( errno ) ));
    else
      FD_LOG_ERR(( "fopen failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  uint value = 0;
  if( FD_UNLIKELY( fscanf( fp, "%u\n", &value ) != 1 ) )
    FD_LOG_ERR(( "failed to read uint from `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return value;
}

void
write_uint_file( const char * path,
                 uint         value ) {
  FILE * fp = fopen( path, "w" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "fopen failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fprintf( fp, "%u\n", value ) <= 0 ) )
    FD_LOG_ERR(( "fprintf failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

void
try_defragment_memory( void ) {
  write_uint_file( "/proc/sys/vm/compact_memory", 1 );
  /* sleep a little to give the OS some time to perform the
     compaction */
  nanosleep1( 0, 250000000 );
}

void
expected_pages( config_t * const config, uint out[2] ) {
  uint num_tiles = 0;

  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    switch( config->shmem.workspaces[ i ].kind ) {
      case wksp_netmux_inout:
      case wksp_quic_verify:
      case wksp_verify_dedup:
      case wksp_dedup_pack:
      case wksp_pack_bank:
      case wksp_bank_shred:
      case wksp_metrics_quic:
      case wksp_metrics_verify:
      case wksp_metrics_dedup:
      case wksp_metrics_pack:
      case wksp_metrics_bank:
        break;
      case wksp_net:
      case wksp_netmux:
      case wksp_quic:
      case wksp_verify:
      case wksp_dedup:
      case wksp_pack:
      case wksp_bank:
      case wksp_metrics:
        num_tiles++;
        break;
    }

    switch( config->shmem.workspaces[ i ].page_size ) {
      case FD_SHMEM_GIGANTIC_PAGE_SZ:
        out[ 1 ] += (uint)config->shmem.workspaces[ i ].num_pages;
        break;
      case FD_SHMEM_HUGE_PAGE_SZ:
        out[ 0 ] += (uint)config->shmem.workspaces[ i ].num_pages;
        break;
      default:
        break;
    }
  }

  /* each tile has 6 huge pages for its stack, and then the main solana
     labs thread, and the pid namespace parent thread also have 6 huge
     pages each for the stack */
  out[ 0 ] += ( num_tiles + 2 ) * 6;
}

static const char * ERR_MSG = "please confirm your host is configured for gigantic pages,";

static void init( config_t * const config ) {
  char * paths[ 2 ] = {
    "/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
    "/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages",
  };
  uint expected[ 2 ] = { 0 };
  expected_pages( config, expected );

  for( int i=0; i<2; i++ ) {
    uint actual = read_uint_file( paths[ i ], ERR_MSG );

    try_defragment_memory();
    if( FD_UNLIKELY( actual < expected[ i ] ) )
      write_uint_file( paths[ i ], expected[ i ] );
  }
}

static configure_result_t check( config_t * const config ) {
  char * paths[ 2 ] = {
    "/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
    "/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages",
  };
  uint expected[ 2 ] = { 0 };
  expected_pages( config, expected );

  for( int i=0; i<2; i++ ) {
    uint actual = read_uint_file( paths[i], ERR_MSG );
    if( FD_UNLIKELY( actual < expected[i] ) )
      NOT_CONFIGURED( "expected at least %u %s pages, but there are %u",
                      expected[i],
                      i ? "gigantic" : "huge",
                      actual );
  }

  CONFIGURE_OK();
}

configure_stage_t large_pages = {
  .name            = "large-pages",
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};
