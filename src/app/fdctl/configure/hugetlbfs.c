#include "configure.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mount.h>

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, "hugetlbfs", "increase `/proc/sys/vm/nr_hugepages`, mount hugetblfs filesystem at `/mnt`" );
}

static void
fini_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, "hugetlbfs", "remove directories from `/mnt`, unmount hugetlbfs" );
}

void
try_defragment_memory( void ) {
  write_uint_file( "/proc/sys/vm/compact_memory", 1 );
  /* Sleep a little to give the OS some time to perform the
     compaction. */
  nanosleep1( 0, 250000000 /* 250 millis */ );
}

static const char * ERR_MSG = "please confirm your host is configured for gigantic pages,";

static char const * TOTAL_HUGE_PAGE_PATH[ 2 ] = {
  "/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
  "/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages",
};

static char const * FREE_HUGE_PAGE_PATH[ 2 ] = {
  "/sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages",
  "/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/free_hugepages",
};

static ulong PAGE_SIZE[ 2 ] = {
  2097152,
  1073741824,
};

static char const * PAGE_NAMES[ 2 ] = {
  "huge",
  "gigantic"
};

static void
init( config_t * const config ) {
  ulong required_pages[ 2 ] = {
    fd_topo_huge_page_cnt( &config->topo, 1 ),
    fd_topo_gigantic_page_cnt( &config->topo )
  };

  char const * mount_path[ 2 ] = {
    config->hugetlbfs.huge_page_mount_path,
    config->hugetlbfs.gigantic_page_mount_path,
  };

  /* Do NOT include anonymous huge pages in the min_size count that we reserve here,
     because they do not come from the hugetlbfs.  Counting them towards that
     reservation would prevent the anonymous mmap which maps them in from
     succeeding. */
  ulong min_size[ 2 ] = { PAGE_SIZE[ 0 ] * fd_topo_huge_page_cnt( &config->topo, 0 ),
                          PAGE_SIZE[ 1 ] * fd_topo_gigantic_page_cnt( &config->topo ) };

  for( ulong i=0UL; i<2UL; i++ ) {
    uint free_pages = read_uint_file( FREE_HUGE_PAGE_PATH[ i ], ERR_MSG );

    /* There is a TOCTOU race condition here, but it's not avoidable. There's
       no way to atomically increment the page count. */
    try_defragment_memory();
    FD_TEST( required_pages[ i ]<=UINT_MAX );
    if( FD_UNLIKELY( free_pages<required_pages[ i ] ) ) {
      uint total_pages = read_uint_file( TOTAL_HUGE_PAGE_PATH[ i ], ERR_MSG );
      uint additional_pages_needed = (uint)required_pages[ i ]-free_pages;
      write_uint_file( TOTAL_HUGE_PAGE_PATH[ i ], total_pages+additional_pages_needed );
      if( FD_UNLIKELY( read_uint_file( TOTAL_HUGE_PAGE_PATH[ i ], ERR_MSG )<total_pages+additional_pages_needed ) )
        FD_LOG_ERR(( "ENOMEM-Failed to reserve enough %s pages in the kernel to run "
                     "Firedancer. Your system is already using %u pages, has %u free "
                     "pages, and needs %lu (%u more) pages to run Firedancer.  Attempting to "
                     "reserve the required additional pages failed, which means you "
                     "either do not have enough memory left on the system, or you "
                     "have the memory but it is fragmented and could not be reserved "
                     "in one block. Either increase the memory on your machine, or "
                     "try to run the hugetlbfs stage after rebooting your system "
                     "so that it can reserve pages before system memory is fragmented.",
                     PAGE_NAMES[ i ], total_pages - free_pages, free_pages, required_pages[ i ], additional_pages_needed ));
    }

    mkdir_all( mount_path[ i ], config->uid, config->gid );
    char options[ 256 ];
    FD_TEST( fd_cstr_printf_check( options, sizeof(options), NULL, "pagesize=%lu,min_size=%lu", PAGE_SIZE[ i ], min_size[ i ] ) );
    if( FD_UNLIKELY( mount( "none", mount_path[ i ], "hugetlbfs", 0, options) ) )
      FD_LOG_ERR(( "mount of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( chown( mount_path[ i ], config->uid, config->gid ) ) )
      FD_LOG_ERR(( "chown of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( chmod( mount_path[ i ], S_IRUSR | S_IWUSR | S_IXUSR ) ) )
      FD_LOG_ERR(( "chmod of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
  }
}

static void
fini( config_t * const config ) {
  const char * mount_path[ 2 ] = {
    config->hugetlbfs.huge_page_mount_path,
    config->hugetlbfs.gigantic_page_mount_path,
  };

  for( ulong i=0UL; i<2UL; i++ ) {
    FILE * fp = fopen( "/proc/self/mounts", "r" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "failed to open `/proc/self/mounts`" ));

    char line[ 4096 ];
    while( FD_LIKELY( fgets( line, 4096UL, fp ) ) ) {
      if( FD_UNLIKELY( strlen( line )==4095UL ) ) FD_LOG_ERR(( "line too long in `/proc/self/mounts`" ));
      if( FD_UNLIKELY( strstr( line, mount_path[ i ] ) ) ) {
        if( FD_UNLIKELY( umount( mount_path[ i ] ) ) )
          FD_LOG_ERR(( "umount of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
      }
    }

    if( FD_UNLIKELY( ferror( fp ) ) )
      FD_LOG_ERR(( "error reading `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( fclose( fp ) ) )
      FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( rmdir( mount_path[ i ] ) && errno!=ENOENT ) )
      FD_LOG_ERR(( "error removing hugetlbfs mount at `%s` (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
  }
}

static configure_result_t
check( config_t * const config ) {
  char const * mount_path[ 2 ] = {
    config->hugetlbfs.huge_page_mount_path,
    config->hugetlbfs.gigantic_page_mount_path,
  };

  static char const * MOUNT_PAGE_SIZE[ 2 ]  = {
    "pagesize=2M",
    "pagesize=1024M",
  };

  ulong required_min_size[ 2 ] = { PAGE_SIZE[ 0 ] * fd_topo_huge_page_cnt( &config->topo, 0 ),
                                   PAGE_SIZE[ 1 ] * fd_topo_gigantic_page_cnt( &config->topo ) };

  struct stat st;
  int result1 = stat( mount_path[ 0 ], &st );
  if( FD_UNLIKELY( result1 && errno!=ENOENT ) )
    PARTIALLY_CONFIGURED( "failed to stat `%s` (%i-%s)", mount_path[ 0 ], errno, fd_io_strerror( errno ) );
  int result2 = stat( mount_path[ 1 ], &st );
  if( FD_UNLIKELY( result2 && errno!=ENOENT ) )
    PARTIALLY_CONFIGURED( "failed to stat `%s` (%i-%s)", mount_path[ 1 ], errno, fd_io_strerror( errno ) );

  if( FD_UNLIKELY( result1 && result2 ) )
    NOT_CONFIGURED( "mounts `%s` and `%s` do not exist", mount_path[ 0 ], mount_path[ 1 ] );
  else if( FD_UNLIKELY( result1 || result2 ) )
    PARTIALLY_CONFIGURED( "only one of `%s` and `%s` exists", mount_path[ 0 ], mount_path[ 1 ] );

  for( ulong i=0UL; i<2UL; i++ ) {
    CHECK( check_dir( mount_path[ i ], config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

    FILE * fp = fopen( "/proc/self/mounts", "r" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "failed to open `/proc/self/mounts`" ));

    char line[ 4096 ];
    int found = 0;
    while( FD_LIKELY( fgets( line, 4096UL, fp ) ) ) {
      if( FD_UNLIKELY( strlen( line )==4095UL ) ) FD_LOG_ERR(( "line too long in `/proc/self/mounts`" ));
      if( FD_UNLIKELY( strstr( line, mount_path[ i ] ) ) ) {
        found = 1;

        char * saveptr;
        char * device = strtok_r( line, " ", &saveptr );
        if( FD_UNLIKELY( !device ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( device, "none" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is on unrecognized device, expected `none`", mount_path[ i ] );
        }

        char * path1 = strtok_r( NULL, " ", &saveptr );
        if( FD_UNLIKELY( !path1 ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( path1, mount_path[ i ] ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is on unrecognized path, expected `%s`", path1, mount_path[ i ] );
        }

        char * type = strtok_r( NULL, " ", &saveptr );
        if( FD_UNLIKELY( !type ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( type, "hugetlbfs" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has unrecognized type, expected `hugetlbfs`", mount_path[ i ] );
        }

        char * options = strtok_r( NULL, " ", &saveptr );
        if( FD_UNLIKELY( !options ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));

        char * saveptr2;
        char * rw = strtok_r( options, ",", &saveptr2 );
        if( FD_UNLIKELY( !rw ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( rw, "rw" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is not mounted read/write, expected `rw`", mount_path[ i ] );
        }

        char * seclabel = strtok_r( NULL, ",", &saveptr2 );
        if( FD_UNLIKELY( !seclabel ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));

        char * relatime;
        if( FD_LIKELY( !strcmp( seclabel, "seclabel" ) ) ) {
          relatime = strtok_r( NULL, ",", &saveptr2 );
          if( FD_UNLIKELY( !relatime ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        } else {
          relatime = seclabel;
        }

        if( FD_UNLIKELY( strcmp( relatime, "relatime" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is not mounted with `relatime`, expected `relatime`", mount_path[ i ] );
        }

        char * pagesize = strtok_r( NULL, ",", &saveptr2 );
        if( FD_UNLIKELY( !pagesize ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( pagesize, MOUNT_PAGE_SIZE[ i ] ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has unrecognized pagesize, expected `%s` %s", mount_path[ i ], MOUNT_PAGE_SIZE[ i ], pagesize );
        }

        char * _min_size = strtok_r( NULL, ",", &saveptr2 );
        if( FD_UNLIKELY( !_min_size ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strncmp( "min_size=", _min_size, 9 ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has unrecognized min_size, expected at least `min_size=%lu`", mount_path[ i ], required_min_size[ i ] );
        }

        char * endptr;
        ulong min_size = strtoul( _min_size+9, &endptr, 10 );
        if( FD_UNLIKELY( *endptr ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has malformed min_size, expected `min_size=%lu`", mount_path[ i ], required_min_size[ i ] );
        }

        if( FD_UNLIKELY( min_size<required_min_size[ i ] ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has min_size `%lu`, expected at least `min_size=%lu`", mount_path[ i ], min_size, required_min_size[ i ] );
        }

        break;
      }
    }

    if( FD_UNLIKELY( ferror( fp ) ) )
      FD_LOG_ERR(( "error reading `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( fclose( fp ) ) )
      FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( !found ) )
      PARTIALLY_CONFIGURED( "mount `%s` not found in `/proc/self/mounts`", mount_path[ i ] );
  }

  CONFIGURE_OK();
}

configure_stage_t hugetlbfs = {
  .name            = "hugetlbfs",
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};
