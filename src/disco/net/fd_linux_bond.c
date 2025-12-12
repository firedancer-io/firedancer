#include "fd_linux_bond.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

int
fd_bonding_is_master( char const * device ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/bonding", device ) );
  struct stat st;
  int err = stat( path, &st );
  if( FD_UNLIKELY( err && errno != ENOENT ) )
    FD_LOG_ERR(( "error checking if device `%s` is bonded, stat(%s) failed (%i-%s)",
                 device, path, errno, fd_io_strerror( errno ) ));
  return !err;
}

static void
read_slaves( char const * device,
             char         output[ 4096 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/bonding/slaves", device ) );

  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) )
    FD_LOG_ERR(( "error configuring network device, fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fgets( output, 4096, fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( feof( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (EOF)", path ));
  if( FD_UNLIKELY( ferror( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (error)", path ));
  if( FD_UNLIKELY( strlen( output ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
  if( FD_UNLIKELY( strlen( output ) == 0 ) ) FD_LOG_ERR(( "line empty in `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fclose(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  output[ strlen( output ) - 1 ] = '\0';
}

fd_bonding_slave_iter_t *
fd_bonding_slave_iter_init(
    fd_bonding_slave_iter_t * iter,
    char const * device
) {
  read_slaves( device, iter->line );
  iter->saveptr = NULL;
  iter->tok     = strtok_r( iter->line, " \t", &iter->saveptr );
  return iter;
}

int
fd_bonding_slave_iter_done( fd_bonding_slave_iter_t const * iter ) {
  return !iter->tok;
}

void
fd_bonding_slave_iter_next(
    fd_bonding_slave_iter_t * iter
) {
  iter->tok = strtok_r( NULL, " \t", &iter->saveptr );
}

char const *
fd_bonding_slave_iter_ele(
    fd_bonding_slave_iter_t const * iter
) {
  return iter->tok;
}

uint
fd_bonding_slave_cnt( char const * device ) {
  fd_bonding_slave_iter_t iter_[1];
  uint cnt = 0U;
  for( fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, device );
       !fd_bonding_slave_iter_done( iter );
       fd_bonding_slave_iter_next( iter ) ) {
    cnt++;
  }
  return cnt;
}
