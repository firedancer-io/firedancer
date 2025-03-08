#include "fd_file_util.h"

#include <stdio.h>
#include <errno.h>

int
fd_file_util_read_uint( char const * path,
                        uint *       value ) {
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) ) return -1;

  uint _value;
  if( FD_UNLIKELY( 1!=fscanf( fp, "%u\n", &_value ) ) ) {
    errno = ERANGE;
    return -1;
  }
  if( FD_UNLIKELY( fclose( fp ) ) ) return -1;
  *value = _value;
  return 0;
}
