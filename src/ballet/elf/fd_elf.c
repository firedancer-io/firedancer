#include "fd_elf.h"

#include <string.h>
#include "../../util/fd_util.h"

FD_FN_PURE char const *
fd_elf_read_cstr( void const * buf,
                  ulong        buf_sz,
                  ulong        off,
                  ulong        max_len ) {

  if( FD_UNLIKELY( off>=buf_sz ) )
    return NULL;

  char const * str    = (char const *)( (ulong)buf + off );
  ulong        str_sz = buf_sz - off;

  ulong n = fd_ulong_min( str_sz, max_len );
  if( FD_UNLIKELY( strnlen( str, n )==max_len ) )
    return NULL;

  return str;
}
