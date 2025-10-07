#include "fd_vinyl_base.h"

char const *
fd_vinyl_strerror( int err ) {
  switch( err ) {
  case FD_VINYL_SUCCESS:     return "success";
  case FD_VINYL_ERR_INVAL:   return "inval";
  case FD_VINYL_ERR_AGAIN:   return "again";
  case FD_VINYL_ERR_CORRUPT: return "corrupt";
  case FD_VINYL_ERR_EMPTY:   return "empty";
  case FD_VINYL_ERR_FULL:    return "full";
  case FD_VINYL_ERR_KEY:     return "key";
  default: break;
  }
  return "unknown";
}
