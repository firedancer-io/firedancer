#include "fd_groove_base.h"

char const *
fd_groove_strerror( int err ) {
  switch( err ) {
  case FD_GROOVE_SUCCESS:     return "success";
  case FD_GROOVE_ERR_INVAL:   return "bad input";
  case FD_GROOVE_ERR_AGAIN:   return "try again later";
  case FD_GROOVE_ERR_CORRUPT: return "corrupt";
  case FD_GROOVE_ERR_EMPTY:   return "empty";
  case FD_GROOVE_ERR_FULL:    return "full";
  case FD_GROOVE_ERR_KEY:     return "key not found";
  default: break;
  }
  return "unknown";
}
