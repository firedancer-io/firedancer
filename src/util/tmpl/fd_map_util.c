#include "fd_map.h"

FD_FN_CONST char const *
fd_map_strerror( int err ) {
  switch( err ) {
  case FD_MAP_SUCCESS:     return "success";
  case FD_MAP_ERR_INVAL:   return "invalid";
  case FD_MAP_ERR_AGAIN:   return "try again";
  case FD_MAP_ERR_CORRUPT: return "corrupt";
  //case FD_MAP_ERR_EMPTY:   return "empty";
  case FD_MAP_ERR_FULL:    return "full";
  case FD_MAP_ERR_KEY:     return "key";
  default:                 return "unknown";
  }
}
