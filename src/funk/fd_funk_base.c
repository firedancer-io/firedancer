#include "fd_funk_base.h"

char const *
fd_funk_strerror( int err ) {
  switch( err ) {
  case FD_FUNK_SUCCESS:    return "success";
  case FD_FUNK_ERR_INVAL:  return "inval";
  case FD_FUNK_ERR_XID:    return "xid";
  case FD_FUNK_ERR_KEY:    return "key";
  case FD_FUNK_ERR_FROZEN: return "frozen";
  case FD_FUNK_ERR_TXN:    return "txn";
  case FD_FUNK_ERR_REC:    return "rec";
  case FD_FUNK_ERR_MEM:    return "mem";
  case FD_FUNK_ERR_SYS:    return "sys";
  default: break;
  }
  return "unknown";
}

