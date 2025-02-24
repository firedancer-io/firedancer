#include "fd_funkier_base.h"

char const *
fd_funkier_strerror( int err ) {
  switch( err ) {
  case FD_FUNKIER_SUCCESS:    return "success";
  case FD_FUNKIER_ERR_INVAL:  return "inval";
  case FD_FUNKIER_ERR_XID:    return "xid";
  case FD_FUNKIER_ERR_KEY:    return "key";
  case FD_FUNKIER_ERR_FROZEN: return "frozen";
  case FD_FUNKIER_ERR_TXN:    return "txn";
  case FD_FUNKIER_ERR_REC:    return "rec";
  case FD_FUNKIER_ERR_MEM:    return "mem";
  case FD_FUNKIER_ERR_SYS:    return "sys";
  default: break;
  }
  return "unknown";
}
