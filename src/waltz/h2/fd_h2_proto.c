#include "fd_h2_proto.h"

FD_FN_CONST char const *
fd_h2_frame_name( uint frame_id ) {
  switch( frame_id ) {
  case FD_H2_FRAME_TYPE_DATA:            return "DATA";
  case FD_H2_FRAME_TYPE_HEADERS:         return "HEADERS";
  case FD_H2_FRAME_TYPE_PRIORITY:        return "PRIORITY";
  case FD_H2_FRAME_TYPE_RST_STREAM:      return "RST_STREAM";
  case FD_H2_FRAME_TYPE_SETTINGS:        return "SETTINGS";
  case FD_H2_FRAME_TYPE_PUSH_PROMISE:    return "PUSH_PROMISE";
  case FD_H2_FRAME_TYPE_PING:            return "PING";
  case FD_H2_FRAME_TYPE_GOAWAY:          return "GOAWAY";
  case FD_H2_FRAME_TYPE_WINDOW_UPDATE:   return "WINDOW_UPDATE";
  case FD_H2_FRAME_TYPE_CONTINUATION:    return "CONTINUATION";
  case FD_H2_FRAME_TYPE_ALTSVC:          return "ALTSVC";
  case FD_H2_FRAME_TYPE_ORIGIN:          return "ORIGIN";
  case FD_H2_FRAME_TYPE_PRIORITY_UPDATE: return "PRIORITY_UPDATE";
  default:
    return "unknown";
  }
}

FD_FN_CONST char const *
fd_h2_setting_name( uint setting_id ) {
  switch( setting_id ) {
  case 0: return "reserved";
  case FD_H2_SETTINGS_HEADER_TABLE_SIZE:      return "HEADER_TABLE_SIZE";
  case FD_H2_SETTINGS_ENABLE_PUSH:            return "ENABLE_PUSH";
  case FD_H2_SETTINGS_MAX_CONCURRENT_STREAMS: return "MAX_CONCURRENT_STREAMS";
  case FD_H2_SETTINGS_INITIAL_WINDOW_SIZE:    return "INITIAL_WINDOW_SIZE";
  case FD_H2_SETTINGS_MAX_FRAME_SIZE:         return "MAX_FRAME_SIZE";
  case FD_H2_SETTINGS_MAX_HEADER_LIST_SIZE:   return "MAX_HEADER_LIST_SIZE";
  default:                                    return "unknown";
  }
}

FD_FN_CONST char const *
fd_h2_strerror( uint err ) {
  switch( err ) {
  case FD_H2_SUCCESS:                   return "success";
  case FD_H2_ERR_PROTOCOL:              return "protocol error";
  case FD_H2_ERR_INTERNAL:              return "internal error";
  case FD_H2_ERR_FLOW_CONTROL:          return "flow control error";
  case FD_H2_ERR_SETTINGS_TIMEOUT:      return "timed out waiting for settings";
  case FD_H2_ERR_STREAM_CLOSED:         return "stream closed";
  case FD_H2_ERR_FRAME_SIZE:            return "invalid frame size";
  case FD_H2_ERR_REFUSED_STREAM:        return "stream refused";
  case FD_H2_ERR_CANCEL:                return "stream cancelled";
  case FD_H2_ERR_COMPRESSION:           return "compression error";
  case FD_H2_ERR_CONNECT:               return "error while connecting";
  case FD_H2_ERR_ENHANCE_YOUR_CALM:     return "enhance your calm";
  case FD_H2_ERR_INADEQUATE_SECURITY:   return "inadequate security";
  case FD_H2_ERR_HTTP_1_1_REQUIRED:     return "HTTP/1.1 required";
  default:                              return "unknown";
  }
}
