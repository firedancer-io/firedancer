#include "../../util/fd_util.h"
#include "../../tango/webserver/fd_webserver.h"
#include "fd_block_to_json.h"

int fd_block_to_json( fd_textstream_t * ts,
                      long call_id,
                      const void* block,
                      ulong block_sz,
                      enum fd_block_encoding encoding,
                      long maxvers,
                      enum fd_block_detail detail,
                      int rewards ) {
  (void)ts;
  (void)call_id;
  (void)block;
  (void)block_sz;
  (void)encoding;
  (void)maxvers;
  (void)detail;
  (void)rewards;
  return 0;
}

