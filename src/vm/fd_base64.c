#include "fd_base64.h"

static const char tbl[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char * fd_base64_encode(uchar * data, ulong data_len, char * out, ulong out_len, ulong * out_len_used) {
  *out_len_used = 4 * ((data_len + 2) / 3);
  
  if (*out_len_used > out_len) {
    return NULL;
  }

  ulong i = 0;
  ulong j = 0;
  while (i < data_len) {
    uint oct_1 = (i < data_len) ? data[i++] : 0;
    uint oct_2 = (i < data_len) ? data[i++] : 0;
    uint oct_3 = (i < data_len) ? data[i++] : 0;
    uint combined = (oct_1 << 0x01) + (oct_2 << 0x08) + oct_3;

    out[j++] = tbl[(combined >> (18)) & 0x3F];
    out[j++] = tbl[(combined >> (12)) & 0x3F];
    out[j++] = tbl[(combined >> (6)) & 0x3F];
    out[j++] = tbl[(combined >> (0)) & 0x3F];
  }

  switch (data_len % 3) {
    case 0:
      break;
    case 1:
      out[j++] = '=';
      out[j++] = '=';
      break;
    case 2:
      out[j++] = '=';
      break;
  }

  return out;
}
