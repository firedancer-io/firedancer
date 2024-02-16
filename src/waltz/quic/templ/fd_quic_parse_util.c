#include "fd_quic_parse_util.h"

/* ensure visible symbol gets emitted per c99 */
extern
ulong
fd_quic_parse_bits( uchar const * buf, ulong cur_bit, ulong bits );

extern
int
fd_quic_encode_bits( uchar * buf, ulong cur_bit, ulong val, ulong bits );

