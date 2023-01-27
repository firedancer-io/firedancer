#include "fd_quic_parse_util.h"

/* ensure visible symbol gets emitted per c99 */
extern
uint64_t
fd_quic_parse_bits( uchar const * buf, size_t cur_bit, size_t bits );

extern
int
fd_quic_encode_bits( uchar * buf, size_t cur_bit, uint64_t val, size_t bits );

