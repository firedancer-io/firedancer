#include "fd_ssmanifest_writer.h"

#define STATE_BLOCKHASH_QUEUE        1
#define STATE_HASHES                 2
#define STATE_HARD_FORKS             3
#define STATE_COUNTERS               4
#define STATE_VOTE_ACCOUNTS          5
#define STATE_STAKE_DELEGATION       6
#define STATE_STAKE_EPOCH            7
#define STATE_STAKE_HISTORY          8
#define STATE_BANK_TRAILER           9
#define STATE_ACCOUNT_STORAGE_ENTRY 10
#define STATE_BANK_HASH_INFO        11
#define STATE_EPOCH_STAKES          12
#define STATE_EPOCH_STAKES_STAKES   13
#define STATE_EPOCH_STAKES_EPOCH    14
#define STATE_EPOCH_STAKE_HISTORY   15
#define STATE_EPOCH_TOTAL_STAKE     16
#define STATE_NODE_VOTE_ACCOUNTS    17
#define STATE_AUTH_VOTER            18
#define STATE_LTHASH                19
#define STATE_DONE                  20
#define STATE_INIT STATE_BLOCKHASH_QUEUE

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t * enc,
                           fd_bank_t const *        bank ) {
  enc->state = STATE_BLOCKHASH_QUEUE;
  enc->bank = bank;
  return enc;
}

/* Size estimate */

#define ENCODE_FN     static ulong manifest_estimate( fd_ssmanifest_writer_t * enc )
#define PREP          ulong sz = 0UL;
#define PUSH_VAL(t,n) do { sz += sizeof(t); (void)(n); } while(0)
#define RET_EXPR      sz
#include "fd_ssmanifest_encoder.c"

ulong
fd_snap_manifest_serialized_sz( fd_bank_t const * bank ) {
  fd_ssmanifest_writer_t writer[1];
  fd_ssmanifest_writer_init( writer, bank );
  ulong sz = 0UL;
  for(;;) {
    ulong chunk = manifest_estimate( writer );
    if( FD_UNLIKELY( !chunk ) ) break;
    sz += chunk;
  }
  return sz;
}

/* Actual encoder */

__attribute__((cold,noreturn))
static void fail( fd_ssmanifest_writer_t const * enc,
                  ulong buf_sz,
                  ulong line_nr ) {
  FD_LOG_ERR(( "buffer overflow (state=%u, buf_sz=%lu, line_nr=%lu)", enc->state, buf_sz, line_nr ));
}

#define ENCODE_FN                                                         \
  ulong                                                                   \
  fd_snap_manifest_serialize( fd_ssmanifest_writer_t * enc,               \
                              uchar out_buf[ FD_SSMANIFEST_BUF_MIN ],     \
                              ulong buf_sz )
#define PREP                                                              \
  uchar * p  = out_buf;                                                   \
  uchar * p1 = out_buf+buf_sz;
#define PUSH_VAL( t, n )                                                  \
  FD_STORE( t, __extension__({                                            \
    /* compile time bounds check elide */                                 \
    if( FD_UNLIKELY( p+sizeof(t) > p1 ) ) fail( enc, buf_sz, __LINE__ );  \
    uchar * ret = p;                                                      \
    p += sizeof(t);                                                       \
    ret;                                                                  \
  }), (n) )
#define RET_EXPR (ulong)( p - out_buf )
#include "fd_ssmanifest_encoder.c"
