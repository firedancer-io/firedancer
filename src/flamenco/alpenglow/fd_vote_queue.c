#include "fd_vote_queue.h"
#include "../runtime/fd_hashes.h"

/* Images kept by a memo slot (memo[i]!=NULL) are read from and hashed
   into the slot; others point into the account being stored (acc_cnt
   counts them).  cv[i] (NULL for none) is the account's memo slot,
   whose cached cv saves hashing input bytes [2048,). */

#define QUEUE_MAX FD_BLAKE3_LEFT_XN_MAX
#define LEFT_DATA (2040UL)          /* data bytes in input bytes [0,2048) */
#define TAIL_SZ   (1UL+2UL*32UL)    /* executable | owner | pubkey */

struct __attribute__((aligned(FD_VOTE_QUEUE_ALIGN))) fd_vote_queue {
  fd_lthash_value_t        delta[ 1 ];
  fd_lthash_value_t        tmp  [ QUEUE_MAX ];
  uchar                    left [ QUEUE_MAX ][ 2048 ];
  ulong                    cnt;
  ulong                    acc_cnt;
  fd_footer_cache_memo_t * memo [ QUEUE_MAX ];
  fd_footer_cache_memo_t * cv   [ QUEUE_MAX ];
  int                      sub  [ QUEUE_MAX ];
  uchar const *            pk   [ QUEUE_MAX ];
  uchar const *            ow   [ QUEUE_MAX ];
  ulong                    la   [ QUEUE_MAX ];
  int                      ex   [ QUEUE_MAX ];
  uchar const *            da   [ QUEUE_MAX ];
  ulong                    dl   [ QUEUE_MAX ];
  fd_lthash_value_t *      out  [ QUEUE_MAX ];
};

FD_STATIC_ASSERT( sizeof (fd_vote_queue_t)==FD_VOTE_QUEUE_FOOTPRINT, vote_queue_footprint );
FD_STATIC_ASSERT( alignof(fd_vote_queue_t)==FD_VOTE_QUEUE_ALIGN,     vote_queue_align     );

fd_vote_queue_t *
fd_vote_queue_init( void * mem ) {
  fd_vote_queue_t * q = (fd_vote_queue_t *)mem;
  q->cnt     = 0UL;
  q->acc_cnt = 0UL;
  fd_lthash_zero( q->delta );
  return q;
}

/* hash hashes the queued images into delta.  An image whose data is
   2041 to 4023 bytes, all zero past offset 2040, hashes only its first
   2048 input bytes plus its memo slot's cached right cv (refilled if
   the slot's key changed); the rest go through lthash_xn. */

static void
hash( fd_vote_queue_t * q ) {
  uchar const * lptr[ QUEUE_MAX ];
  uchar         cv  [ QUEUE_MAX ][ 32 ];
  uchar const * cptr[ QUEUE_MAX ];
  void *        lout[ QUEUE_MAX ];
  ulong         lcnt = 0UL;
  ulong         rest[ QUEUE_MAX ];
  ulong         rcnt = 0UL;
  for( ulong i=0UL; i<q->cnt; i++ ) {
    ulong len = q->dl[ i ];
    int   fit = q->cv[ i ] && q->la[ i ] && len>LEFT_DATA && len<=4096UL-8UL-TAIL_SZ;
    if( fit ) {
      ulong acc = 0UL;
      ulong off = LEFT_DATA;
      for( ; off+8UL<=len; off+=8UL ) acc |= FD_LOAD( ulong, q->da[ i ]+off );
      for( ; off<len;      off++     ) acc |= q->da[ i ][ off ];
      fit = !acc;
    }
    if( !fit ) { rest[ rcnt++ ] = i; continue; }

    fd_footer_cache_memo_t * m = q->cv[ i ];
    if( FD_UNLIKELY( m->cv_data_len!=len || m->cv_executable!=!!q->ex[ i ] ||
                     !fd_memeq( m->cv_pubkey, q->pk[ i ], 32UL ) || !fd_memeq( m->cv_owner, q->ow[ i ], 32UL ) ) ) {
      uchar r[ 2048 ] = {0};
      ulong zsz = len-LEFT_DATA;
      r[ zsz ] = (uchar)!!q->ex[ i ];
      fd_memcpy( r+zsz+1UL,     q->ow[ i ], 32UL );
      fd_memcpy( r+zsz+1UL+32UL, q->pk[ i ], 32UL );
      fd_blake3_right_cv( r, zsz+TAIL_SZ, m->cv );
      fd_memcpy( m->cv_pubkey, q->pk[ i ], 32UL );
      fd_memcpy( m->cv_owner,  q->ow[ i ], 32UL );
      m->cv_executable = !!q->ex[ i ];
      m->cv_data_len   = len;
    }
    FD_STORE( ulong, q->left[ lcnt ], q->la[ i ] );
    fd_memcpy( q->left[ lcnt ]+8UL, q->da[ i ], LEFT_DATA );
    fd_memcpy( cv[ lcnt ], m->cv, 32UL ); /* m may be refilled by a later image */
    lptr[ lcnt ] = q->left[ lcnt ];
    cptr[ lcnt ] = cv[ lcnt ];
    lout[ lcnt ] = q->out[ i ]->bytes;
    lcnt++;
  }
  if( lcnt ) fd_blake3_fini_2048_left_xn( lcnt, lptr, cptr, lout );
  for( ulong off=0UL; off<rcnt; off+=FD_BLAKE3_XN_MAX ) {
    uchar const *       pk [ FD_BLAKE3_XN_MAX ];
    uchar const *       ow [ FD_BLAKE3_XN_MAX ];
    ulong               la [ FD_BLAKE3_XN_MAX ];
    int                 ex [ FD_BLAKE3_XN_MAX ];
    uchar const *       da [ FD_BLAKE3_XN_MAX ];
    ulong               dl [ FD_BLAKE3_XN_MAX ];
    fd_lthash_value_t * out[ FD_BLAKE3_XN_MAX ];
    ulong k = fd_ulong_min( rcnt-off, FD_BLAKE3_XN_MAX );
    for( ulong j=0UL; j<k; j++ ) {
      ulong i = rest[ off+j ];
      pk[ j ] = q->pk[ i ]; ow[ j ] = q->ow[ i ]; la[ j ] = q->la[ i ]; ex[ j ] = q->ex[ i ];
      da[ j ] = q->da[ i ]; dl[ j ] = q->dl[ i ]; out[ j ] = q->out[ i ];
    }
    fd_hashes_account_lthash_xn( k, pk, ow, la, ex, da, dl, out );
  }
  for( ulong i=0UL; i<q->cnt; i++ ) {
    if( q->sub[ i ] ) fd_lthash_sub( q->delta, q->out[ i ] );
    else              fd_lthash_add( q->delta, q->out[ i ] );
  }
  q->cnt     = 0UL;
  q->acc_cnt = 0UL;
}

static void
push( fd_vote_queue_t *        q,
      fd_footer_cache_memo_t * memo,
      fd_footer_cache_memo_t * cv,
      int                      sub,
      uchar const *            pubkey,
      uchar const *            owner,
      ulong                    lamports,
      int                      executable,
      uchar const *            data,
      ulong                    data_len ) {
  ulong i = q->cnt++;
  q->memo[ i ] = memo;
  q->cv  [ i ] = cv;
  q->sub [ i ] = sub;
  q->pk  [ i ] = pubkey;     q->ow[ i ] = owner; q->la[ i ] = lamports;
  q->ex  [ i ] = executable; q->da[ i ] = data;  q->dl[ i ] = data_len;
  q->out [ i ] = memo ? &memo->lthash : q->tmp+i;
  q->acc_cnt  += !memo;
  if( q->cnt==QUEUE_MAX ) hash( q );
}

void
fd_vote_queue_store( fd_vote_queue_t *        q,
                     fd_acc_t const *         acc,
                     fd_footer_cache_memo_t * memo ) {
  for( ulong i=0UL; memo && i<q->cnt; i++ ) {
    if( FD_UNLIKELY( q->memo[ i ]==memo ) ) { hash( q ); break; } /* memo's waiting image */
  }

  fd_lthash_value_t const * pre = memo ? fd_footer_cache_memo_query( memo, acc->pubkey, acc->prior_owner, acc->prior_lamports, acc->prior_executable, acc->prior_data, acc->prior_data_len ) : NULL;
  if( pre ) fd_lthash_sub( q->delta, pre ); /* before the slot is overwritten */
  else      push( q, NULL, memo, 1, acc->pubkey, acc->prior_owner, acc->prior_lamports, acc->prior_executable, acc->prior_data, acc->prior_data_len );

  int kept = memo && fd_footer_cache_memo_insert( memo, acc->pubkey, acc->owner, acc->lamports, acc->executable, acc->data, acc->data_len );
  FD_TEST( kept || !pre ); /* a hit's prior image fit */
  if( kept ) push( q, memo, memo, 0, memo->pubkey, memo->owner, memo->lamports, memo->executable, memo->data, memo->data_len );
  else       push( q, NULL, memo, 0, acc->pubkey,  acc->owner,  acc->lamports,  acc->executable,  acc->data,  acc->data_len  );

  if( q->acc_cnt ) hash( q );
}

fd_lthash_value_t const *
fd_vote_queue_fini( fd_vote_queue_t * q ) {
  if( q->cnt ) hash( q );
  return q->delta;
}
