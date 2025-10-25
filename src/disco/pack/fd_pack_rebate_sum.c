#include "fd_pack_rebate_sum.h"
#include "fd_pack.h"
#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

static const fd_acct_addr_t null_addr = { 0 };

#define MAP_NAME        rmap
#define MAP_T           fd_pack_rebate_entry_t
#define MAP_LG_SLOT_CNT 13
#define MAP_KEY_T       fd_acct_addr_t
#define MAP_KEY_NULL    null_addr
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_addr)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_hash( 132132, (key).b, 32UL ))
#define MAP_MOVE(d,s)         (__extension__({ FD_LOG_CRIT(( "Tried to move a map value" )); (d)=(s); }))

#include "../../util/tmpl/fd_map.c"


void *
fd_pack_rebate_sum_new( void * mem ) {
  fd_pack_rebate_sum_t * s = (fd_pack_rebate_sum_t *)mem;

  s->total_cost_rebate        = 0UL;
  s->vote_cost_rebate         = 0UL;
  s->data_bytes_rebate        = 0UL;
  s->microblock_cnt_rebate    = 0UL;
  s->ib_result                = 0;
  s->writer_cnt               = 0U;

  rmap_new( s->map );

  /* Not a good place to put this, but there's not really a better place
     for it either.  The compiler should eliminate it. */
  FD_TEST( rmap_footprint()==sizeof(s->map) );
  return mem;
}

#define HEADROOM (FD_PACK_REBATE_SUM_CAPACITY-MAX_TXN_PER_MICROBLOCK*FD_TXN_ACCT_ADDR_MAX)

ulong
fd_pack_rebate_sum_add_txn( fd_pack_rebate_sum_t         * s,
                            fd_txn_p_t     const         * txns,
                            fd_acct_addr_t const * const * adtl_writable,
                            ulong                          txn_cnt ) {
  /* See end of function for this equation */
  if( FD_UNLIKELY( txn_cnt==0UL ) ) return (ulong)((fd_int_max( 0, (int)s->writer_cnt - (int)HEADROOM ) + 1636) / 1637);

  int is_initializer_bundle = 1;
  int ib_success            = 1;
  int any_in_block          = 0;

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t const * txn = txns+i;
    ulong rebated_cus   = txn->bank_cu.rebated_cus;
    int   in_block      = !!(txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS);

    /* For IB purposes, treat AlreadyProcessed (7) as success.  If one
       transaction is an initializer bundle, they all must be, so it's
       unclear if the first line should be an |= or an &=, but &= seems
       more right. */
    is_initializer_bundle &= !!(txn->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE);
    ib_success            &= in_block | ((txn->flags&FD_TXN_P_FLAGS_RESULT_MASK)==(7U<<24));
    any_in_block          |= in_block;

    s->total_cost_rebate += rebated_cus;
    s->vote_cost_rebate  += fd_ulong_if( txn->flags & FD_TXN_P_FLAGS_IS_SIMPLE_VOTE, rebated_cus,     0UL );
    s->data_bytes_rebate += fd_ulong_if( !in_block,                                  txn->payload_sz, 0UL );

    if( FD_UNLIKELY( rebated_cus==0UL ) ) continue;

    fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( TXN(txn), txn->payload );
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( TXN(txn), FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {

      ulong j=fd_txn_acct_iter_idx( iter );

      fd_pack_rebate_entry_t * in_table = rmap_query( s->map, accts[j], NULL );
      if( FD_UNLIKELY( !in_table ) ) {
        in_table = rmap_insert( s->map, accts[j] );
        in_table->rebate_cus = 0UL;
        s->inserted[ s->writer_cnt++ ] = in_table;
      }
      in_table->rebate_cus += rebated_cus;
    }
    if( FD_LIKELY( txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) {
      accts = adtl_writable[i];
      for( ulong j=0UL; j<(ulong)TXN(txn)->addr_table_adtl_writable_cnt; j++ ) {
        fd_pack_rebate_entry_t * in_table = rmap_query( s->map, accts[j], NULL );
        if( FD_UNLIKELY( !in_table ) ) {
          in_table = rmap_insert( s->map, accts[j] );
          in_table->rebate_cus = 0UL;
          s->inserted[ s->writer_cnt++ ] = in_table;
        }
        in_table->rebate_cus += rebated_cus;
      }
    }
    FD_TEST( s->writer_cnt<=FD_PACK_REBATE_SUM_CAPACITY );
  }

  int is_bundle = txns->flags & FD_TXN_P_FLAGS_BUNDLE; /* can't mix bundle and non-bundle */
  ulong microblock_cnt_rebate = fd_ulong_if( any_in_block, 0UL, fd_ulong_if( is_bundle, txn_cnt, 1UL ) );
  s->microblock_cnt_rebate += microblock_cnt_rebate;
  s->data_bytes_rebate     += microblock_cnt_rebate*48UL; /* microblock headers */

  if( FD_UNLIKELY( is_initializer_bundle & (s->ib_result!=-1) ) ) { /* if in -1 state, stay. Shouldn't be possible */
    s->ib_result = fd_int_if( ib_success, 1, -1 );
  }

  /* We want to make sure that we have enough capacity to insert 31*128
     addresses without hitting 5k.  Thus, if x is the current value of
     writer_cnt, we need to call report at least y times to ensure
                        x-y*1637 <= 5*1024-31*128
                               y >= (x-1152)/1637
     but y is an integer, so y >= ceiling( (x-1152)/1637 ) */
  return (ulong)((fd_int_max( 0, (int)s->writer_cnt - (int)HEADROOM ) + 1636) / 1637);
}


ulong
fd_pack_rebate_sum_report( fd_pack_rebate_sum_t * s,
                           fd_pack_rebate_t     * out ) {
  if( FD_UNLIKELY( (s->ib_result==0) & (s->total_cost_rebate==0UL) & (s->writer_cnt==0U) ) ) return 0UL;
  out->total_cost_rebate       = s->total_cost_rebate;          s->total_cost_rebate       = 0UL;
  out->vote_cost_rebate        = s->vote_cost_rebate;           s->vote_cost_rebate        = 0UL;
  out->data_bytes_rebate       = s->data_bytes_rebate;          s->data_bytes_rebate       = 0UL;
  out->microblock_cnt_rebate   = s->microblock_cnt_rebate;      s->microblock_cnt_rebate   = 0UL;
  out->ib_result               = s->ib_result;                  s->ib_result               = 0;

  out->writer_cnt = 0U;
  ulong writer_cnt = fd_ulong_min( s->writer_cnt, 1637UL );
  for( ulong i=0UL; i<writer_cnt; i++ ) {
    fd_pack_rebate_entry_t * e = s->inserted[ --(s->writer_cnt) ];
    out->writer_rebates[ out->writer_cnt++ ] = *e;
    rmap_remove( s->map, e );
  }

  return sizeof(*out)-sizeof(fd_pack_rebate_entry_t)+(out->writer_cnt)*sizeof(fd_pack_rebate_entry_t);
}

void
fd_pack_rebate_sum_clear( fd_pack_rebate_sum_t * s ) {
  s->total_cost_rebate       = 0UL;
  s->vote_cost_rebate        = 0UL;
  s->data_bytes_rebate       = 0UL;
  s->microblock_cnt_rebate   = 0UL;
  s->ib_result               = 0;

  ulong writer_cnt = s->writer_cnt;
  for( ulong i=0UL; i<writer_cnt; i++ ) {
    fd_pack_rebate_entry_t * e = s->inserted[ --(s->writer_cnt) ];
    rmap_remove( s->map, e );
  }
}
