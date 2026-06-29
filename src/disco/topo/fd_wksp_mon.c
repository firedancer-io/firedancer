#include "fd_wksp_mon.h"
#include "../../tango/tempo/fd_tempo.h"
#include "../../util/wksp/fd_wksp_private.h"
#include <stddef.h>

#if FD_HAS_AVX
#include <immintrin.h>
#endif

fd_wksp_mon_t *
fd_wksp_mon_init( fd_wksp_mon_t * mon,
                  fd_wksp_t *     wksp,
                  ulong           bytes_per_sec,
                  long            now ) {
  fd_memset( mon, 0, sizeof(fd_wksp_mon_t) );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ticks_per_byte = tick_per_ns * 1e9 / (double)bytes_per_sec;
  ulong  ticks_per_part = (ulong)(ticks_per_byte * (double)FD_WKSP_PRIVATE_PINFO_FOOTPRINT);

  /* Ensure at most 5 full sweeps per second by lowering the effective
     rate for small workspaces.  min_ticks_per_part is the rate at which
     a full sweep takes exactly 200ms. */

  ulong part_max = wksp->part_max;
  FD_TEST( part_max );
  ulong min_ticks_per_part = (ulong)(tick_per_ns * 200e6 / (double)part_max);
  if( ticks_per_part<min_ticks_per_part ) ticks_per_part = min_ticks_per_part;
  if( FD_UNLIKELY( !ticks_per_part ) ) ticks_per_part = 1UL;

  mon->wksp           = wksp;
  mon->part_max       = part_max;
  mon->ticks_per_part = ticks_per_part;
  mon->last_tick      = now;
  return mon;
}

void *
fd_wksp_mon_fini( fd_wksp_mon_t * mon ) {
  fd_memset( mon, 0, sizeof(fd_wksp_mon_t) );
  return (void *)mon;
}

fd_wksp_mon_t *
fd_wksp_mon_tick( fd_wksp_mon_t * mon,
                  long            now ) {

  ulong part_max = mon->part_max;

  mon->tick_rem += (now - mon->last_tick);
  mon->last_tick = now;

  if( FD_UNLIKELY( !part_max ) ) return mon;

  ulong ticks_per_part = mon->ticks_per_part;
  if( FD_UNLIKELY( mon->tick_rem<(long)ticks_per_part ) ) return mon;

  ulong part_budget = (ulong)mon->tick_rem / ticks_per_part;
  part_budget = fd_ulong_min( part_budget, FD_WKSP_MON_BURST_MAX );

  ulong scan_idx = mon->scan_idx;
  part_budget = fd_ulong_min( part_budget, part_max - scan_idx );

  mon->tick_rem -= (long)(part_budget * ticks_per_part);

  fd_wksp_private_pinfo_t const * pinfo = fd_wksp_private_pinfo_const( mon->wksp );

  ulong acc_free_cnt    = mon->acc_free_cnt;
  ulong acc_free_sz     = mon->acc_free_sz;
  ulong acc_free_max_sz = mon->acc_free_max_sz;
  ulong acc_used_cnt    = mon->acc_used_cnt;
  ulong acc_used_sz     = mon->acc_used_sz;

  ulong scan_end = scan_idx + part_budget;

  FD_STATIC_ASSERT( offsetof(fd_wksp_private_pinfo_t, gaddr_lo)== 0UL, layout );
  FD_STATIC_ASSERT( offsetof(fd_wksp_private_pinfo_t, gaddr_hi)== 8UL, layout );
  FD_STATIC_ASSERT( offsetof(fd_wksp_private_pinfo_t, tag     )==16UL, layout );

# if FD_HAS_AVX
  for( ulong i=scan_idx; i<scan_end; i++ ) {
    __m256i v = _mm256_stream_load_si256( (__m256i const *)(pinfo + i) );
    ulong tmp[4] __attribute__((aligned(32)));
    _mm256_store_si256( (__m256i *)tmp, v );
    ulong gaddr_lo = tmp[0];
    ulong gaddr_hi = tmp[1];
    ulong part_tag = tmp[2];
    if( FD_UNLIKELY( gaddr_hi<=gaddr_lo ) ) continue;
    ulong part_sz = gaddr_hi - gaddr_lo;
    if( !part_tag ) {
      acc_free_cnt++;
      acc_free_sz += part_sz;
      if( part_sz>acc_free_max_sz ) acc_free_max_sz = part_sz;
    } else {
      acc_used_cnt++;
      acc_used_sz += part_sz;
      mon->acc_used_hist[ fd_ulong_find_msb( part_sz ) ]++;
    }
  }
# else
  for( ulong i=scan_idx; i<scan_end; i++ ) {
    FD_COMPILER_MFENCE();
    ulong gaddr_lo = pinfo[ i ].gaddr_lo;
    ulong gaddr_hi = pinfo[ i ].gaddr_hi;
    ulong part_tag = pinfo[ i ].tag;
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( gaddr_hi<=gaddr_lo ) ) continue;
    ulong part_sz = gaddr_hi - gaddr_lo;
    if( !part_tag ) {
      acc_free_cnt++;
      acc_free_sz += part_sz;
      if( part_sz>acc_free_max_sz ) acc_free_max_sz = part_sz;
    } else {
      acc_used_cnt++;
      acc_used_sz += part_sz;
      mon->acc_used_hist[ fd_ulong_find_msb( part_sz ) ]++;
    }
  }
# endif

  mon->acc_free_cnt    = acc_free_cnt;
  mon->acc_free_sz     = acc_free_sz;
  mon->acc_free_max_sz = acc_free_max_sz;
  mon->acc_used_cnt    = acc_used_cnt;
  mon->acc_used_sz     = acc_used_sz;

  scan_idx = scan_end;
  if( scan_idx==part_max ) {
    mon->free_cnt    = acc_free_cnt;
    mon->free_sz     = acc_free_sz;
    mon->free_max_sz = acc_free_max_sz;

    /* Walk log2 histogram to find median used partition size.
       Linearly interpolate within the median bucket. */
    ulong median_sz = 0UL;
    if( acc_used_cnt ) {
      ulong half = acc_used_cnt / 2UL;
      ulong cum  = 0UL;
      ulong mb   = 0UL;
      for( ulong b=0UL; b<64UL; b++ ) {
        cum += mon->acc_used_hist[b];
        if( cum>half ) { mb = b; break; }
      }
      float lo         = (float)(1UL<<mb);
      float hi         = (mb<63UL) ? (float)(1UL<<(mb+1UL)) : lo;
      float below      = (float)(cum - mon->acc_used_hist[mb]);
      float bucket_cnt = (float)mon->acc_used_hist[mb];
      float rank       = (float)half - below;
      median_sz = (ulong)(lo + (hi - lo) * rank / bucket_cnt);
    }
    mon->part_median_sz = median_sz;
    mon->part_mean_sz   = acc_used_cnt ? (acc_used_sz / acc_used_cnt) : 0UL;

    mon->sweep_cnt++;
    mon->acc_free_cnt    = 0UL;
    mon->acc_free_sz     = 0UL;
    mon->acc_free_max_sz = 0UL;
    mon->acc_used_cnt    = 0UL;
    mon->acc_used_sz     = 0UL;
    fd_memset( mon->acc_used_hist, 0, sizeof(mon->acc_used_hist) );
    scan_idx = 0UL;
  }

  mon->scan_idx = scan_idx;
  return mon;
}
