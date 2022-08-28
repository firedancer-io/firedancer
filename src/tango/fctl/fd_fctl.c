#include "fd_fctl.h"

void *
fd_fctl_new( void * shmem,
             ulong  rx_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_fctl_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( rx_max>FD_FCTL_RX_MAX_MAX ) ) {
    FD_LOG_WARNING(( "too large rx_max" ));
    return NULL;
  }

  fd_fctl_t * fctl = (fd_fctl_t *)shmem;

  fctl->rx_max    = (ushort)rx_max;
  fctl->rx_cnt    = (ushort)0;
  fctl->in_refill = 0;
  fctl->cr_burst  = 0UL;
  fctl->cr_max    = 0UL;
  fctl->cr_resume = 0UL;
  fctl->cr_refill = 0UL;

  return shmem;
}

fd_fctl_t *
fd_fctl_cfg_rx_add( fd_fctl_t *   fctl,
                    ulong         cr_max,
                    ulong const * seq_laddr,
                    ulong *       slow_laddr ) {
  if( FD_UNLIKELY( !fctl ) ) {
    FD_LOG_WARNING(( "NULL fctl" ));
    return NULL;
  }

  if( FD_UNLIKELY( !cr_max ) ) {
    FD_LOG_WARNING(( "too small cr_max" ));
    return NULL;
  }

  if( FD_UNLIKELY( cr_max > (ulong)LONG_MAX ) ) {
    FD_LOG_WARNING(( "too large cr_max" ));
    return NULL;
  }

  /* NULL seq_laddr okay (indicates disabled for time being) */

  if( FD_UNLIKELY( !slow_laddr ) ) {
    FD_LOG_WARNING(( "NULL slow_laddr" ));
    return NULL;
  }

  ulong rx_idx = (ulong)fctl->rx_cnt;
  if( FD_UNLIKELY( rx_idx>=(ulong)fctl->rx_max ) ) {
    FD_LOG_WARNING(( "too many rx in this fctl" ));
    return NULL;
  }

  fd_fctl_private_rx_t * rx = fd_fctl_private_rx( fctl );
  rx[ rx_idx ].cr_max     = (long)cr_max;
  rx[ rx_idx ].seq_laddr  = seq_laddr;
  rx[ rx_idx ].slow_laddr = slow_laddr;

  fctl->rx_cnt = (ushort)(rx_idx+1UL);
  return fctl;
}

fd_fctl_t *
fd_fctl_cfg_done( fd_fctl_t * fctl,
                  ulong       cr_burst,
                  ulong       cr_max,
                  ulong       cr_resume,
                  ulong       cr_refill ) {
  if( FD_UNLIKELY( !fctl ) ) {
    FD_LOG_WARNING(( "NULL fctl" ));
    return NULL;
  }

  fd_fctl_private_rx_t * rx     = fd_fctl_private_rx( fctl );
  ulong                  rx_cnt = (ulong)fctl->rx_cnt;

  ulong cr_burst_max = (ulong)LONG_MAX;
  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) cr_burst_max = fd_ulong_min( cr_burst_max, (ulong)rx[rx_idx].cr_max );
  /* cr_burst_max is min( LONG_MAX, rx[:].cr_max ), which is in [1,LONG_MAX] as rx[:].cr_max is positive */

  if( FD_UNLIKELY( !((1UL<=cr_burst) & (cr_burst<=cr_burst_max)) ) ) {
    FD_LOG_WARNING(( "cr_burst (%lu) must be in [%lu,%lu] for receiver config", cr_burst, 1UL, cr_burst_max ));
    return NULL;
  }

  /* At this point, cr_burst is in [1,cr_burst_max], which is in [1,LONG_MAX] */

  if( !cr_max ) {
    cr_max = cr_burst_max;
    for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) cr_max = fd_ulong_max( cr_max, (ulong)rx[rx_idx].cr_max );
    /* cr_max is in [cr_burst,LONG_MAX] as rx[:].cr_max is positive */
  }

  if( FD_UNLIKELY( !((cr_burst<=cr_max) & (cr_max<=((ulong)LONG_MAX))) ) ) {
    FD_LOG_WARNING(( "cr_max (%lu) must be in [%lu,%lu] for receiver config", cr_max, cr_burst, (ulong)LONG_MAX ));
    return NULL;
  }

  /* cr_max is in [cr_burst,LONG_MAX] at this point */

  if( !cr_resume ) cr_resume = cr_burst + ((2UL*(cr_max-cr_burst))/3UL); /* no ovfl possible */

  if( FD_UNLIKELY( !((cr_burst<=cr_resume) & (cr_resume<=cr_max)) ) ) {
    FD_LOG_WARNING(( "cr_resume (%lu) must be in [%lu,%lu] for receiver config", cr_resume, cr_burst, cr_max ));
    return NULL;
  }

  /* cr_resume is in [cr_burst,cr_max] at this point */

  if( !cr_refill ) cr_refill = cr_burst + ((cr_resume-cr_burst)>>1); /* no ovfl possible */

  if( FD_UNLIKELY( !((cr_burst<=cr_refill) & (cr_refill<=cr_resume)) ) ) {
    FD_LOG_WARNING(( "cr_refill (%lu) must be in [%lu,%lu] for receiver config", cr_refill, cr_burst, cr_resume ));
    return NULL;
  }

  /* cr_refill is in [cr_burst,cr_resume] at this point */

  fctl->cr_burst  = cr_burst;
  fctl->cr_max    = cr_max;
  fctl->cr_resume = cr_resume;
  fctl->cr_refill = cr_refill;

  return fctl;
}

