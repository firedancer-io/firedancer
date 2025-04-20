#include "fd_dns_tile.h"
#include "../metrics/fd_metrics.h"
#include "../../tango/tempo/fd_tempo.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <unistd.h>

static void
resolve_domain( fd_dns_tile_t *      ctx,
                fd_dns_tile_task_t * task ) {
  struct addrinfo hints;
  memset( &hints, 0, sizeof(hints) );
  hints.ai_family   = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags    = AI_V4MAPPED|AI_ALL;

  struct addrinfo * res = NULL;
  int err = getaddrinfo( task->name, NULL, &hints, &res );
  ctx->metrics.gai_cnt++;
  if( FD_UNLIKELY( err ) ) {
    if( FD_UNLIKELY( err!=task->gai_err_cache ) ) {
      FD_LOG_WARNING(( "getaddrinfo(%s %d) failed for (%i-%s)", task->name, task->name_len, err, gai_strerror( err ) ) );
    }
    ctx->metrics.gai_err_cnt++;
    return;
  }
  task->gai_err_cache = err;

  uchar * ip6_cur         = ctx->ip6_scratch;
  uchar * ip6_scratch_end = ctx->ip6_scratch + sizeof(ctx->ip6_scratch);
  ulong hash = 0UL;
  for(
      struct addrinfo * rp=res;
      rp && ip6_cur+16<=ip6_scratch_end;
      rp=rp->ai_next
  ) {
    if( FD_UNLIKELY( rp->ai_family!=AF_INET6 ) ) continue;
    struct sockaddr_in6 const * addr6 = fd_type_pun_const( rp->ai_addr );
    memcpy( ip6_cur, addr6->sin6_addr.s6_addr, 16UL );
    hash ^= fd_hash( 0UL, ip6_cur, 16UL );
    ip6_cur += 16;
  }
  ulong ip6_addr_cnt = (ulong)( ip6_cur - ctx->ip6_scratch )>>4;

  if( FD_UNLIKELY( hash != task->val_hash ) ) {
    FD_LOG_INFO(( "Updated DNS records for %.*s", (int)task->name_len, task->name ) );
    task->val_hash = hash;
    ctx->metrics.addr_set_change_cnt++;
  }

  long resolve_time = fd_log_wallclock();
  fd_dns_cache_put( ctx->cache, task->name, task->name_len, resolve_time, ctx->ip6_scratch, ip6_addr_cnt );

  freeaddrinfo( res );
}

static void
resolve_all_domains( fd_dns_tile_t * ctx ) {
  long start = fd_log_wallclock();

  for( ulong i=0UL; i<ctx->task_cnt; i++ ) {
    resolve_domain( ctx, ctx->tasks+i );
  }

  ctx->resolve_next = fd_log_wallclock() + (long)fd_tempo_async_reload( ctx->rng, ctx->resolve_async_min );
  ctx->metrics.last_refresh = (ulong)start / (ulong)1e9;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->in_cnt  ) ) FD_LOG_ERR(( "dns tile has unexpected in links"  ));
  if( FD_UNLIKELY( tile->out_cnt ) ) FD_LOG_ERR(( "dns tile has unexpected out links" ));

  fd_dns_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_dns_tile_t) );
  if( FD_UNLIKELY( !fd_dns_cache_join( fd_topo_obj_laddr( topo, tile->dns.dns_cache_obj_id ), ctx->cache ) ) ) {
    FD_LOG_ERR(( "fd_dns_cache_join failed" ));
  }

  uint rng_seed;
  if( FD_UNLIKELY( !fd_rng_secure( &rng_seed, sizeof(uint) ) ) ) FD_LOG_ERR(( "fd_rng_secure failed" ));
  fd_rng_new( ctx->rng, rng_seed, 0UL );

  /* Register bundle endpoint URL's domain name as a resolve task */
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->tasks[0].name ), tile->dns.bundle_domain, tile->dns.bundle_domain_len ) );
  ctx->tasks[ 0 ].name_len = (uchar)tile->dns.bundle_domain_len;
  ctx->task_cnt = 1UL;

  /* Refresh DNS records every 30s to 64.3s. */
  ctx->resolve_async_min = (ulong)30e9;
  ctx->resolve_next      = 0L; /* query domains in next housekeep */
}

static void
during_housekeeping( fd_dns_tile_t * ctx ) {
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now > ctx->resolve_next ) ) {
    resolve_all_domains( ctx );
  }
}

static void
metrics_write( fd_dns_tile_t * ctx ) {
  FD_MCNT_SET  ( DNS, ADDRESS_LOOKUPS,      ctx->metrics.gai_cnt             );
  FD_MCNT_SET  ( DNS, ADDRESS_LOOKUP_FAILS, ctx->metrics.gai_err_cnt         );
  FD_MCNT_SET  ( DNS, ADDRESS_CHANGES,      ctx->metrics.addr_set_change_cnt );
  FD_MGAUGE_SET( DNS, LAST_REFRESH,         ctx->metrics.last_refresh        );
}

#define STEM_BURST 0
#define STEM_LAZY ((long)10e6) /* 10ms */
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_dns_tile_t)
#define STEM_CALLBACK_CONTEXT_TYPE        fd_dns_tile_t
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_dns = {
  .name              = "dns",
  .scratch_align     = NULL,
  .scratch_footprint = NULL,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
  .disable_sandbox   = 1,
};
