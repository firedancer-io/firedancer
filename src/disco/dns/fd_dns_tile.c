#include "fd_dns_tile.h"
#include "../metrics/fd_metrics.h"
#include "../../tango/tempo/fd_tempo.h"
#include "../../waltz/resolv/fd_netdb.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> /* TCP_FASTOPEN_CONNECT (seccomp) */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <unistd.h>

#include "generated/fd_dns_tile_seccomp.h"

static void
resolve_domain( fd_dns_tile_t *      ctx,
                fd_dns_tile_task_t * task ) {
  fd_addrinfo_t hints;
  memset( &hints, 0, sizeof(hints) );
  hints.ai_family = AF_INET6;
  hints.ai_flags  = FD_AI_V4MAPPED|FD_AI_ALL;

  uchar out_mem[ 4096 ];
  void * pout = out_mem;

  fd_addrinfo_t * res = NULL;
  int err = fd_getaddrinfo( task->name, &hints, &res, &pout, sizeof(out_mem) );
  ctx->metrics.gai_cnt++;
  if( FD_UNLIKELY( err ) ) {
    if( FD_UNLIKELY( err!=task->gai_err_cache ) ) {
      FD_LOG_WARNING(( "fd_getaddrinfo(%s) failed for (%i-%s)", task->name, err, fd_gai_strerror( err ) ) );
    }
    ctx->metrics.gai_err_cnt++;
    return;
  }
  task->gai_err_cache = err;

  uchar * ip6_cur         = ctx->ip6_scratch;
  uchar * ip6_scratch_end = ctx->ip6_scratch + sizeof(ctx->ip6_scratch);
  ulong hash = 0UL;
  for(
      fd_addrinfo_t * rp=res;
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

  long resolve_time_nanos = fd_log_wallclock();
  fd_dns_cache_put( ctx->cache, task->name, task->name_len, resolve_time_nanos, ctx->ip6_scratch, ip6_addr_cnt );
}

static void
resolve_all_domains( fd_dns_tile_t * ctx ) {
  long start = fd_log_wallclock();

  for( ulong i=0UL; i<ctx->task_cnt; i++ ) {
    resolve_domain( ctx, ctx->tasks+i );
  }

  ctx->resolve_next_nanos = fd_log_wallclock() + (long)fd_tempo_async_reload( ctx->rng, ctx->resolve_async_min );
  ctx->metrics.last_refresh = (ulong)start / (ulong)1e9;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_dns_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_dns_tile_t) );

  uint rng_seed;
  if( FD_UNLIKELY( !fd_rng_secure( &rng_seed, sizeof(uint) ) ) ) FD_LOG_ERR(( "fd_rng_secure failed" ));
  fd_rng_new( ctx->rng, rng_seed, 0UL );

  /* Init resolver */
  if( FD_UNLIKELY( !fd_netdb_open_fds( ctx->netdb_fds ) ) ) {
    FD_LOG_ERR(( "fd_netdb_open_fds failed" ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_dns_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( tile->in_cnt  ) ) FD_LOG_ERR(( "dns tile has unexpected in links"  ));
  if( FD_UNLIKELY( tile->out_cnt ) ) FD_LOG_ERR(( "dns tile has unexpected out links" ));

  if( FD_UNLIKELY( !fd_dns_cache_join( fd_topo_obj_laddr( topo, tile->dns.dns_cache_obj_id ), ctx->cache ) ) ) {
    FD_LOG_ERR(( "fd_dns_cache_join failed" ));
  }

  /* Register bundle endpoint URL's domain name as a resolve task */
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->tasks[0].name ), tile->dns.bundle_domain, tile->dns.bundle_domain_len ) );
  ctx->tasks[ 0 ].name_len = (uchar)tile->dns.bundle_domain_len;
  ctx->task_cnt = 1UL;

  /* Refresh DNS records every 30s to 64.3s. */
  ctx->resolve_async_min  = (ulong)30e9;
  ctx->resolve_next_nanos = 0L; /* query domains in next housekeep */
}

FD_FN_CONST static ulong
scratch_align( void ) {
  return alignof(fd_dns_tile_t);
}

FD_FN_CONST static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_dns_tile_t);
}

static void
during_housekeeping( fd_dns_tile_t * ctx ) {
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now > ctx->resolve_next_nanos ) ) {
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

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_dns_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_dns_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->netdb_fds->etc_hosts,
      (uint)ctx->netdb_fds->etc_resolv_conf
  );
  return sock_filter_policy_fd_dns_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_dns_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->netdb_fds->etc_hosts >= 0 ) )
    out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_hosts;
  out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_resolv_conf;
  return out_cnt;
}

#define STEM_BURST 0
#define STEM_LAZY ((long)10e6) /* 10ms */
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_dns_tile_t)
#define STEM_CALLBACK_CONTEXT_TYPE        fd_dns_tile_t
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_dns = {
  .name                     = "dns",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .rlimit_file_cnt          = 64,
  .keep_host_networking     = 1
};
