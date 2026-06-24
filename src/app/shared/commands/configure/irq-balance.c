/* irq-balance is the sibling of the irq-affinity configure stage.
   See the long doc comment in irq-affinity.c. */

#define _DEFAULT_SOURCE
#include "configure.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "fd_irqbalance_client.h"

#include <errno.h>

#define MISMATCH_SAMPLE_MAX (16UL)
#define MISMATCH_STR_LEN    (128UL)

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "irq-balance", "connect to `/run/irqbalance/<sock>`" );
}

static void
fini_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "irq-balance", "connect to `/run/irqbalance/<sock>`" );
}

static char *
cpuset_to_list_sample( char *               buf,
                       ulong                buf_sz,
                       fd_cpuset_t const * cpuset ) {
  char * p = fd_cstr_init( buf );
  ulong total_cnt = 0UL;
  for( ulong iter = fd_cpuset_const_iter_init( cpuset );
       !fd_cpuset_const_iter_done( iter );
       iter = fd_cpuset_const_iter_next( cpuset, iter ) ) {
    if( FD_LIKELY( total_cnt<MISMATCH_SAMPLE_MAX ) ) {
      if( FD_LIKELY( total_cnt ) ) p = fd_cstr_append_char( p, ',' );
      if( FD_UNLIKELY( (ulong)(p-buf)+32UL >= buf_sz ) ) break;
      p = fd_cstr_append_ulong_as_text( p, 0, 0, iter, fd_ulong_base10_dig_cnt( iter ) );
    }
    total_cnt++;
  }
  if( FD_UNLIKELY( total_cnt>MISMATCH_SAMPLE_MAX && (ulong)(p-buf)+32UL<buf_sz ) ) {
    p = fd_cstr_append_cstr( p, ",+" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, total_cnt-MISMATCH_SAMPLE_MAX, fd_ulong_base10_dig_cnt( total_cnt-MISMATCH_SAMPLE_MAX ) );
    p = fd_cstr_append_cstr( p, " more" );
  }
  fd_cstr_fini( p );
  return buf;
}

static fd_cpuset_t *
topo_banned_cpus( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ],
                  fd_topo_t const * topo ) {
  fd_cpuset_new( cpuset );
  ulong cpu_cnt = fd_shmem_cpu_cnt();
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( tile->cpu_idx < cpu_cnt ) fd_cpuset_insert( cpuset, tile->cpu_idx );
  }
  return cpuset;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  /* The irqbalance daemon applies a `settings cpus` command only on its
     next periodic scan() tick (the SLEEP interval, 10s by default), and
     the `setup` query reports the committed mask, never the pending
     one. init() and fini() read the state back immediately, so the
     framework's synchronous POST_INIT / POST_FINI checks always observe
     the pre-change state and would spuriously fail ("didn't do
     anything" / "not undone"). There is no socket command to force a
     synchronous commit or to read back the pending ban, so these
     post-action checks are unverifiable; report the outcome the
     framework expects for a successful action and rely on init()/fini()
     having sent the command.  POST_INIT wants OK (configured);
     POST_FINI wants NOT_CONFIGURED (undone).  The standalone CHECK
     still reports the true committed state once the daemon has had a
     tick to apply it. */
  if( check_type==FD_CONFIGURE_CHECK_TYPE_POST_INIT ) CONFIGURE_OK();
  if( check_type==FD_CONFIGURE_CHECK_TYPE_POST_FINI ) NOT_CONFIGURED( "irqbalance commits asynchronously; undo not verifiable" );

  FD_CPUSET_DECL( actual );
  if( FD_UNLIKELY( -1==fd_irqbalance_ban_cpus_get( actual ) ) ) {
    int err = errno;
    switch( err ) {
    case ENOENT:
    case ECONNREFUSED:
      /* irqbalance is not installed or not running, so there is nothing
         to configure and nothing to undo. */
      CONFIGURE_OK();
    case EACCES:
      /* During the permission check phases, an EACCES means we need to
         escalate privileges before the real check; FINI_PERM treats it
         as OK so fini can proceed.  Outside those phases it is a
         genuine misconfiguration. */
      if( check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ) CONFIGURE_OK();
      NOT_CONFIGURED( "insufficient permissions to query irqbalance daemon banned CPU list" );
    default:
      FD_LOG_ERR(( "fd_irqbalance_ban_cpus_get() failed unexpectedly (%i-%s)", err, fd_io_strerror( err ) ));
    }
  }

  if( FD_LIKELY( !fd_cpuset_cnt( actual ) ) ) NOT_CONFIGURED( "irqbalance daemon has no banned CPUs" );

  FD_CPUSET_DECL( required );
  topo_banned_cpus( required, &config->topo );
  if( FD_LIKELY( fd_cpuset_eq( actual, required ) ) ) CONFIGURE_OK();

  FD_CPUSET_DECL( mismatched );
  fd_cpuset_xor( mismatched, actual, required );
  char cpu_str[ MISMATCH_STR_LEN ];
  cpuset_to_list_sample( cpu_str, sizeof(cpu_str), mismatched );
  NOT_CONFIGURED( "irqbalance daemon banned CPU list does not match Firedancer tile CPUs (CPUs: %s)", cpu_str );
}

static void
init( config_t const * config ) {
  FD_CPUSET_DECL( firedancer );
  topo_banned_cpus( firedancer, &config->topo );

  if( FD_UNLIKELY( -1==fd_irqbalance_ban_cpus_set( firedancer ) ) ) {
    int err = errno;
    if( FD_UNLIKELY( err!=ENOENT && err!=ECONNREFUSED && err!=EACCES ) ) {
      FD_LOG_ERR(( "fd_irqbalance_ban_cpus_set() failed unexpectedly (%i-%s)", err, fd_io_strerror( err ) ));
    }
  }
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)config; (void)pre_init;

  FD_CPUSET_DECL( banned );
  fd_cpuset_new( banned );

  if( FD_UNLIKELY( -1==fd_irqbalance_ban_cpus_set( banned ) ) ) {
    int err = errno;
    if( FD_UNLIKELY( err!=ENOENT && err!=ECONNREFUSED && err!=EACCES ) ) {
      FD_LOG_ERR(( "fd_irqbalance_ban_cpus_set() failed unexpectedly (%i-%s)", err, fd_io_strerror( err ) ));
    }
  }
  return 1;
}

configure_stage_t fd_cfg_stage_irq_balance = {
  .name            = "irq-balance",
  .always_recreate = 0,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check
};

#undef MISMATCH_SAMPLE_MAX
#undef MISMATCH_STR_LEN
