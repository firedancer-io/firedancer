/* irq-balance is the sibling of the irq-affinity configure stage.
   See the long doc comment in irq-affinity.c. */

#define _DEFAULT_SOURCE
#include "configure.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "fd_irqbalance_client.h"

#define MISMATCH_SAMPLE_MAX (16UL)
#define MISMATCH_STR_LEN    (128UL)

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

static int
enabled( config_t const * config ) {
  return !!config->firedancer.layout.interrupts.configure_irqbalance;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  FD_CPUSET_DECL( actual );
  if( FD_UNLIKELY( !fd_irqbalance_ban_cpus_get( actual ) ) ) CONFIGURE_OK();

  if( check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ||
      check_type==FD_CONFIGURE_CHECK_TYPE_PRE_FINI  ) {
    if( FD_LIKELY( fd_cpuset_cnt( actual ) ) ) CONFIGURE_OK();
    NOT_CONFIGURED( "irqbalance daemon has no banned CPUs" );
  }

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

  if( FD_UNLIKELY( !fd_irqbalance_ban_cpus_set( firedancer ) ) )
    FD_LOG_WARNING(( "failed to update irqbalance banned CPU list" ));
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)config; (void)pre_init;

  FD_CPUSET_DECL( banned );
  fd_cpuset_new( banned );
  if( FD_UNLIKELY( !fd_irqbalance_ban_cpus_set( banned ) ) ) {
    FD_LOG_WARNING(( "failed to update irqbalance banned CPU list" ));
    return 0;
  }
  return 1;
}

configure_stage_t fd_cfg_stage_irq_balance = {
  .name            = "irq-balance",
  .always_recreate = 1,
  .enabled         = enabled,
  .init            = init,
  .fini            = fini,
  .check           = check
};

#undef MISMATCH_SAMPLE_MAX
#undef MISMATCH_STR_LEN
