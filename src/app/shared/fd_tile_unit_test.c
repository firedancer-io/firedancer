#include "fd_tile_unit_test.h"
#include "../../app/platform/fd_file_util.h"
#include "../../app/shared/fd_obj_callbacks.c"
#include "../../app/firedancer/callbacks.c"
#include "../../app/shared/fd_action.h"
#include <errno.h>    /* errno */
#include <sys/mman.h> /* MAP_FAILED */

extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;
extern fd_topo_obj_callbacks_t fd_obj_cb_store;
extern fd_topo_obj_callbacks_t fd_obj_cb_fec_sets;
extern fd_topo_obj_callbacks_t fd_obj_cb_txncache;
extern fd_topo_obj_callbacks_t fd_obj_cb_banks;
extern fd_topo_obj_callbacks_t fd_obj_cb_funk;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_mcache,
  &fd_obj_cb_dcache,
  &fd_obj_cb_fseq,
  &fd_obj_cb_metrics,
  &fd_obj_cb_dbl_buf,
  &fd_obj_cb_neigh4_hmap,
  &fd_obj_cb_fib4,
  &fd_obj_cb_keyswitch,
  &fd_obj_cb_tile,
  &fd_obj_cb_store,
  &fd_obj_cb_fec_sets,
  &fd_obj_cb_txncache,
  &fd_obj_cb_banks,
  &fd_obj_cb_funk,
  &fd_obj_cb_acc_pool,
  NULL,
};

/* Dummy tiles to fill up the topology. It works with both
   fdctl's and firedancer's topologies. */
fd_topo_run_tile_t dummy_tile_net    = { .name = "net"    };
fd_topo_run_tile_t dummy_tile_netlnk = { .name = "netlnk" };
fd_topo_run_tile_t dummy_tile_sock   = { .name = "sock"   };
fd_topo_run_tile_t dummy_tile_quic   = { .name = "quic"   };
fd_topo_run_tile_t dummy_tile_bundle = { .name = "bundle" };
fd_topo_run_tile_t dummy_tile_verify = { .name = "verify" };
fd_topo_run_tile_t dummy_tile_dedup  = { .name = "dedup"  };
fd_topo_run_tile_t dummy_tile_pack   = { .name = "pack"   };
fd_topo_run_tile_t dummy_tile_shred  = { .name = "shred"  };
fd_topo_run_tile_t dummy_tile_sign   = { .name = "sign"   };
fd_topo_run_tile_t dummy_tile_metric = { .name = "metric" };
fd_topo_run_tile_t dummy_tile_cswtch = { .name = "cswtch" };
fd_topo_run_tile_t dummy_tile_gui    = { .name = "gui"    };
fd_topo_run_tile_t dummy_tile_rpc    = { .name = "rpc"    };
fd_topo_run_tile_t dummy_tile_plugin = { .name = "plugin" };
fd_topo_run_tile_t dummy_tile_bencho = { .name = "bencho" };
fd_topo_run_tile_t dummy_tile_benchg = { .name = "benchg" };
fd_topo_run_tile_t dummy_tile_benchs = { .name = "benchs" };
fd_topo_run_tile_t dummy_tile_pktgen = { .name = "pktgen" };
fd_topo_run_tile_t dummy_tile_resolv = { .name = "resolv" };
fd_topo_run_tile_t dummy_tile_poh    = { .name = "poh"    };
fd_topo_run_tile_t dummy_tile_bank   = { .name = "bank"   };
fd_topo_run_tile_t dummy_tile_store  = { .name = "store"  };
fd_topo_run_tile_t dummy_tile_gossvf = { .name = "gossvf" };
fd_topo_run_tile_t dummy_tile_gossip = { .name = "gossip" };
fd_topo_run_tile_t dummy_tile_repair = { .name = "repair" };
fd_topo_run_tile_t dummy_tile_send   = { .name = "send"   };
fd_topo_run_tile_t dummy_tile_replay = { .name = "replay" };
fd_topo_run_tile_t dummy_tile_exec   = { .name = "exec"   };
fd_topo_run_tile_t dummy_tile_tower  = { .name = "tower"  };
fd_topo_run_tile_t dummy_tile_snapct = { .name = "snapct" };
fd_topo_run_tile_t dummy_tile_snapld = { .name = "snapld" };
fd_topo_run_tile_t dummy_tile_snapdc = { .name = "snapdc" };
fd_topo_run_tile_t dummy_tile_snapin = { .name = "snapin" };
fd_topo_run_tile_t dummy_tile_arch_f = { .name = "arch_f" };
fd_topo_run_tile_t dummy_tile_arch_w = { .name = "arch_w" };
fd_topo_run_tile_t dummy_tile_scap   = { .name = "scap"   };
fd_topo_run_tile_t dummy_tile_genesi = { .name = "genesi" };
fd_topo_run_tile_t dummy_tile_ipecho = { .name = "ipecho" };

fd_topo_run_tile_t * TILES[] = {
  NULL, /* Placeholder for tile under test (it must appear first). */
  &dummy_tile_net,
  &dummy_tile_netlnk,
  &dummy_tile_sock,
  &dummy_tile_quic,
  &dummy_tile_bundle,
  &dummy_tile_verify,
  &dummy_tile_dedup,
  &dummy_tile_pack,
  &dummy_tile_shred,
  &dummy_tile_sign,
  &dummy_tile_metric,
  &dummy_tile_cswtch,
  &dummy_tile_gui,
  &dummy_tile_rpc,
  &dummy_tile_plugin,
  &dummy_tile_bencho,
  &dummy_tile_benchg,
  &dummy_tile_benchs,
  &dummy_tile_pktgen,
  &dummy_tile_resolv,
  &dummy_tile_poh,
  &dummy_tile_bank,
  &dummy_tile_store,
  &dummy_tile_gossvf,
  &dummy_tile_gossip,
  &dummy_tile_repair,
  &dummy_tile_send,
  &dummy_tile_replay,
  &dummy_tile_exec,
  &dummy_tile_tower,
  &dummy_tile_snapct,
  &dummy_tile_snapld,
  &dummy_tile_snapdc,
  &dummy_tile_snapin,
  &dummy_tile_arch_f,
  &dummy_tile_arch_w,
  &dummy_tile_scap,
  &dummy_tile_genesi,
  &dummy_tile_ipecho,
  NULL,
};

action_t * ACTIONS[] = {
  NULL,
};

fd_topo_tile_t *
fd_tile_unit_test_init( char const *         default_topo_config_path,
                        char const *         override_topo_config_path,
                        char const *         user_topo_config_path,
                        int                  netns,
                        int                  is_firedancer,
                        int                  is_local_cluster,
                        void (*fd_topo_initialize_)(config_t *),
                        fd_topo_run_tile_t * topo_run_tile,
                        config_t *           out_config ) {
  /* The tile-under-test must be placed at index 0 in TILES. */
  TILES[0] = topo_run_tile;

  /* Default topo config. */
  char * default_config = NULL;
  ulong default_config_sz = 0UL;
  if( FD_UNLIKELY( default_topo_config_path==NULL ) ) {
    FD_LOG_WARNING(( "undefined default_config_path" ));
    return NULL;
  };
  default_config = fd_file_util_read_all( default_topo_config_path, &default_config_sz );
  if( FD_UNLIKELY( default_config==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "failed to read default config file `%s` (%d-%s)", default_topo_config_path, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  /* Override topo config. */
  char * override_config = NULL;
  ulong override_config_sz = 0UL;
  if( FD_LIKELY( override_topo_config_path ) ) {
    override_config = fd_file_util_read_all( override_topo_config_path, &override_config_sz );
    if( FD_UNLIKELY( override_config==MAP_FAILED ) ){
      FD_LOG_WARNING(( "failed to read user config file `%s` (%d-%s)", override_topo_config_path, errno, fd_io_strerror( errno ) ));
      return NULL;
    }
  }

  /* User topo config. */
  char * user_config = NULL;
  ulong user_config_sz = 0UL;
  if( FD_LIKELY( user_topo_config_path ) ) {
    user_config = fd_file_util_read_all( user_topo_config_path, &user_config_sz );
    if( FD_UNLIKELY( user_config==MAP_FAILED ) ){
      FD_LOG_WARNING(( "failed to read user config file `%s` (%d-%s)", user_topo_config_path, errno, fd_io_strerror( errno ) ));
      return NULL;
    }
  }

  /* Load config. */
  fd_memset( out_config, 0, sizeof( config_t ) ); /* This step is needed (see w->wksp check). */

  fd_config_load( is_firedancer, netns, is_local_cluster,
                  default_config, default_config_sz,
                  override_config, override_topo_config_path, override_config_sz,
                  user_config, user_config_sz, user_topo_config_path,
                  out_config );

  /* Initialize topo. */
  fd_topo_initialize_( out_config );

  /* Process test tile. */
  fd_topo_tile_t * test_tile = NULL;
  for( ulong i=0; i<out_config->topo.tile_cnt; i++ ) {
    if( !strcmp( out_config->topo.tiles[ i ].name, topo_run_tile->name ) ) {
      test_tile = &out_config->topo.tiles[ i ];
      for( ulong j=0; j<test_tile->uses_obj_cnt; j++ ) {
        if( FD_UNLIKELY( test_tile->uses_obj_id[j] >= out_config->topo.obj_cnt ) ) {
          FD_LOG_WARNING(( "test_tile->uses_obj_id[%lu] %lu exceeds config->topo.obj_cnt %lu", j, test_tile->uses_obj_id[j], out_config->topo.obj_cnt ));
          return NULL;
        }
        fd_topo_obj_t * o = &out_config->topo.objs[ test_tile->uses_obj_id[j] ];
        fd_topo_wksp_t * w = &out_config->topo.workspaces[ o->wksp_id ];
        if( FD_UNLIKELY( w->wksp != NULL ) ) continue; /* the workspace has already been initialized */
        FD_LOG_NOTICE(( "Creating workspace %s (--page-cnt %lu, --page-sz %lu, --cpu-idx %lu)", w->name, w->page_cnt, w->page_sz, fd_shmem_cpu_idx( w->numa_idx ) ));
        ulong cpu_idx = fd_shmem_cpu_idx( w->numa_idx );
        w->wksp = fd_wksp_new_anon( w->name, w->page_sz, 1UL, &w->page_cnt, &cpu_idx, 0U, w->part_max );
        // w->wksp = fd_wksp_new_anonymous( w->page_sz,  w->page_cnt, fd_shmem_cpu_idx( w->numa_idx ), w->name, 0UL );
        if( FD_UNLIKELY( w->wksp==NULL ) ) {
          FD_LOG_WARNING(( "w->wksp==NULL for o->wksp_id %lu for test_tile->uses_obj_id[%lu] %lu", o->wksp_id, j, test_tile->uses_obj_id[j] ));
          return NULL;
        }
        ulong offset = fd_wksp_alloc( w->wksp, fd_topo_workspace_align(), w->known_footprint, 1UL );
        /* TODO assert offset==gaddr_lo ? */
        if( FD_UNLIKELY( !offset ) ) {
          FD_LOG_WARNING(( "fd_wksp_alloc failed with offset %lu", offset ));
          return NULL;
        }
        fd_topo_wksp_new( &out_config->topo, w, CALLBACKS );
      }
      break;
    }
  }
  if( FD_UNLIKELY( test_tile==NULL ) ) {
    FD_LOG_WARNING(( "test_tile==NULL" ));
    return NULL;
  }
  fd_topo_fill_tile( &out_config->topo, test_tile );
  return test_tile;
}
