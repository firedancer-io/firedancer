#include "../../util/pod/fd_pod_format.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/store/fd_store.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"
#include "../../flamenco/progcache/fd_progcache.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../discof/backup/fd_backup_shmem.h"
#include "../../discof/restore/utils/fd_snapin_io.h"

#include "../../discof/admin/fd_adminctl.h"

#define VAL(name) (__extension__({                                                             \
  ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
  if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
  __x; }))

static ulong
banks_footprint( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  return fd_banks_footprint( VAL("max_live_slots"), VAL("max_fork_width"), FD_RUNTIME_MAX_STAKE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS_FALLBACK, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
}

static ulong
banks_align( fd_topo_t const *     topo FD_FN_UNUSED,
             fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_banks_align();
}

static void
banks_new( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  int larger_max_cost_per_block = fd_pod_queryf_int( topo->props, 0, "obj.%lu.larger_max_cost_per_block", obj->id );
  ulong seed = fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.seed", obj->id );
  FD_TEST( fd_banks_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_live_slots"), VAL("max_fork_width"), FD_RUNTIME_MAX_STAKE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS_FALLBACK, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, larger_max_cost_per_block, seed ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_banks = {
  .name      = "banks",
  .footprint = banks_footprint,
  .align     = banks_align,
  .new       = banks_new,
};

static ulong
progcache_align( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_progcache_shmem_align();
}

static ulong
progcache_footprint( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj ) {
  return fd_progcache_shmem_footprint( VAL("txn_max"), VAL("rec_max") );
}

static ulong
progcache_loose( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  return VAL("heap_max");
}

static void
progcache_new( fd_topo_t const *     topo,
               fd_topo_obj_t const * obj ) {
  ulong seed = fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.seed", obj->id );
  if( !seed ) FD_TEST( fd_rng_secure( &seed, sizeof(ulong) ) );
  FD_TEST( fd_progcache_shmem_new( fd_topo_obj_laddr( topo, obj->id ), 2UL, seed, VAL("txn_max"), VAL("rec_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_progcache = {
  .name      = "progcache",
  .footprint = progcache_footprint,
  .loose     = progcache_loose,
  .align     = progcache_align,
  .new       = progcache_new,
};

/* adminctl: admin tile command channel */

static ulong
adminctl_align( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_adminctl_align();
}

static ulong
adminctl_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_adminctl_footprint();
}

static void
adminctl_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_adminctl_new( fd_topo_obj_laddr( topo, obj->id ) ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_adminctl = {
  .name      = "adminctl",
  .footprint = adminctl_footprint,
  .align     = adminctl_align,
  .new       = adminctl_new,
};

static ulong
fec_sets_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return VAL("sz");
}

static ulong
fec_sets_align( fd_topo_t const *     topo FD_FN_UNUSED,
                  fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_dcache_align();
}

static void
fec_sets_new( FD_PARAM_UNUSED fd_topo_t const *     topo,
              FD_PARAM_UNUSED fd_topo_obj_t const * obj ) {
  FD_TEST( fd_topo_obj_laddr( topo, obj->id ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_fec_sets = {
  .name      = "fec_sets",
  .footprint = fec_sets_footprint,
  .align     = fec_sets_align,
  .new       = fec_sets_new,
};

static ulong
store_footprint( fd_topo_t const * topo,
                 fd_topo_obj_t const * obj ) {
  return fd_store_footprint( VAL("fec_max"), VAL("fec_data_max") );
}

static ulong
store_align( fd_topo_t const *     topo FD_FN_UNUSED,
             fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_store_align();
}

static void
store_new( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  FD_TEST( fd_store_new( fd_topo_obj_laddr( topo, obj->id ), VAL("part_cnt"), VAL("fec_max"), VAL("fec_data_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_store = {
  .name      = "store",
  .footprint = store_footprint,
  .align     = store_align,
  .new       = store_new,
};

static ulong
accdb_footprint( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  return fd_accdb_shmem_footprint( VAL("max_accounts"), VAL("max_live_slots"), VAL("max_account_writes_per_slot"), VAL("partition_cnt"), VAL("cache_footprint"), VAL("cache_min_reserved"), VAL("joiner_cnt"), VAL("max_incremental_accounts") );
}

static ulong
accdb_align( fd_topo_t const *     topo FD_FN_UNUSED,
             fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_accdb_shmem_align();
}

static void
accdb_new( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  FD_TEST( fd_accdb_shmem_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_accounts"), VAL("max_live_slots"), VAL("max_account_writes_per_slot"), VAL("partition_cnt"), VAL("partition_sz"), VAL("cache_footprint"), VAL("cache_min_reserved"), (int)VAL("bundle_enabled"), VAL("seed"), VAL("joiner_cnt"), VAL("max_incremental_accounts") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_accdb = {
  .name      = "accdb",
  .footprint = accdb_footprint,
  .align     = accdb_align,
  .new       = accdb_new,
};

static ulong
txncache_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  int larger_max_cost_per_block = fd_pod_queryf_int( topo->props, 0, "obj.%lu.larger_max_cost_per_block", obj->id );
  return fd_txncache_shmem_footprint( VAL("max_live_slots"), VAL("max_txn_per_slot"), larger_max_cost_per_block );
}

static ulong
txncache_align( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_txncache_shmem_align();
}

static void
txncache_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  int larger_max_cost_per_block = fd_pod_queryf_int( topo->props, 0, "obj.%lu.larger_max_cost_per_block", obj->id );
  FD_TEST( fd_txncache_shmem_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_live_slots"), VAL("max_txn_per_slot"), larger_max_cost_per_block, VAL("seed") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_txncache = {
  .name      = "txncache",
  .footprint = txncache_footprint,
  .align     = txncache_align,
  .new       = txncache_new,
};

static ulong
rnonce_ss_footprint( fd_topo_t const *     topo FD_FN_UNUSED,
                     fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return sizeof(fd_rnonce_ss_t);
}

static ulong
rnonce_ss_align( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return alignof(fd_rnonce_ss_t);
}

static void
rnonce_ss_new( fd_topo_t const *     topo,
               fd_topo_obj_t const * obj ) {
  FD_TEST( fd_rng_secure( fd_topo_obj_laddr( topo, obj->id ), sizeof(fd_rnonce_ss_t) ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_rnonce_ss = {
  .name      = "rnonce_ss",
  .footprint = rnonce_ss_footprint,
  .align     = rnonce_ss_align,
  .new       = rnonce_ss_new,
};

static ulong
backup_footprint_cb( fd_topo_t const *     topo,
                         fd_topo_obj_t const * obj ) {
  return fd_backup_footprint( VAL("max_accounts") );
}

static ulong
backup_align_cb( fd_topo_t const *     topo FD_FN_UNUSED,
                     fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_backup_align();
}

static void
backup_new_cb( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  FD_TEST( fd_backup_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_accounts") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_backup = {
  .name      = "backup",
  .footprint = backup_footprint_cb,
  .align     = backup_align_cb,
  .new       = backup_new_cb,
};

static ulong
snapio_snoop_footprint_cb( fd_topo_t const *     topo,
                           fd_topo_obj_t const * obj ) {
  return fd_snapio_snoop_footprint( VAL("worker_cnt") );
}

static ulong
snapio_snoop_align_cb( fd_topo_t const *     topo FD_FN_UNUSED,
                       fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_snapio_snoop_align();
}

static void
snapio_snoop_new_cb( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj ) {
  FD_TEST( fd_snapio_snoop_new( fd_topo_obj_laddr( topo, obj->id ), VAL("worker_cnt") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_snapio_snoop = {
  .name      = "snapio_snoop",
  .footprint = snapio_snoop_footprint_cb,
  .align     = snapio_snoop_align_cb,
  .new       = snapio_snoop_new_cb,
};

#undef VAL
