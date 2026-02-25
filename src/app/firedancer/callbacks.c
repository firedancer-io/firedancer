#include "../../util/pod/fd_pod_format.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/store/fd_store.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_acc_pool.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"
#include "../../funk/fd_funk.h"
#include "../../disco/shred/fd_rnonce_ss.h"

#define VAL(name) (__extension__({                                                             \
  ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
  if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
  __x; }))

static ulong
banks_locks_footprint( fd_topo_t const *     topo FD_PARAM_UNUSED,
                       fd_topo_obj_t const * obj FD_PARAM_UNUSED ) {
  return sizeof(fd_banks_locks_t);
}

static ulong
banks_locks_align( fd_topo_t const *     topo FD_PARAM_UNUSED,
                   fd_topo_obj_t const * obj FD_PARAM_UNUSED ) {
  return alignof(fd_banks_locks_t);
}

static void
banks_locks_new( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  fd_banks_locks_init( fd_topo_obj_laddr( topo, obj->id ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_banks_locks = {
  .name      = "banks_locks",
  .footprint = banks_locks_footprint,
  .align     = banks_locks_align,
  .new       = banks_locks_new,
};

static ulong
banks_footprint( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  return fd_banks_footprint( VAL("max_live_slots"), VAL("max_fork_width") );
}

static ulong
banks_align( fd_topo_t const *     topo FD_FN_UNUSED,
             fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_banks_align();
}

static void
banks_new( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  ulong seed = fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.seed", obj->id );
  FD_TEST( fd_banks_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_live_slots"), VAL("max_fork_width"), seed ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_banks = {
  .name      = "banks",
  .footprint = banks_footprint,
  .align     = banks_align,
  .new       = banks_new,
};

static ulong
funk_align( fd_topo_t const *     topo,
            fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_funk_align();
}

static ulong
funk_footprint( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  return fd_funk_shmem_footprint( VAL("txn_max"), VAL("rec_max") );
}

static ulong
funk_loose( fd_topo_t const *     topo,
            fd_topo_obj_t const * obj ) {
  return VAL("heap_max");
}

static void
funk_new( fd_topo_t const *     topo,
          fd_topo_obj_t const * obj ) {
  ulong funk_seed = fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.seed", obj->id );
  if( !funk_seed ) FD_TEST( fd_rng_secure( &funk_seed, sizeof(ulong) ) );
  FD_TEST( fd_funk_shmem_new( fd_topo_obj_laddr( topo, obj->id ), 2UL, funk_seed, VAL("txn_max"), VAL("rec_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_funk = {
  .name      = "funk",
  .footprint = funk_footprint,
  .loose     = funk_loose,
  .align     = funk_align,
  .new       = funk_new,
};

static ulong
funk_locks_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return fd_funk_locks_footprint( VAL("txn_max"), VAL("rec_max") );
}

static void
funk_locks_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  FD_TEST( fd_funk_locks_new( fd_topo_obj_laddr( topo, obj->id ), VAL("txn_max"), VAL("rec_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_funk_locks = {
  .name      = "funk_locks",
  .footprint = funk_locks_footprint,
  .align     = funk_align,
  .new       = funk_locks_new,
};

/* cnc: a tile admin message queue */

static ulong
cnc_align( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_cnc_align();
}

static ulong
cnc_footprint( fd_topo_t const *     topo,
               fd_topo_obj_t const * obj ) {
  return fd_cnc_footprint( VAL("app_sz") );
}

static void
cnc_new( fd_topo_t const *     topo,
         fd_topo_obj_t const * obj ) {
  FD_TEST( fd_cnc_new( fd_topo_obj_laddr( topo, obj->id ), VAL("app_sz"), VAL("type"), fd_log_wallclock() ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_cnc = {
  .name      = "cnc",
  .footprint = cnc_footprint,
  .align     = cnc_align,
  .new       = cnc_new,
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
  return fd_store_footprint( VAL("fec_max") );
}

static ulong
store_align( fd_topo_t const *     topo FD_FN_UNUSED,
             fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_store_align();
}

static void
store_new( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  FD_TEST( fd_store_new( fd_topo_obj_laddr( topo, obj->id ), VAL("fec_max"), VAL("part_cnt") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_store = {
  .name      = "store",
  .footprint = store_footprint,
  .align     = store_align,
  .new       = store_new,
};

static ulong
txncache_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_txncache_shmem_footprint( VAL("max_live_slots"), VAL("max_txn_per_slot") );
}

static ulong
txncache_align( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_txncache_shmem_align();
}

static void
txncache_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_txncache_shmem_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_live_slots"), VAL("max_txn_per_slot") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_txncache = {
  .name      = "txncache",
  .footprint = txncache_footprint,
  .align     = txncache_align,
  .new       = txncache_new,
};

static ulong
acc_pool_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_acc_pool_footprint( VAL("max_account_cnt") );
}

static ulong
acc_pool_align( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_acc_pool_align();
}

static void
acc_pool_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_acc_pool_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_account_cnt") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_acc_pool = {
  .name      = "acc_pool",
  .footprint = acc_pool_footprint,
  .align     = acc_pool_align,
  .new       = acc_pool_new,
};


static ulong
rnonce_ss_footprint( fd_topo_t const *     topo FD_FN_UNUSED,
                     fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return sizeof(fd_rnonce_ss_t) + sizeof(ulong);
}

static ulong
rnonce_ss_align( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return alignof(fd_rnonce_ss_t);
}

static void
rnonce_ss_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  memset( fd_topo_obj_laddr( topo, obj->id ), '\0', sizeof(fd_rnonce_ss_t)+sizeof(ulong) );
}

fd_topo_obj_callbacks_t fd_obj_cb_rnonce_ss = {
  .name      = "rnonce_ss",
  .footprint = rnonce_ss_footprint,
  .align     = rnonce_ss_align,
  .new       = rnonce_ss_new,
};

#undef VAL
