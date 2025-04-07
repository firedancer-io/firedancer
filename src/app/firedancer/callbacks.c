#include "../shared/fd_config.h"
#include "../../disco/topo/fd_pod_format.h"

#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"

#define VAL(name) (__extension__({                                                             \
  ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
  if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
  __x; }))

static ulong
runtime_pub_footprint( fd_topo_t const *     topo FD_FN_UNUSED,
                      fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_runtime_public_footprint();
}

static ulong
runtime_pub_align( fd_topo_t const *     topo FD_FN_UNUSED,
                  fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_runtime_public_align();
}

static void
runtime_pub_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  FD_TEST( fd_runtime_public_new( fd_topo_obj_laddr( topo, obj->id ) ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_runtime_pub = {
  .name      = "runtime_pub",
  .footprint = runtime_pub_footprint,
  .align     = runtime_pub_align,
  .new       = runtime_pub_new,
};

static ulong
blockstore_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return fd_blockstore_footprint( VAL("shred_max"), VAL("block_max"), VAL("idx_max"), VAL("txn_max") ) + VAL("alloc_max");
}

static ulong
blockstore_align( fd_topo_t const *     topo FD_FN_UNUSED,
                  fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_blockstore_align();
}

static void
blockstore_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  FD_TEST( fd_blockstore_new( fd_topo_obj_laddr( topo, obj->id ), VAL("wksp_tag"), VAL("seed"), VAL("shred_max"), VAL("block_max"), VAL("idx_max"), VAL("txn_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_blockstore = {
  .name      = "blockstore",
  .footprint = blockstore_footprint,
  .align     = blockstore_align,
  .new       = blockstore_new,
};

static ulong
txncache_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_txncache_footprint( VAL("max_rooted_slots"), VAL("max_live_slots"), VAL("max_txn_per_slot"), FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS );
}

static ulong
txncache_align( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_txncache_align();
}

static void
txncache_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_txncache_new( fd_topo_obj_laddr( topo, obj->id ), VAL("max_rooted_slots"), VAL("max_live_slots"), VAL("max_txn_per_slot"), FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_txncache = {
  .name      = "txncache",
  .footprint = txncache_footprint,
  .align     = txncache_align,
  .new       = txncache_new,
};

static ulong
exec_spad_footprint( fd_topo_t const *     topo FD_FN_UNUSED,
                     fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_spad_footprint( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT );
}

static ulong
exec_spad_align( fd_topo_t const *     topo FD_FN_UNUSED,
                 fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_spad_align();
}

static void
exec_spad_new( fd_topo_t const *     topo,
               fd_topo_obj_t const * obj ) {
  FD_TEST( fd_spad_new( fd_topo_obj_laddr( topo, obj->id ), FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_exec_spad = {
  .name      = "exec_spad",
  .footprint = exec_spad_footprint,
  .align     = exec_spad_align,
  .new       = exec_spad_new,
};

#undef VAL
