#include "../../vinyl/fd_vinyl.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod_format.h"

#define VAL(name) (__extension__({                                                             \
  ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
  if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
  __x; }))


/* vinyl_meta: a shared memory separately chained hash map */

static ulong
vinyl_meta_align( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_vinyl_meta_align();
}

static ulong
vinyl_meta_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return fd_vinyl_meta_footprint( VAL("ele_max"), VAL("lock_cnt"), VAL("probe_max") );
}

static void
vinyl_meta_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  FD_TEST( fd_vinyl_meta_new( fd_topo_obj_laddr( topo, obj->id ), VAL("ele_max"), VAL("lock_cnt"), VAL("probe_max"), VAL("seed") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_meta = {
  .name      = "vinyl_meta",
  .footprint = vinyl_meta_footprint,
  .align     = vinyl_meta_align,
  .new       = vinyl_meta_new,
};

/* vinyl_meta_ele: hash map elements of vinyl_meta */

static ulong
vinyl_meta_ele_align( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return alignof(fd_vinyl_meta_ele_t);
}

static ulong
vinyl_meta_ele_footprint( fd_topo_t const *     topo,
                          fd_topo_obj_t const * obj ) {
  return sizeof(fd_vinyl_meta_ele_t) * VAL("cnt");
}

static void
vinyl_meta_ele_new( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_meta_ele = {
  .name      = "vinyl_meta_e",
  .footprint = vinyl_meta_ele_footprint,
  .align     = vinyl_meta_ele_align,
  .new       = vinyl_meta_ele_new,
};
