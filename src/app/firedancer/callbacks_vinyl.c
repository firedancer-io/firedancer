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

/* vinyl_data: the shared memory object underpinning a vinyl_data object
   is an arbitrary FD_VINYL_BSTREAM_BLOCK_SZ shared memory region with
   no special init procedure. */

static ulong
vinyl_data_align( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return FD_VINYL_BSTREAM_BLOCK_SZ;
}

static ulong
vinyl_data_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return VAL("sz");
}

static void
vinyl_data_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_data = {
  .name      = "vinyl_data",
  .footprint = vinyl_data_footprint,
  .align     = vinyl_data_align,
  .new       = vinyl_data_new,
};

/* vinyl_line: object pool for vinyl cache management */

static ulong
vinyl_line_align( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return alignof(fd_vinyl_line_t);
}

static ulong
vinyl_line_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return sizeof(fd_vinyl_line_t) * VAL("cnt");
}

static void
vinyl_line_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_line = {
  .name      = "vinyl_line",
  .footprint = vinyl_line_footprint,
  .align     = vinyl_line_align,
  .new       = vinyl_line_new,
};

/* vinyl_data_obj: variable size object cache */

static ulong
vinyl_data_obj_align( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return alignof(fd_vinyl_data_obj_t);
}

static ulong
vinyl_data_obj_footprint( fd_topo_t const *    topo,
                          fd_topo_obj_t const * obj ) {
  return fd_ulong_align_up( VAL("sz"), alignof(fd_vinyl_data_obj_t) );
}

static void
vinyl_data_obj_new( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_data_obj = {
  .name      = "vinyl_data_obj",
  .footprint = vinyl_data_obj_footprint,
  .align     = vinyl_data_obj_align,
  .new       = vinyl_data_obj_new,
};

/* vinyl_rq: vinyl request queue */

static ulong
vinyl_rq_align( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_vinyl_rq_align();
}

static ulong
vinyl_rq_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_vinyl_rq_footprint( VAL("rq_max") );
}

static void
vinyl_rq_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  FD_TEST( fd_vinyl_rq_new( fd_topo_obj_laddr( topo, obj->id ), VAL("rq_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_rq = {
  .name      = "vinyl_rq",
  .footprint = vinyl_rq_footprint,
  .align     = vinyl_rq_align,
  .new       = vinyl_rq_new,
};

/* vinyl_cq: vinyl completion queue */

static ulong
vinyl_cq_align( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_vinyl_cq_align();
}

static ulong
vinyl_cq_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_vinyl_cq_footprint( VAL("cq_max") );
}

static void
vinyl_cq_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  FD_TEST( fd_vinyl_cq_new( fd_topo_obj_laddr( topo, obj->id ), VAL("cq_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_cq = {
  .name      = "vinyl_cq",
  .footprint = vinyl_cq_footprint,
  .align     = vinyl_cq_align,
  .new       = vinyl_cq_new,
};
