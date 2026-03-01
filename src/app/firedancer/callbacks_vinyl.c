#include "../../vinyl/fd_vinyl.h"
#include "../../disco/topo/fd_topo.h"
#include "../../discof/restore/utils/fd_vinyl_admin.h"
#include "../../flamenco/accdb/fd_vinyl_req_pool.h"
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
  return fd_ulong_max( alignof(fd_vinyl_meta_ele_t), 128UL );
}

static ulong
vinyl_meta_ele_footprint( fd_topo_t const *     topo,
                          fd_topo_obj_t const * obj ) {
  return fd_ulong_align_up( sizeof(fd_vinyl_meta_ele_t) * VAL("cnt"), vinyl_meta_ele_align( topo, obj ) );
}

static void
vinyl_meta_ele_new( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  /* On Zen 4:
     - non-temporal wide stores are fastest
     - scattering 8 byte writes is slower
     - memset is slowest */

# if FD_HAS_AVX512
  uchar * m0 = fd_topo_obj_laddr( topo, obj->id );
  uchar * m1 = m0 + vinyl_meta_ele_footprint( topo, obj );
  __m512i zero = _mm512_setzero_si512();
  for( uchar * m=m0; m<m1; m+=64 ) {
    _mm512_stream_si512( (__m512i *)m, zero );
  }
  _mm_sfence();
# else
  fd_vinyl_meta_ele_t * ele = fd_topo_obj_laddr( topo, obj->id );
  ulong cnt = VAL("cnt");
  for( ulong i=0UL; i<cnt; i++ ) {
    ele[ i ].phdr.ctl = 0UL;
  }
# endif
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_meta_ele = {
  .name      = "vinyl_meta_e",
  .footprint = vinyl_meta_ele_footprint,
  .align     = vinyl_meta_ele_align,
  .new       = vinyl_meta_ele_new,
};

/* vinyl_data: memory arena for data cache entries */

static ulong
vinyl_data_align( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return alignof(fd_vinyl_data_obj_t);
}

static ulong
vinyl_data_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return fd_ulong_align_dn( VAL("data_sz"), alignof(fd_vinyl_data_obj_t) );
}

static void
vinyl_data_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  /* initialized by user */
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_data = {
  .name      = "vinyl_data",
  .footprint = vinyl_data_footprint,
  .align     = vinyl_data_align,
  .new       = vinyl_data_new,
};

/* vinyl_line: shared line cache array */

static ulong
vinyl_line_align( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return alignof(fd_vinyl_line_t);
}

static ulong
vinyl_line_footprint( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  return VAL("line_max") * sizeof(fd_vinyl_line_t);
}

static void
vinyl_line_new( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  /* initialized by user */
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_line = {
  .name      = "vinyl_line",
  .footprint = vinyl_line_footprint,
  .align     = vinyl_line_align,
  .new       = vinyl_line_new,
};

/* vinyl_req_pool: request allocator */

static ulong
vinyl_req_pool_align( fd_topo_t const *     topo,
                      fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_vinyl_req_pool_align();
}

static ulong
vinyl_req_pool_footprint( fd_topo_t const *     topo,
                            fd_topo_obj_t const * obj ) {
  return fd_vinyl_req_pool_footprint( VAL("batch_max"), VAL("batch_key_max") );
}

static void
vinyl_req_pool_new( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  FD_TEST( fd_vinyl_req_pool_new( fd_topo_obj_laddr( topo, obj->id ), VAL("batch_max"), VAL("batch_key_max") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_req_pool = {
  .name      = "vinyl_rpool",
  .footprint = vinyl_req_pool_footprint,
  .align     = vinyl_req_pool_align,
  .new       = vinyl_req_pool_new,
};

/* vinyl_rq: request queue */

static ulong
vinyl_rq_align( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_vinyl_rq_align();
}

static ulong
vinyl_rq_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_vinyl_rq_footprint( VAL("req_cnt") );
}

static void
vinyl_rq_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_vinyl_rq_new( fd_topo_obj_laddr( topo, obj->id ), VAL("req_cnt") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_rq = {
  .name      = "vinyl_rq",
  .footprint = vinyl_rq_footprint,
  .align     = vinyl_rq_align,
  .new       = vinyl_rq_new,
};

/* vinyl_cq: completion queue */

static ulong
vinyl_cq_align( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  (void)topo; (void)obj;
  return fd_vinyl_cq_align();
}

static ulong
vinyl_cq_footprint( fd_topo_t const *     topo,
                    fd_topo_obj_t const * obj ) {
  return fd_vinyl_cq_footprint( VAL("comp_cnt") );
}

static void
vinyl_cq_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_vinyl_cq_new( fd_topo_obj_laddr( topo, obj->id ), VAL("comp_cnt") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_cq = {
  .name      = "vinyl_cq",
  .footprint = vinyl_cq_footprint,
  .align     = vinyl_cq_align,
  .new       = vinyl_cq_new,
};

static ulong
vinyl_admin_footprint( fd_topo_t const *     topo FD_PARAM_UNUSED,
                       fd_topo_obj_t const * obj FD_PARAM_UNUSED ) {
  return sizeof(fd_vinyl_admin_t);
}

static ulong
vinyl_admin_align( fd_topo_t const *     topo FD_PARAM_UNUSED,
                   fd_topo_obj_t const * obj FD_PARAM_UNUSED ) {
  return alignof(fd_vinyl_admin_t);
}

static void
vinyl_admin_new( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  fd_vinyl_admin_new( fd_topo_obj_laddr( topo, obj->id ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_vinyl_admin = {
  .name      = "vinyl_admin",
  .footprint = vinyl_admin_footprint,
  .align     = vinyl_admin_align,
  .new       = vinyl_admin_new,
};

#undef VAL
