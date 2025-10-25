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
