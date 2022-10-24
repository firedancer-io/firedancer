$(call add-hdrs,fd_sse.h fd_sse_vc.h fd_sse_vi.h fd_sse_vf.h fd_sse_vd.h fd_sse_vl.h)
$(call make-unit-test,test_sse,test_sse,fd_util)

$(call add-hdrs,fd_avx.h fd_avx_wc.h fd_avx_wi.h fd_avx_wf.h fd_avx_wd.h fd_avx_wl.h)
$(call make-unit-test,test_avx,test_avx,fd_util)

