$(call add-hdrs,fd_sse.h fd_sse_vc.h fd_sse_vi.h fd_sse_vf.h fd_sse_vd.h)
$(call make-unit-test,test_sse,test_sse,fd_util)

