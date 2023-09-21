$(call add-hdrs,fd_sse.h fd_sse_vc.h fd_sse_vi.h fd_sse_vu.h fd_sse_vf.h fd_sse_vl.h fd_sse_vv.h fd_sse_vd.h fd_sse_vl.h fd_sse_vb.h)
ifdef FD_HAS_SSE
$(call make-unit-test,test_sse_4x32,test_sse_4x32 test_sse_common,fd_util)
$(call make-unit-test,test_sse_2x64,test_sse_2x64 test_sse_common,fd_util)
$(call make-unit-test,test_sse_16x8,test_sse_16x8 test_sse_common,fd_util)
$(call run-unit-test,test_sse_4x32,)
$(call run-unit-test,test_sse_2x64,)
$(call run-unit-test,test_sse_16x8,)
endif

$(call add-hdrs,fd_avx.h fd_avx_wc.h fd_avx_wi.h fd_avx_wu.h fd_avx_wf.h fd_avx_wl.h fd_avx_wv.h fd_avx_wd.h fd_avx_wl.h fd_avx_wb.h)
ifdef FD_HAS_AVX
$(call make-unit-test,test_avx_8x32,test_avx_8x32 test_avx_common,fd_util)
$(call make-unit-test,test_avx_4x64,test_avx_4x64 test_avx_common,fd_util)
$(call make-unit-test,test_avx_32x8,test_avx_32x8 test_avx_common,fd_util)
$(call run-unit-test,test_avx_8x32,)
$(call run-unit-test,test_avx_4x64,)
$(call run-unit-test,test_avx_32x8,)
endif

$(call add-hdrs,fd_avx512.h fd_avx512_wwl.h)
ifdef FD_HAS_AVX512
$(call make-unit-test,test_avx512_8x64,test_avx512_8x64 test_avx_common,fd_util)
$(call run-unit-test,test_avx512_8x64,)
endif
