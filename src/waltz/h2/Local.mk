# HPACK
$(call add-hdrs,fd_hpack.h,fd_waltz)
$(call add-objs,fd_hpack,fd_waltz)
$(call make-fuzz-test,fuzz_hpack_rd,fuzz_hpack_rd,fd_waltz fd_util)

# HTTP/2
$(call add-hdrs,fd_h2_base.h)
$(call make-unit-test,test_h2,test_h2,fd_waltz fd_util)
$(call run-unit-test,test_h2)
