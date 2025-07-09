$(call add-hdrs,fd_sha256.h)
$(call add-objs,fd_sha256,fd_ballet)
ifdef FD_HAS_AVX
$(call add-objs,fd_sha256_batch_avx,fd_ballet)
endif
ifdef FD_HAS_AVX512
$(call add-objs,fd_sha256_batch_avx512,fd_ballet)
endif

$(call make-unit-test,test_sha256,test_sha256,fd_ballet fd_util)
$(call run-unit-test,test_sha256)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_sha256,fuzz_sha256,fd_ballet fd_util)
endif
