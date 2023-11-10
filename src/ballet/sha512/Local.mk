$(call add-hdrs,fd_sha512.h)
$(call add-objs,fd_sha512,fd_ballet)
ifdef FD_HAS_AVX
$(call add-asms,fd_sha512_core_avx2,fd_ballet)
$(call add-objs,fd_sha512_batch_avx,fd_ballet)
endif
ifdef FD_HAS_AVX512
$(call add-objs,fd_sha512_batch_avx512,fd_ballet)
endif

$(call make-unit-test,test_sha512,test_sha512,fd_ballet fd_util)
$(call fuzz-test,fuzz_sha512,fuzz_sha512,fd_ballet fd_util)
$(call run-unit-test,test_sha512,)

$(call make-unit-test,test_sha384,test_sha384,fd_ballet fd_util)
$(call fuzz-test,fuzz_sha384,fuzz_sha384,fd_ballet fd_util)
$(call run-unit-test,test_sha384)
