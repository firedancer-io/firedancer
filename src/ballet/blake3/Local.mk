$(call add-hdrs,fd_blake3.h)
$(call add-objs,fd_blake3 fd_blake3_ref,fd_ballet)
ifdef FD_HAS_SSE
$(call add-objs,fd_blake3_sse41,fd_ballet)
endif
ifdef FD_HAS_AVX512
$(call add-objs,fd_blake3_avx512,fd_ballet)
endif
ifdef FD_HAS_AVX
$(call add-objs,fd_blake3_avx2,fd_ballet)
endif

$(call make-unit-test,test_blake3,test_blake3,fd_ballet fd_util)
$(call make-fuzz-test,fuzz_blake3,fuzz_blake3,fd_ballet fd_util)
