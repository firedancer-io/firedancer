$(call add-hdrs,fd_sha256.h)
$(call add-objs,fd_sha256,fd_ballet)
ifdef FD_HAS_AVX
$(call add-asms,fd_sha256_core_shaext,fd_ballet)
endif

$(call make-unit-test,test_sha256,test_sha256,fd_ballet fd_util)
$(call run-unit-test,test_sha256)
