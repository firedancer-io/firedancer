$(call add-hdrs,fd_sha512.h)
$(call add-objs,fd_sha512,fd_ballet)
ifdef FD_HAS_AVX
UNAME := $(shell uname)
ifneq ($(UNAME), Darwin)
$(call add-asms,fd_sha512_core_avx2,fd_ballet)
endif
endif

$(call make-unit-test,test_sha512,test_sha512,fd_ballet fd_util)
