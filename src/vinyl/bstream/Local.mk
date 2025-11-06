$(call add-hdrs,fd_vinyl_bstream.h)
$(call add-objs,fd_vinyl_bstream,fd_vinyl)
ifdef FD_HAS_AVX512
$(call add-objs,fd_hash_avx512dq,fd_vinyl)
endif
$(call make-unit-test,test_vinyl_bstream,test_vinyl_bstream,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_bstream)
