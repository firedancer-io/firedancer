$(call add-hdrs,fd_falcon.h)
$(call add-objs,fd_falcon,fd_ballet)

ifdef FD_HAS_AVX512
$(call add-objs,fd_falcon_pt,fd_ballet)
$(OBJDIR)/obj/ballet/falcon/fd_falcon_pt.o: CFLAGS+=-mavx512f -mavx512dq -mavx512bw
endif
# test_falcon: default runs correctness tests + microbenchmarks. To skip correctness
# tests and run benchmarks only, rebuild test_falcon.o with -DFD_TEST_FALCON_BENCH_ONLY=1.
$(call make-unit-test,test_falcon,test_falcon,fd_ballet fd_util)
$(call run-unit-test,test_falcon)
