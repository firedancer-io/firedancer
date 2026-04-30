$(call add-hdrs,fd_lthash2.h)
$(call add-objs,fd_lthash2,fd_ballet)

ifdef FD_HAS_AVX512
$(OBJDIR)/obj/ballet/lthash2/fd_lthash2.o: CFLAGS+=-mavx512f -mavx512dq
endif

$(call make-unit-test,test_lthash2,test_lthash2,fd_ballet fd_util)
$(call run-unit-test,test_lthash2)
