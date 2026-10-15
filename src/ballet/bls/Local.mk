$(call add-hdrs,fd_bls12_381.h fd_bls.h)
$(call add-objs,fd_bls12_381 fd_bls ref/fd_bls ref/fd_bls_ops,fd_ballet)

ifdef FD_HAS_AVX512
FD_BLS_AVX512_DEPS:=$(wildcard src/ballet/bls/avx512/*.h src/ballet/bls/avx512/*.inc) \
  $(wildcard src/ballet/vroom/fd_vroom*.h src/ballet/vroom/fd_vroom*.c) \
  src/ballet/bls/avx512/fd_bls_final.c \
  src/ballet/bls/avx512/fd_bls_miller.c \
  src/ballet/bls/avx512/fd_bls_g1.c \
  src/ballet/bls/avx512/fd_bls_hash.c \
  src/ballet/bls/avx512/fd_bls.c
$(OBJDIR)/obj/ballet/bls/avx512/fd_bls_backend.o: src/ballet/bls/avx512/fd_bls_backend.c $(FD_BLS_AVX512_DEPS)
	@echo -e "CC-IFMA\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(FD_VROOM_CC) $(FD_VROOM_CFLAGS) -c $< -o $@
$(call add-objs,avx512/fd_bls_backend,fd_ballet)
$(call make-unit-test,test_bls_avx512,avx512/test_bls_avx512,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls_avx512)
endif

$(call make-unit-test,test_bls,test_bls,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls)

$(call make-unit-test,test_bls12_381,test_bls12_381,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls12_381)
