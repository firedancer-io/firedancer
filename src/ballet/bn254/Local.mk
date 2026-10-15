$(call add-hdrs,fd_bn254.h fd_bn254_scalar.h fd_poseidon.h)
$(call add-objs,fd_bn254 fd_bn254_field fd_bn254_field_ext fd_bn254_fp12 fd_bn254_g1 fd_bn254_g2 fd_bn254_g2_check fd_bn254_pairing fd_bn254_final_exp fd_poseidon,fd_ballet)

ifdef FD_HAS_AVX512
FD_BN254_AVX512_DEPS:=$(wildcard src/ballet/bn254/avx512/*.h src/ballet/bn254/avx512/*.inc src/ballet/bn254/avx512/*.c) \
  $(wildcard src/ballet/vroom/fd_vroom*.h src/ballet/vroom/fd_vroom*.c) \
  src/ballet/bn254/fd_bn254_backend.h
$(OBJDIR)/obj/ballet/bn254/avx512/fd_bn254_backend.o: src/ballet/bn254/avx512/fd_bn254_backend.c $(FD_BN254_AVX512_DEPS)
	@echo -e "CC-IFMA\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(FD_VROOM_CC) $(FD_VROOM_CFLAGS) -c $< -o $@
$(call add-objs,avx512/fd_bn254_backend,fd_ballet)
$(call make-unit-test,test_bn254_avx512,avx512/test_bn254_avx512,fd_ballet fd_util)
$(call run-unit-test,test_bn254_avx512)
endif

$(call make-unit-test,test_bn254,test_bn254,fd_ballet fd_util)
$(call make-unit-test,test_poseidon,test_poseidon,fd_ballet fd_util)
$(call run-unit-test,test_bn254)
$(call run-unit-test,test_poseidon)
