$(call add-hdrs,fd_bls12_381.h fd_bls.h)

ifdef FD_HAS_AVX512

# FD_BLS_AVX512_CC:=clang-21
# FD_BLS_AVX512_FLAGS:=-std=c17 -O3 -g -fPIC -fno-omit-frame-pointer \
#   -march=native -mavx512ifma -DFD_HAS_AVX512=1 -DFD_HAS_INT128=1 -DFD_HAS_HOSTED=1 \
#   -DFD_HAS_X86=1 -DFD_IS_X86_64=1 -Wno-ignored-attributes \
#   -Wno-unknown-pragmas -I.

# $(OBJDIR)/obj/ballet/bls/avx512/%.o: src/ballet/bls/avx512/%.c $(wildcard src/ballet/bls/avx512/*.h src/ballet/bls/avx512/*.inc)
# 	@echo -e "CC-IFMA\t$(notdir $@)"
# 	$(Q)$(MKDIR) $(dir $@) && $(FD_BLS_AVX512_CC) $(FD_BLS_AVX512_FLAGS) -c $< -o $@

$(call add-objs,fd_bls12_381 avx512/fd_bls_rns avx512/fd_bls_field avx512/fd_bls_final \
  avx512/fd_bls_g2 avx512/fd_bls_miller avx512/fd_bls_g1 avx512/fd_bls_hash avx512/fd_bls,fd_ballet)
$(call make-unit-test,test_bls_avx512,avx512/test_bls_avx512,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls_avx512)

else

$(call add-objs,fd_bls12_381 ref/fd_bls,fd_ballet)

endif

$(call make-unit-test,test_bls12_381,test_bls12_381,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls12_381)

$(call make-unit-test,test_bls_api,test_bls_api,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls_api)
