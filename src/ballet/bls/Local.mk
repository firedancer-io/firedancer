ifdef FD_HAS_BLST

$(call add-hdrs,fd_bls12_381.h)
$(call add-objs,fd_bls12_381,fd_ballet)

ifdef FD_HAS_AVX512
VROOM_CC:=clang-21
VROOM_C_HEADERS:=$(shell find src/ballet/bls/vroom -type f \( -name '*.h' -o -name '*.inc' -o -name '*.c' \))
$(OBJDIR)/obj/ballet/bls/vroom/fd_vroom_backend.o: src/ballet/bls/vroom/fd_vroom_backend.c $(VROOM_C_HEADERS)
	@echo -e "CC-IFMA\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(VROOM_CC) -std=c17 -O3 -g -fPIC -fno-semantic-interposition -fno-omit-frame-pointer -fwrapv -march=native -mavx512ifma \
  -DFD_HAS_AVX512=1 -DFD_HAS_INT128=1 -DFD_HAS_HOSTED=1 -DFD_HAS_X86=1 -DFD_IS_X86_64=1 \
  -Wno-unused-function -Wno-ignored-attributes -Wno-unknown-pragmas -I. -c $< -o $@
$(call add-hdrs,vroom/fd_vroom_rns.h)
$(call add-hdrs,vroom/fd_vroom_field.h)
$(call add-hdrs,vroom/fd_vroom_miller.h)
$(call add-hdrs,vroom/fd_vroom_final.h)
$(call add-objs,vroom/fd_vroom_backend,fd_ballet)
$(call add-hdrs,fd_vroom.h)
$(call add-objs,fd_vroom,fd_ballet)
$(call make-unit-test,test_vroom_rns,vroom/test_vroom_rns,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_vroom_rns)
endif

$(call make-unit-test,test_bls12_381,test_bls12_381,fd_ballet fd_util,$(BLST_LIBS))

$(call run-unit-test,test_bls12_381)

else

$(warning bls12_381 disabled due to lack of libblst)

endif
