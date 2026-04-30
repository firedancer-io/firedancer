$(call add-hdrs,fd_keccak256.h fd_shake256.h fd_keccak256_avx2_keccak8_eo_asm.h fd_keccak256_keccak1eo_asm.h fd_keccak256_avx512_keccak4a_asm.h fd_keccak256_avx512_keccak8a_asm.h fd_keccak256_avx512_keccak8b_asm.h)
$(call add-objs,fd_keccak256 fd_shake256,fd_ballet)

ifdef FD_HAS_AVX
$(call add-objs,fd_keccak256_avx2_keccak8 fd_keccak256_avx2_keccak8_eo,fd_ballet)
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_avx2_keccak8.o: CFLAGS+=-mavx2 -mno-avx512f -mno-avx512vl -mno-avx512bw -mno-avx512dq
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_avx2_keccak8_eo.o: CFLAGS+=-mavx2 -mbmi2 -mno-avx512f -mno-avx512vl -mno-avx512bw -mno-avx512dq
endif

ifdef FD_HAS_AVX512
$(call add-objs,fd_keccak256_avx512_keccak1 fd_keccak256_avx512_keccak8 fd_keccak256_avx512_keccak16_eo,fd_ballet)
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_avx512_keccak1.o: CFLAGS+=-mavx512f -mavx512dq
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_avx512_keccak8.o: CFLAGS+=-mavx512f -mavx512dq
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_avx512_keccak16_eo.o: CFLAGS+=-mavx512f -mavx512dq -mbmi2
endif

ifdef FD_HAS_S2NBIGNUM
$(call add-objs,fd_keccak256_s2n_keccak4,fd_ballet)
endif

$(call make-unit-test,test_keccak256,test_keccak256,fd_ballet fd_util)
$(call run-unit-test,test_keccak256)

# Optional Keccak-f[1600] with u64 lanes split into two uint32 limbs (plonky2-style):
#   make -j FD_KECCAK256_INTERLEAVED32=1 $(OBJDIR)/unit-test/test_keccak256 $(OBJDIR)/unit-test/test_shake256 $(OBJDIR)/unit-test/test_merlin
ifdef FD_KECCAK256_INTERLEAVED32
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256.o: CFLAGS+=-DFD_KECCAK256_USE_INTERLEAVED32=1
$(OBJDIR)/obj/ballet/keccak256/fd_shake256.o: CFLAGS+=-DFD_KECCAK256_USE_INTERLEAVED32=1
$(OBJDIR)/obj/ballet/merlin/fd_merlin.o: CFLAGS+=-DFD_KECCAK256_USE_INTERLEAVED32=1
endif

# x86_64 Keccak-f[1600] (BMI andn + BMI2 rorx), same lane bits as interleaved32.
# Enable on the make command line (not only in headers): the .S object and -D
# are wired here. Example (default OBJDIR is build/native/gcc):
#   make -j FD_KECCAK256_X86_64_LIMB_ASM=1 test_keccak256
#   $(OBJDIR)/unit-test/test_keccak256
# With MACHINE=native, CC=clang uses OBJDIR build/native/clang (see config/machine/native.mk).
#
# Toggling FD_KECCAK256_X86_64_LIMB_ASM only changes CFLAGS, not sources; the stamp
# below forces fd_keccak256.o / fd_shake256.o / fd_merlin.o to rebuild when it flips.
KECCAK256_X86_64_LIMB_ASM_CFG:=$(OBJDIR)/obj/ballet/keccak256/.x86_64_limb_asm_cfg

$(KECCAK256_X86_64_LIMB_ASM_CFG): .FORCE
	@$(MKDIR) $(dir $@)
	@echo "$(strip $(FD_KECCAK256_X86_64_LIMB_ASM))" > $@.tmp
	@if ! cmp -s $@.tmp $@ 2>/dev/null; then mv $@.tmp $@; else $(RM) $@.tmp; fi

$(OBJDIR)/obj/ballet/keccak256/fd_keccak256.o: $(KECCAK256_X86_64_LIMB_ASM_CFG)
$(OBJDIR)/obj/ballet/keccak256/fd_shake256.o: $(KECCAK256_X86_64_LIMB_ASM_CFG)
$(OBJDIR)/obj/ballet/merlin/fd_merlin.o: $(KECCAK256_X86_64_LIMB_ASM_CFG)

.PHONY: .FORCE

ifdef FD_KECCAK256_X86_64_LIMB_ASM
ifndef FD_IS_X86_64
$(error FD_KECCAK256_X86_64_LIMB_ASM requires an x86_64 build (FD_IS_X86_64))
endif
$(call add-asms,fd_keccak256_x86_64_limb_f1600,fd_ballet)
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_x86_64_limb_f1600.o: CFLAGS+=-mbmi2
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256_x86_64_limb_f1600.o: $(KECCAK256_X86_64_LIMB_ASM_CFG)
$(OBJDIR)/obj/ballet/keccak256/fd_keccak256.o: CFLAGS+=-DFD_KECCAK256_USE_X86_64_LIMB_ASM=1
$(OBJDIR)/obj/ballet/keccak256/fd_shake256.o: CFLAGS+=-DFD_KECCAK256_USE_X86_64_LIMB_ASM=1
$(OBJDIR)/obj/ballet/merlin/fd_merlin.o: CFLAGS+=-DFD_KECCAK256_USE_X86_64_LIMB_ASM=1
endif

$(call make-unit-test,test_shake256,test_shake256,fd_ballet fd_util)
$(call run-unit-test,test_shake256)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_keccak256,fuzz_keccak256,fd_ballet fd_util)
endif
