# Two-object build per upstream build.sh: server.c unity build +
# assembly.S (#includes pre-generated per-arch .s bodies from elf/).
# -fno-builtin: keep constant-time memory routines from becoming libc
# calls.  x86: __BLST_PORTABLE__ assembles both ADX and portable paths
# with runtime cpuid dispatch; -mno-avx per upstream (avoid SSE<->AVX
# transition penalties).  arm: no variant dispatch; armv8 bodies only.
# Other machines (noarch, power9, riscv) take the pure C path.  vect.h
# forces 64-bit limbs whenever the compiler defines __x86_64__ or
# __aarch64__, which no_asm.h (32-bit limbs only) cannot build, so
# undefine them; blst includes only stddef.h so this is safe.
BLST_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS))) -fno-builtin
BLST_OBJS:=$(OBJDIR)/obj/third_party/blst/server.o
ifdef FD_HAS_X86
BLST_CFLAGS_NOWARN+=-D__BLST_PORTABLE__ -mno-avx
BLST_OBJS+=$(OBJDIR)/obj/third_party/blst/assembly.o
else ifdef FD_HAS_ARM
BLST_OBJS+=$(OBJDIR)/obj/third_party/blst/assembly.o
else
BLST_CFLAGS_NOWARN+=-D__BLST_NO_ASM__ -U__x86_64__ -U__aarch64__
endif

$(OBJDIR)/obj/third_party/blst/server.o : src/third_party/blst/src/server.c $(OBJDIR)/.flags src/third_party/blst/Local.mk
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(BLST_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

$(OBJDIR)/obj/third_party/blst/assembly.o : src/third_party/blst/build/assembly.S $(OBJDIR)/.flags src/third_party/blst/Local.mk
	@echo -e "AS\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(BLST_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

ASM_DEPFILES+=$(OBJDIR)/obj/third_party/blst/assembly.d

THIRDPARTY_DEPFILES+=$(OBJDIR)/obj/third_party/blst/server.d

LIB_NAMES+=fd_blst
LIB_OBJS_fd_blst+=$(BLST_OBJS)
$(OBJDIR)/lib/libfd_blst.a: $(BLST_OBJS)
$(OBJDIR)/lib/libfd_blst.a: $(OBJDIR)/lib/libfd_blst.a.mlist

lib: $(OBJDIR)/lib/libfd_blst.a

# libfd_blst.a sits in global LDFLAGS (see with-blst.mk), which gives
# executables no prerequisite edge to it.  Order-only edge via
# libfd_util.a (linked by every executable; excluded from its $^).
$(OBJDIR)/lib/libfd_util.a: | $(OBJDIR)/lib/libfd_blst.a
