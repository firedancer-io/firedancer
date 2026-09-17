# Upstream build.sh compiles two objects: the server.c unity build and
# assembly.S (#includes pre-generated per-arch .s bodies from elf/).
# server.c is compiled as two Firedancer-owned unity TUs instead (README.txt); slow one first
# -fno-builtin: keep constant-time memory routines from becoming libc
# calls.  x86: __BLST_PORTABLE__ assembles both ADX and portable paths
# with runtime cpuid dispatch; -mno-avx per upstream (avoid SSE<->AVX
# transition penalties).  arm: no variant dispatch; armv8 bodies only.
# Other machines (noarch, power9, riscv) take the pure C path.  vect.h
# forces 64-bit limbs whenever the compiler defines __x86_64__ or
# __aarch64__, which no_asm.h (32-bit limbs only) cannot build, so
# undefine them.
BLST_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS))) -fno-builtin
BLST_C_OBJS:=$(OBJDIR)/obj/third_party/blst/fd_blst_curve.o $(OBJDIR)/obj/third_party/blst/fd_blst_field.o
BLST_OBJS:=$(BLST_C_OBJS)
ifdef FD_HAS_X86
BLST_CFLAGS_NOWARN+=-D__BLST_PORTABLE__ -mno-avx
BLST_OBJS+=$(OBJDIR)/obj/third_party/blst/assembly.o
else ifdef FD_HAS_ARM
BLST_OBJS+=$(OBJDIR)/obj/third_party/blst/assembly.o
else
BLST_CFLAGS_NOWARN+=-D__BLST_NO_ASM__ -U__x86_64__ -U__aarch64__ -ffreestanding
endif

$(OBJDIR)/obj/third_party/blst/fd_blst_%.o : src/third_party/blst/fd_blst_%.c $(OBJDIR)/.flags src/third_party/blst/Local.mk
	@$(info CC$(TAB)$(notdir $@))
	$(Q)$(CC) $(BLST_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

$(OBJDIR)/obj/third_party/blst/assembly.o : src/third_party/blst/build/assembly.S $(OBJDIR)/.flags src/third_party/blst/Local.mk
	@$(info AS$(TAB)$(notdir $@))
	$(Q)$(CC) $(BLST_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

ASM_DEPFILES+=$(OBJDIR)/obj/third_party/blst/assembly.d

THIRDPARTY_DEPFILES+=$(BLST_C_OBJS:.o=.d)

LIB_NAMES+=fd_blst
LIB_OBJS_fd_blst+=$(BLST_OBJS)
$(OBJDIR)/lib/libfd_blst.a: $(BLST_OBJS)
$(OBJDIR)/lib/libfd_blst.a: $(OBJDIR)/lib/libfd_blst.a.mlist

lib: $(OBJDIR)/lib/libfd_blst.a

# libfd_blst.a sits in global LDFLAGS (see with-blst.mk), which gives
# executables no prerequisite edge to it.  Order-only edge via
# libfd_util.a (linked by every executable; excluded from its $^).
$(OBJDIR)/lib/libfd_util.a: | $(OBJDIR)/lib/libfd_blst.a
