ifdef FD_HAS_BLST

# Two-object build per upstream build.sh: server.c unity build +
# assembly.S (#includes pre-generated per-arch .s bodies from elf/).
# -fno-builtin: keep constant-time memory routines from becoming libc
# calls.  x86: __BLST_PORTABLE__ assembles both ADX and portable paths
# with runtime cpuid dispatch; -mno-avx per upstream (avoid SSE<->AVX
# transition penalties).  arm: no variant dispatch; armv8 bodies only.
BLST_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS))) -fno-builtin
ifdef FD_HAS_X86
BLST_CFLAGS_NOWARN+=-D__BLST_PORTABLE__ -mno-avx
endif

$(OBJDIR)/obj/third_party/blst/server.o : src/third_party/blst/src/server.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(BLST_CFLAGS_NOWARN) -c $< -o $@

$(OBJDIR)/obj/third_party/blst/assembly.o : src/third_party/blst/build/assembly.S
	@echo -e "AS\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(BLST_CFLAGS_NOWARN) -c $< -o $@

$(OBJDIR)/lib/libfd_blst.a: $(OBJDIR)/obj/third_party/blst/server.o $(OBJDIR)/obj/third_party/blst/assembly.o

lib: $(OBJDIR)/lib/libfd_blst.a

# libfd_blst.a sits in global LDFLAGS (see with-blst.mk), which gives
# executables no prerequisite edge to it.  Order-only edge via
# libfd_util.a (linked by every executable; excluded from its $^).
$(OBJDIR)/lib/libfd_util.a: | $(OBJDIR)/lib/libfd_blst.a

endif
