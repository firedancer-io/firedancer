ifdef FD_HAS_HOSTED
# Compiled without project warning flags (upstream code, unmodified).
# Archive wired directly, bzip2-style: add-objs would register the TU
# in DEPFILES and "make check" would syntax-check it with full flags.
$(OBJDIR)/lib/libfd_waltz.a: $(OBJDIR)/obj/third_party/picohttpparser/picohttpparser.o

PICOHTTP_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/third_party/picohttpparser/picohttpparser.o : src/third_party/picohttpparser/picohttpparser.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(PICOHTTP_CFLAGS_NOWARN) -c $< -o $@

$(call add-hdrs,picohttpparser.h)

$(call make-fuzz-test,fuzz_picohttpparser,fuzz_picohttpparser,fd_waltz fd_util)
endif
