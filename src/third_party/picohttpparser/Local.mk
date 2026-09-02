ifdef FD_HAS_HOSTED
# Compiled without project warning flags (upstream code, unmodified).
# Archive wired directly, bzip2-style: add-objs would register the TU
# in DEPFILES and "make check" would syntax-check it with full flags.
LIB_OBJS_fd_waltz+=$(OBJDIR)/obj/third_party/picohttpparser/picohttpparser.o
$(OBJDIR)/lib/libfd_waltz.a: $(OBJDIR)/obj/third_party/picohttpparser/picohttpparser.o

PICOHTTP_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/third_party/picohttpparser/picohttpparser.o : src/third_party/picohttpparser/picohttpparser.c $(OBJDIR)/.flags src/third_party/picohttpparser/Local.mk
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(PICOHTTP_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

THIRDPARTY_DEPFILES+=$(OBJDIR)/obj/third_party/picohttpparser/picohttpparser.d

$(call add-hdrs,picohttpparser.h)

$(call make-fuzz-test,fuzz_picohttpparser,fuzz_picohttpparser,fd_waltz fd_util)
endif
