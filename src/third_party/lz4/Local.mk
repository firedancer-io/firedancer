ifdef FD_HAS_LZ4

# Standalone trailing archive (global LDFLAGS, see with-lz4.mk) rather
# than folded into libfd_util.a: with single-pass linkers (ld.bfd)
# libfd_util.a's LZ4 refs only resolve from an archive placed after
# -lfd_util, and LDFLAGS is last in _make-exe.
LZ4_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/third_party/lz4/lib/%.o : src/third_party/lz4/lib/%.c $(OBJDIR)/.flags src/third_party/lz4/Local.mk
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(LZ4_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

THIRDPARTY_DEPFILES+=$(OBJDIR)/obj/third_party/lz4/lib/lz4.d

LIB_NAMES+=fd_lz4
LIB_OBJS_fd_lz4+=$(OBJDIR)/obj/third_party/lz4/lib/lz4.o
$(OBJDIR)/lib/libfd_lz4.a: $(OBJDIR)/obj/third_party/lz4/lib/lz4.o
$(OBJDIR)/lib/libfd_lz4.a: $(OBJDIR)/lib/libfd_lz4.a.mlist

lib: $(OBJDIR)/lib/libfd_lz4.a

# Global-LDFLAGS archive: order-only edge via libfd_util.a (see
# third_party/blst/Local.mk for rationale).
$(OBJDIR)/lib/libfd_util.a: | $(OBJDIR)/lib/libfd_lz4.a

endif

