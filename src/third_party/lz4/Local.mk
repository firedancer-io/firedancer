ifdef FD_HAS_LZ4

# Core block API (lz4.c) covers all first-party use (fd_checkpt,
# fd_wksp, vinyl); lz4hc exists only for librocksdb.a's
# LZ4_compress_HC* refs.  Standalone trailing archive (global
# LDFLAGS, see with-lz4.mk) rather than folded into libfd_util.a:
# librocksdb.a appears after -lfd_util on rocksdb link lines, so with
# single-pass linkers (ld.bfd) its LZ4 refs only resolve from an
# archive placed after it.  LDFLAGS is last in _make-exe.
LZ4_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/third_party/lz4/lib/%.o : src/third_party/lz4/lib/%.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(LZ4_CFLAGS_NOWARN) -c $< -o $@

$(OBJDIR)/lib/libfd_lz4.a: $(OBJDIR)/obj/third_party/lz4/lib/lz4.o $(OBJDIR)/obj/third_party/lz4/lib/lz4hc.o

lib: $(OBJDIR)/lib/libfd_lz4.a

# Global-LDFLAGS archive: order-only edge via libfd_util.a (see
# third_party/blst/Local.mk for rationale).
$(OBJDIR)/lib/libfd_util.a: | $(OBJDIR)/lib/libfd_lz4.a

endif
