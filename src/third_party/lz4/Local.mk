ifdef FD_HAS_LZ4

# Core block API (lz4.c) covers all first-party use (fd_checkpt,
# fd_wksp, vinyl).  lz4hc exists only for librocksdb.a's
# LZ4_compress_HC* refs.  Objects go into libfd_util.a: several
# lz4-consuming targets link fd_util alone, and fd_util is last in
# every lib list.
LZ4_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/third_party/lz4/lib/%.o : src/third_party/lz4/lib/%.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(LZ4_CFLAGS_NOWARN) -c $< -o $@

$(OBJDIR)/lib/libfd_util.a: $(OBJDIR)/obj/third_party/lz4/lib/lz4.o $(OBJDIR)/obj/third_party/lz4/lib/lz4hc.o

endif
