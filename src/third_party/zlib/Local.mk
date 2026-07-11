ifdef FD_HAS_HOSTED
# Compress-only subset; sole consumer is the fd_gzip_pack build tool.
ZLIB_OBJS:=adler32 crc32 deflate trees zutil
$(OBJDIR)/lib/libfd_zlib.a: $(patsubst %,$(OBJDIR)/obj/third_party/zlib/%.o,$(ZLIB_OBJS))

lib: $(OBJDIR)/lib/libfd_zlib.a

ZLIB_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS))) -DZ_SOLO

$(OBJDIR)/obj/third_party/zlib/%.o : src/third_party/zlib/%.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(ZLIB_CFLAGS_NOWARN) -c $< -o $@
endif
