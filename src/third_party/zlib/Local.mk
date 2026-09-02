ifdef FD_HAS_HOSTED
# Compress-only subset; sole consumer is the fd_gzip_pack build tool.
ZLIB_OBJS:=adler32 crc32 deflate trees zutil
LIB_NAMES+=fd_zlib
LIB_OBJS_fd_zlib+=$(patsubst %,$(OBJDIR)/obj/third_party/zlib/%.o,$(ZLIB_OBJS))
$(OBJDIR)/lib/libfd_zlib.a: $(patsubst %,$(OBJDIR)/obj/third_party/zlib/%.o,$(ZLIB_OBJS))
$(OBJDIR)/lib/libfd_zlib.a: $(OBJDIR)/lib/libfd_zlib.a.mlist

lib: $(OBJDIR)/lib/libfd_zlib.a

ZLIB_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS))) -DZ_SOLO

$(OBJDIR)/obj/third_party/zlib/%.o : src/third_party/zlib/%.c $(OBJDIR)/.flags src/third_party/zlib/Local.mk
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(ZLIB_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

THIRDPARTY_DEPFILES+=$(patsubst %,$(OBJDIR)/obj/third_party/zlib/%.d,$(ZLIB_OBJS))
endif

