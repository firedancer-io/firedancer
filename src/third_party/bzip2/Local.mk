BZ2_OBJS:=blocksort compress crctable decompress huffman randtable bzlib
LIB_OBJS_fd_ballet+=$(patsubst %,$(OBJDIR)/obj/third_party/bzip2/%.o,$(BZ2_OBJS))
$(OBJDIR)/lib/libfd_ballet.a: $(patsubst %,$(OBJDIR)/obj/third_party/bzip2/%.o,$(BZ2_OBJS))

BZIP2_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/third_party/bzip2/%.o : src/third_party/bzip2/%.c $(OBJDIR)/.flags src/third_party/bzip2/Local.mk
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(BZIP2_CFLAGS_NOWARN) $(DEPFLAGS) -c $< -o $@ && $(DEPFIX)

THIRDPARTY_DEPFILES+=$(patsubst %,$(OBJDIR)/obj/third_party/bzip2/%.d,$(BZ2_OBJS))
