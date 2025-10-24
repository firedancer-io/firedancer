ifeq ($(wildcard $(OPT)/git/bzip2/bzlib.c),)
$(warning "bzip2 not installed, skipping")
else

FD_HAS_BZIP2:=1
CFLAGS+=-DFD_HAS_BZIP2=1

BZ2_OBJS:=blocksort compress crctable decompress huffman randtable bzlib
$(OBJDIR)/lib/libfd_ballet.a: $(patsubst %,$(OBJDIR)/obj/ballet/bzip2/%.o,$(BZ2_OBJS))

CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS)))

$(OBJDIR)/obj/ballet/bzip2/%.o : $(OPT)/git/bzip2/%.c
	$(MKDIR) $(dir $@) && \
$(CC) $(CFLAGS_NOWARN) -c $< -o $@

endif
