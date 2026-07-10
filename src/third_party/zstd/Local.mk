ifdef FD_HAS_ZSTD

# pool/threading compile to stubs without ZSTD_MULTITHREAD.
# dictBuilder is only needed by librocksdb.a (ZDICT_*); cheap to keep
# unconditionally, unused members drop at link.
ZSTD_OBJS:=\
  common/debug \
  common/entropy_common \
  common/error_private \
  common/fse_decompress \
  common/pool \
  common/threading \
  common/xxhash \
  common/zstd_common \
  compress/fse_compress \
  compress/hist \
  compress/huf_compress \
  compress/zstd_compress \
  compress/zstd_compress_literals \
  compress/zstd_compress_sequences \
  compress/zstd_compress_superblock \
  compress/zstd_double_fast \
  compress/zstd_fast \
  compress/zstd_lazy \
  compress/zstd_ldm \
  compress/zstd_opt \
  compress/zstd_preSplit \
  decompress/huf_decompress \
  decompress/zstd_ddict \
  decompress/zstd_decompress \
  decompress/zstd_decompress_block \
  dictBuilder/cover \
  dictBuilder/divsufsort \
  dictBuilder/fastcover \
  dictBuilder/zdict

ZSTD_CFLAGS_NOWARN:=$(filter-out -W%,$(filter-out -Werror,$(CPPFLAGS) $(CFLAGS))) -DZSTD_TRACE=0 -DDEBUGLEVEL=0 -DZSTD_LEGACY_SUPPORT=0 -DZSTD_ASAN_DONT_POISON_WORKSPACE=1 -DZSTD_MSAN_DONT_POISON_WORKSPACE=1

$(OBJDIR)/obj/third_party/zstd/lib/%.o : src/third_party/zstd/lib/%.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(ZSTD_CFLAGS_NOWARN) -c $< -o $@

# upstream builds this TU with -fno-tree-vectorize
$(OBJDIR)/obj/third_party/zstd/lib/decompress/zstd_decompress_block.o : src/third_party/zstd/lib/decompress/zstd_decompress_block.c
	@echo -e "CC\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(ZSTD_CFLAGS_NOWARN) -fno-tree-vectorize -c $< -o $@

# self-gated on __x86_64__/ZSTD_ASM_SUPPORTED; empty object elsewhere
$(OBJDIR)/obj/third_party/zstd/lib/decompress/huf_decompress_amd64.o : src/third_party/zstd/lib/decompress/huf_decompress_amd64.S
	@echo -e "AS\t$(notdir $@)"
	$(Q)$(MKDIR) $(dir $@) && \
$(CC) $(ZSTD_CFLAGS_NOWARN) -c $< -o $@

$(OBJDIR)/lib/libfd_zstd.a: $(patsubst %,$(OBJDIR)/obj/third_party/zstd/lib/%.o,$(ZSTD_OBJS)) $(OBJDIR)/obj/third_party/zstd/lib/decompress/huf_decompress_amd64.o

lib: $(OBJDIR)/lib/libfd_zstd.a

# Global-LDFLAGS archive: order-only edge via libfd_util.a (see
# third_party/blst/Local.mk for rationale).
$(OBJDIR)/lib/libfd_util.a: | $(OBJDIR)/lib/libfd_zstd.a

endif
