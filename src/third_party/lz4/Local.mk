ifdef FD_HAS_LZ4

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
