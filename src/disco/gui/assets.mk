# compressed frontend assets (dist_cmp/) and the tools that make them, run as one sub-make by
# src/disco/gui/Local.mk with the stale files as goals.  The tools are built from their own -O1
# objects (compressed output is independent of the level) so this job depends on sources only.
# Caller variables: CC OBJDIR ZSTD_DEFS ZLIB_DEFS Q FD_GUI_DIST

TOOL_DIR:=$(OBJDIR)/tool
TOOL_CFLAGS:=-O1 -std=c17 -fwrapv -pipe -w
TAB:=$(empty)	$(empty)

ZSTD_SRCS:=$(wildcard src/third_party/zstd/lib/common/*.c src/third_party/zstd/lib/compress/*.c)
ZLIB_SRCS:=$(wildcard src/third_party/zlib/*.c)
ZSTD_OBJS:=$(patsubst src/third_party/zstd/lib/%.c,$(TOOL_DIR)/zstd/%.o,$(ZSTD_SRCS))
ZLIB_OBJS:=$(patsubst src/third_party/zlib/%.c,$(TOOL_DIR)/zlib/%.o,$(ZLIB_SRCS))

# dry runs (-n/-q/-t) write nothing; their letters only count in a bare leading short-flag cluster
FD_MF1:=$(firstword $(MAKEFLAGS))
FD_MF1:=$(if $(findstring =,$(FD_MF1))$(filter -%,$(FD_MF1)),,$(FD_MF1))
FD_DRYRUN:=$(findstring n,$(FD_MF1))$(findstring q,$(FD_MF1))$(findstring t,$(FD_MF1))
ifeq ($(FD_DRYRUN),)
# the goals' directories and the object directories, once at parse time
$(shell mkdir -p $(sort $(dir $(MAKECMDGOALS) $(ZSTD_OBJS) $(ZLIB_OBJS))))
endif
.DELETE_ON_ERROR:
# parse-time stamps of the parent (see src/disco/gui/Local.mk); never remade here
$(OBJDIR)/.flags: ;@:
$(TOOL_DIR)/%.mlist: ;@:

# header edges from each object's last compile (depfile written to a tmp, published after success)
-include $(ZSTD_OBJS:.o=.d) $(ZLIB_OBJS:.o=.d)

# $(OBJDIR)/.flags: the parent's compiler+flags stamp, so a CC change rebuilds these too
$(TOOL_DIR)/zstd/%.o: src/third_party/zstd/lib/%.c src/third_party/zstd/Local.mk src/disco/gui/assets.mk $(OBJDIR)/.flags
	@$(info CC$(TAB)$(notdir $@))
	$(Q)$(CC) $(TOOL_CFLAGS) -MD -MP -MF $@.dtmp -isystem src/third_party/zstd/lib $(ZSTD_DEFS) -DZSTD_DISABLE_ASM -c $< -o $@ && mv -f $@.dtmp $(@:.o=.d)

$(TOOL_DIR)/zlib/%.o: src/third_party/zlib/%.c src/third_party/zlib/Local.mk src/disco/gui/assets.mk $(OBJDIR)/.flags
	@$(info CC$(TAB)$(notdir $@))
	$(Q)$(CC) $(TOOL_CFLAGS) -MD -MP -MF $@.dtmp $(ZLIB_DEFS) -c $< -o $@ && mv -f $@.dtmp $(@:.o=.d)

$(TOOL_DIR)/fd_zstd_pack: src/ballet/zstd/fd_zstd_pack.c $(ZSTD_OBJS) $(TOOL_DIR)/zstd.mlist
	@$(info LD$(TAB)$(notdir $@) (tool))
	$(Q)$(CC) $(TOOL_CFLAGS) -isystem src/third_party/zstd/lib $(filter %.c %.o,$^) -o $@

$(TOOL_DIR)/fd_gzip_pack: src/ballet/zstd/fd_gzip_pack.c $(ZLIB_OBJS) $(TOOL_DIR)/zlib.mlist
	@$(info LD$(TAB)$(notdir $@) (tool))
	$(Q)$(CC) $(TOOL_CFLAGS) $(filter %.c %.o,$^) -o $@

$(FD_GUI_DIST)_cmp/%.zst: $(FD_GUI_DIST)/% $(TOOL_DIR)/fd_zstd_pack src/disco/gui/assets.mk
	@$(info ZSTD$(TAB)$(notdir $@))
	$(Q)$(TOOL_DIR)/fd_zstd_pack 19 $< $@

$(FD_GUI_DIST)_cmp/%.gz: $(FD_GUI_DIST)/% $(TOOL_DIR)/fd_gzip_pack src/disco/gui/assets.mk
	@$(info GZIP$(TAB)$(notdir $@))
	$(Q)$(TOOL_DIR)/fd_gzip_pack 9 $< $@
