$(call add-hdrs,$(notdir $(wildcard $(MKPATH)/*.h)))
$(call add-objs,$(patsubst %.c,%,$(notdir $(wildcard $(MKPATH)/*.c))),fd_disco)
