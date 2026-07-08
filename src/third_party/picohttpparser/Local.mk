# Apply local patch to picohttpparser then compile to get the object
src/third_party/picohttpparser/fd_picohttpparser.c: src/third_party/picohttpparser/picohttpparser.c src/third_party/picohttpparser/fd_picohttpparser.patch
	@echo "Applying patch to picohttpparser"
	$(CP) src/third_party/picohttpparser/picohttpparser.c src/third_party/picohttpparser/picohttpparsertemp.c
	$(PATCH) src/third_party/picohttpparser/picohttpparsertemp.c src/third_party/picohttpparser/fd_picohttpparser.patch
	$(CP) src/third_party/picohttpparser/picohttpparsertemp.c src/third_party/picohttpparser/fd_picohttpparser.c
	$(RM) src/third_party/picohttpparser/picohttpparsertemp.c

$(OBJDIR)/obj/third_party/picohttpparser/fd_picohttpparser.o: src/third_party/picohttpparser/fd_picohttpparser.c

ifdef FD_HAS_HOSTED
$(call add-hdrs,picohttpparser.h)
$(call add-objs,fd_picohttpparser,fd_waltz)

$(call make-fuzz-test,fuzz_picohttpparser,fuzz_picohttpparser,fd_waltz fd_util)
endif
