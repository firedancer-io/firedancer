$(call add-hdrs,picohttpparser.h)
$(call add-objs,fd_picohttpparser,fd_ballet)

# Apply local patch to picohttpparser then compile to get the object
src/ballet/http/fd_picohttpparser.c: src/ballet/http/picohttpparser.c src/ballet/http/fd_picohttpparser.patch
	@echo "Applying patch to picohttpparser"
	$(CP) src/ballet/http/picohttpparser.c src/ballet/http/picohttpparsertemp.c
	$(PATCH) src/ballet/http/picohttpparsertemp.c src/ballet/http/fd_picohttpparser.patch
	$(CP) src/ballet/http/picohttpparsertemp.c src/ballet/http/fd_picohttpparser.c
	$(RM) src/ballet/http/picohttpparsertemp.c

$(OBJDIR)/obj/ballet/http/fd_picohttpparser.o: src/ballet/http/fd_picohttpparser.c

$(call make-fuzz-test,fuzz_picohttpparser,fuzz_picohttpparser,fd_ballet fd_util)
