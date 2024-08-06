$(call add-hdrs,fd_http_server.h fd_hcache.h picohttpparser.h fd_sha1.h)
$(call add-objs,fd_http_server fd_hcache fd_picohttpparser fd_sha1,fd_ballet)

# Apply local patch to picohttpparser then compile to get the object
src/ballet/http/fd_picohttpparser.c: src/ballet/http/picohttpparser.c src/ballet/http/fd_picohttpparser.patch
	@echo "Applying patch to picohttpparser"
	$(CP) src/ballet/http/picohttpparser.c src/ballet/http/picohttpparsertemp.c
	$(PATCH) src/ballet/http/picohttpparsertemp.c src/ballet/http/fd_picohttpparser.patch
	$(CP) src/ballet/http/picohttpparsertemp.c src/ballet/http/fd_picohttpparser.c
	$(RM) src/ballet/http/picohttpparsertemp.c

$(OBJDIR)/obj/ballet/http/fd_picohttpparser.o: src/ballet/http/fd_picohttpparser.c

$(call make-unit-test,test_sha1,test_sha1,fd_ballet fd_util)
$(call run-unit-test,test_sha1)

$(call make-unit-test,test_http_server,test_http_server,fd_ballet fd_util)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_picohttpparser,fuzz_picohttpparser,fd_ballet fd_util)
endif
