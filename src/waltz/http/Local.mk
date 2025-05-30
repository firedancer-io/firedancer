$(call add-hdrs,fd_http_server.h picohttpparser.h)
$(call add-objs,fd_http_server fd_picohttpparser,fd_waltz)

# Apply local patch to picohttpparser then compile to get the object
src/waltz/http/fd_picohttpparser.c: src/waltz/http/picohttpparser.c src/waltz/http/fd_picohttpparser.patch
	@echo "Applying patch to picohttpparser"
	$(CP) src/waltz/http/picohttpparser.c src/waltz/http/picohttpparsertemp.c
	$(PATCH) src/waltz/http/picohttpparsertemp.c src/waltz/http/fd_picohttpparser.patch
	$(CP) src/waltz/http/picohttpparsertemp.c src/waltz/http/fd_picohttpparser.c
	$(RM) src/waltz/http/picohttpparsertemp.c

$(OBJDIR)/obj/waltz/http/fd_picohttpparser.o: src/waltz/http/fd_picohttpparser.c

$(call make-unit-test,test_http_server,test_http_server,fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_http_server)

$(call make-unit-test,test_live_http_server,test_live_http_server,fd_waltz fd_ballet fd_util)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_picohttpparser,fuzz_picohttpparser,fd_waltz fd_util)
$(call make-fuzz-test,fuzz_httpserver,fuzz_httpserver,fd_waltz fd_ballet fd_util)
endif

$(call add-hdrs,fd_url.h)
$(call add-objs,fd_url,fd_waltz)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_url_parse,fuzz_url_parse,fd_waltz fd_util)
endif
