_list: Makefile.build $(XKCBpath)/src/ToGlobalMakefile.xsl

bin/.build/Makefile: bin/.build/Makefile.expanded
	mkdir -p $(dir $@)
	xsltproc --param path "'$(XKCBpath)/src/'" --xinclude -o $@ $(XKCBpath)/src/ToGlobalMakefile.xsl $<

bin/.build/Makefile.expanded: Makefile.build
	mkdir -p $(dir $@)
	xsltproc --xinclude -o $@ $(XKCBpath)/src/ExpandProducts.xsl $<

-include bin/.build/Makefile

.PHONY: clean
clean:
	rm -rf bin/
