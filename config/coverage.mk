.PHONY: cov-report

COVDIR:=$(OBJDIR)/cov

cov-report: $(COVDIR)/html

# Create HTML coverage report using lcov genhtml
.PHONY: $(COVDIR)/html
$(COVDIR)/html: $(COVDIR)/cov.lcov
	rm -rf $@
	$(GENHTML) --output $@ $<
	@echo "Created coverage report at $@"

# Export lcov report from indexed profile
.PHONY: $(COVDIR)/cov.lcov
$(COVDIR)/cov.lcov: $(COVDIR)/cov.profdata
	$(LLVM_COV) export                         \
	  -format=lcov                             \
	  -instr-profile=$<                        \
	  $(shell find $(OBJDIR)/obj               \
	    -name '*.o'                            \
	    -exec printf "-object=%q\n" {} \;)     \
	  --ignore-filename-regex="test_.*\\.c"    \
	> $@

# Index raw profiles
$(COVDIR)/cov.profdata: $(wildcard $(COVDIR)/raw/*.profraw)
	@mkdir -p $(COVDIR)
	$(LLVM_PROFDATA) merge -o $@ $^


COMBICOVDIR:=$(BASEDIR)/combi-cov

# Make coverage report mixing coverage info for build under build/linux/clang/combi/
combicov-report: $(COMBICOVDIR)/html
.PHONY: $(COMBICOVDIR)/html
$(COMBICOVDIR)/html: $(COMBICOVDIR)/cov.lcov
	rm -rf $@
	$(GENHTML) --output $@ $<
	@echo "Created coverage report at $@"

.PHONY: $(COVDIR)/cov.lcov
$(COMBICOVDIR)/cov.lcov: $(COMBICOVDIR)/cov.profdata
	$(LLVM_COV) export                         \
	  -format=lcov                             \
	  -instr-profile=$<                        \
	  $(shell find $(OBJDIR)/obj               \
	    -name '*.o'                            \
	    -exec printf "-object=%q\n" {} \;)     \
	  --ignore-filename-regex="test_.*\\.c"    \
	> $@

$(COMBICOVDIR)/cov.profdata: $(wildcard build/linux/clang/combi/*/cov/raw/*.profraw)
	@mkdir -p $(COMBICOVDIR)
	$(LLVM_PROFDATA) merge -o $@ $^
