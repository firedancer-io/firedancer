MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.SUFFIXES:
.PHONY: all info bin rust include lib unit-test integration-test fuzz-test help clean distclean asm ppp show-deps
.PHONY: run-unit-test run-integration-test run-script-test run-fuzz-test
.PHONY: seccomp-policies cov-report dist-cov-report
.SECONDARY:
.SECONDEXPANSION:

OBJDIR:=$(BASEDIR)/$(BUILDDIR)

CPPFLAGS+=-DFD_BUILD_INFO=\"$(OBJDIR)/info\"
CPPFLAGS+=$(EXTRA_CPPFLAGS)

# Auxiliary rules that should not set up dependencies
AUX_RULES:=clean distclean help show-deps run-unit-test run-integration-test cov-report dist-cov-report

all: info bin include lib unit-test fuzz-test

help:
	# Configuration
	# MACHINE         = $(MACHINE)
	# EXTRAS          = $(EXTRAS)
	# SHELL           = $(SHELL)
	# BASEDIR         = $(BASEDIR)
	# BUILDDIR        = $(BUILDDIR)
	# OBJDIR          = $(OBJDIR)
	# CPPFLAGS        = $(CPPFLAGS)
	# CC              = $(CC)
	# CFLAGS          = $(CFLAGS)
	# CXX             = $(CXX)
	# CXXFLAGS        = $(CXXFLAGS)
	# LD              = $(LD)
	# LDFLAGS         = $(LDFLAGS)
	# AR              = $(AR)
	# ARFLAGS         = $(ARFLAGS)
	# RANLIB          = $(RANLIB)
	# CP              = $(CP)
	# RM              = $(RM)
	# MKDIR           = $(MKDIR)
	# RMDIR           = $(RMDIR)
	# TOUCH           = $(TOUCH)
	# SED             = $(SED)
	# FIND            = $(FIND)
	# SCRUB           = $(SCRUB)
	# FUZZFLAGS       = $(FUZZFLAGS)
	# EXTRAS_CPPFLAGS = $(EXTRA_CPPFLAGS)
	# Explicit goals are: all bin include lib unit-test integration-test help clean distclean asm ppp
	# "make all" is equivalent to "make bin include lib unit-test fuzz-test"
	# "make info" makes build info $(OBJDIR)/info for the current platform (if not already made)
	# "make bin" makes all binaries for the current platform (except those requiring the Rust toolchain)
	# "make include" makes all include files for the current platform
	# "make lib" makes all libraries for the current platform
	# "make unit-test" makes all unit-tests for the current platform
	# "make integration-test" makes all integration-tests for the current platform
	# "make rust" makes all binaries for the current platform that require the Rust toolchain
	# "make run-unit-test" runs all unit-tests for the current platform. NOTE: this will not (re)build the test executables
	# "make run-integration-test" runs all integration-tests for the current platform. NOTE: this will not (re)build the test executables
	# "make help" prints this message
	# "make clean" removes editor temp files and the current platform build
	# "make distclean" removes editor temp files and all platform builds
	# "make asm" makes all source files into assembly language files
	# "make ppp" run all source files through the preprocessor
	# "make show-deps" shows all the dependencies
	# "make cov-report" creates an LCOV coverage report from LLVM profdata. Requires make run-unit-test EXTRAS="llvm-cov"
	# Fuzzing (requires fuzzing profile):
	#   "make fuzz-test" makes all fuzz-tests for the current platform
	#   "make run-fuzz-test" re-runs all fuzz tests over existing corpora
	#   "make fuzz_TARGET_unit" re-runs a specific fuzz-test over the existing corpus
	#   "make fuzz_TARGET_run" runs a specific fuzz-test in explore mode for 600 seconds

info: $(OBJDIR)/info

clean:
	#######################################################################
	# Cleaning $(OBJDIR)
	#######################################################################
	$(RMDIR) $(OBJDIR) && $(RMDIR) target && $(RMDIR) solana/target && \
$(SCRUB)

distclean:
	#######################################################################
	# Cleaning $(BASEDIR)
	#######################################################################
	$(RMDIR) $(BASEDIR) && $(RMDIR) target && $(RMDIR) solana/target && \
$(SCRUB)

run-unit-test:
	#######################################################################
	# Running unit tests
	#######################################################################
	contrib/test/run_unit_tests.sh --tests $(OBJDIR)/unit-test/automatic.txt $(TEST_OPTS)

run-integration-test:
	#######################################################################
	# Running integration tests
	#######################################################################
	contrib/test/run_integration_tests.sh --tests $(OBJDIR)/integration-test/automatic.txt $(TEST_OPTS)

##############################
# Usage: $(call make-lib,name)

define _make-lib

lib: $(OBJDIR)/lib/lib$(1).a

endef

make-lib = $(eval $(call _make-lib,$(1)))

##############################
# Usage: $(call add-objs,objs,lib)

define _add-objs

DEPFILES+=$(foreach obj,$(1),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).d))

$(OBJDIR)/lib/lib$(2).a: $(foreach obj,$(1),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o))

endef

add-objs = $(eval $(call _add-objs,$(1),$(2)))

##############################
# Usage: $(call add-asms,asms,lib)

define _add-asms

$(OBJDIR)/lib/lib$(2).a: $(foreach obj,$(1),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o))

endef

add-asms = $(eval $(call _add-asms,$(1),$(2)))

##############################
# Usage: $(call add-hdrs,hdrs)

define _add-hdrs

include: $(foreach hdr,$(1),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/include/%,$(OBJDIR)/$(MKPATH)$(hdr)))

endef

add-hdrs = $(eval $(call _add-hdrs,$(1)))

##############################
# Usage: $(call add-examples,examples)

define _add-examples

include: $(foreach example,$(1),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/example/%,$(OBJDIR)/$(MKPATH)$(example)))

endef

add-examples = $(eval $(call _add-examples,$(1)))

##############################
# Usage: $(call add-scripts,scripts)
# Usage: $(call add-test-scripts,scripts)

# Note: This doesn't mirror the directory hierarchy so can't use use
# generic rule

define _add-script

$(OBJDIR)/$(1)/$(2): $(MKPATH)$(2)
	#######################################################################
	# Copying script $$^ to $$@
	#######################################################################
	$(MKDIR) $$(dir $$@) && \
$(CP) $$< $$@ && \
chmod 755 $$@ && \
$(TOUCH) $$@

$(1): $(OBJDIR)/$(1)/$(2)

endef

add-scripts = $(foreach script,$(1),$(eval $(call _add-script,bin,$(script))))
add-test-scripts = $(foreach script,$(1),$(eval $(call _add-script,unit-test,$(script))))

##############################
# Usage: $(call make-bin,name,objs,libs)
# Usage: $(call make-shared,name,objs,libs)
# Usage: $(call make-unit-test,name,objs,libs)
# Usage: $(call make-integration-test,name,objs,libs)
# Usage: $(call run-unit-test,name,args)
# Usage: $(call run-integration-test,name,args)
# Usage: $(call make-fuzz-test,name,objs,libs)

# Note: The library arguments require customization of each target

# _make-exe usage:
#
#   $(1): Filename of exe
#   $(2): List of objects
#   $(3): List of libraries
#   $(4): Name of meta target (such that make $(4) will include this target)
#   $(5): Subdirectory of target
#   $(6): Extra LDFLAGS
define _make-exe

DEPFILES+=$(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).d))

$(OBJDIR)/$(5)/$(1): $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) $(foreach lib,$(3),$(OBJDIR)/lib/lib$(lib).a)
	#######################################################################
	# Creating $(5) $$@ from $$^
	#######################################################################
	$(MKDIR) $$(dir $$@) && \
$(LD) -L$(OBJDIR)/lib $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) -Wl,--start-group $(foreach lib,$(3),-l$(lib)) -Wl,--end-group $(6) $(LDFLAGS) -o $$@

$(4): $(OBJDIR)/$(5)/$(1)

endef

# Generate list of automatic unit tests from $(call run-unit-test,...)
unit-test: $(OBJDIR)/unit-test/automatic.txt
define _run-unit-test
RUN_UNIT_TEST+=$(OBJDIR)/unit-test/$(1)
endef
$(OBJDIR)/unit-test/automatic.txt:
	$(MKDIR) "$(OBJDIR)/unit-test"
	@$(foreach test,$(RUN_UNIT_TEST),echo $(test)>>$@;)

# Generate list of automatic integration tests from $(call run-integration-test,...)
integration-test: $(OBJDIR)/integration-test/automatic.txt
define _run-integration-test
RUN_INTEGRATION_TEST+=$(OBJDIR)/integration-test/$(1)
endef
$(OBJDIR)/integration-test/automatic.txt:
	$(MKDIR) "$(OBJDIR)/integration-test"
	@$(foreach test,$(RUN_INTEGRATION_TEST),echo $(test)>>$@;)
	$(TOUCH) "$@"

ifndef FD_HAS_FUZZ
FUZZ_EXTRA:=$(OBJDIR)/lib/libfd_fuzz_stub.a
endif

define _fuzz-test

$(eval $(call _make-exe,$(1)/$(1),$(2),$(3),fuzz-test,fuzz-test,$(LDFLAGS_FUZZ) $(FUZZ_EXTRA)))

$(OBJDIR)/fuzz-test/$(1)/$(1): $(FUZZ_EXTRA)

.PHONY: $(1)_unit
$(1)_unit:
	$(MKDIR) "corpus/$(1)" && \
$(MKDIR) -p "$(OBJDIR)/cov/raw" && \
FD_LOG_PATH="" \
LLVM_PROFILE_FILE="$(OBJDIR)/cov/raw/$(1)_unit.profraw" \
$(FIND) corpus/$(1) -type f -exec $(OBJDIR)/fuzz-test/$(1)/$(1) $(FUZZFLAGS) {} +

.PHONY: $(1)_run
$(1)_run:
	$(MKDIR) "corpus/$(1)/explore" && \
$(MKDIR) -p "$(OBJDIR)/cov/raw" && \
FD_LOG_PATH="" \
LLVM_PROFILE_FILE="$(OBJDIR)/cov/raw/$(1)_run.profraw" \
$(OBJDIR)/fuzz-test/$(1)/$(1) -artifact_prefix=corpus/$(1)/ $(FUZZFLAGS) corpus/$(1)/explore corpus/$(1)

run-fuzz-test: $(1)_unit

endef

make-bin       = $(eval $(call _make-exe,$(1),$(2),$(3),bin,bin,$(4)))
make-bin-rust  = $(eval $(call _make-exe,$(1),$(2),$(3),rust,bin,$(4)))
make-shared    = $(eval $(call _make-exe,$(1),$(2),$(3),lib,lib,-shared $(4)))
make-unit-test = $(eval $(call _make-exe,$(1),$(2),$(3),unit-test,unit-test,$(4)))
run-unit-test  = $(eval $(call _run-unit-test,$(1)))
make-integration-test = $(eval $(call _make-exe,$(1),$(2),$(3),integration-test,integration-test,$(4)))
run-integration-test  = $(eval $(call _run-integration-test,$(1)))
make-fuzz-test = $(eval $(call _fuzz-test,$(1),$(2),$(3)))

##############################
## GENERIC RULES

$(OBJDIR)/info :
	#######################################################################
	# Saving build info to $(OBJDIR)/info
	#######################################################################
	$(MKDIR) $(dir $@) && \
echo -e \
"# date     `date +'%Y-%m-%d %H:%M:%S %z'`\n"\
"# source   `whoami`@`hostname`:`pwd`\n"\
"# machine  $(MACHINE)\n"\
"# extras   $(EXTRAS)" > $(OBJDIR)/info && \
git status --porcelain=2 --branch >> $(OBJDIR)/info

$(OBJDIR)/obj/%.d : src/%.c $(OBJDIR)/info
	#######################################################################
	# Generating dependencies for C source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -M -MP $< -o $@.tmp && \
$(SED) 's,\($(notdir $*)\)\.o[ :]*,$(OBJDIR)/obj/$*.o $(OBJDIR)/obj/$*.S $(OBJDIR)/obj/$*.i $@ : ,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.d : src/%.cxx $(OBJDIR)/info
	#######################################################################
	# Generating dependencies for C++ source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MP $< -o $@.tmp && \
$(SED) 's,\($(notdir $*)\)\.o[ :]*,$(OBJDIR)/obj/$*.o $(OBJDIR)/obj/$*.S $(OBJDIR)/obj/$*.i $@ : ,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.o : src/%.c $(OBJDIR)/info
	#######################################################################
	# Compiling C source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/obj/%.o : src/%.cxx $(OBJDIR)/info
	#######################################################################
	# Compiling C++ source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/obj/%.o : src/%.S $(OBJDIR)/info
	#######################################################################
	# Compiling asm source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/obj/%.S : src/%.c $(OBJDIR)/info
	#######################################################################
	# Compiling C source $< to assembly $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(patsubst -g,,$(CPPFLAGS) $(CFLAGS)) -S -fverbose-asm $< -o $@.tmp && \
$(SED) 's,^#,                                                                                               #,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.S : src/%.cxx $(OBJDIR)/info
	#######################################################################
	# Compiling C++ source $< to assembly $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(patsubst -g,,$(CPPFLAGS) $(CXXFLAGS)) -S -fverbose-asm $< -o $@.tmp && \
$(SED) 's,^#,                                                                                               #,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.i : src/%.c $(OBJDIR)/info
	#######################################################################
	# Preprocessing C source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -E $< -o $@

$(OBJDIR)/obj/%.i : src/%.cxx $(OBJDIR)/info
	#######################################################################
	# Preprocessing C++ source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(CPPFLAGS) $(CXXFLAGS) -E $< -o $@

$(OBJDIR)/lib/%.a :
	#######################################################################
	# Creating library $@ from $^
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(RM) $@ && \
$(AR) $(ARFLAGS) $@ $^ && \
$(RANLIB)  $@

$(OBJDIR)/include/% : src/%
	#######################################################################
	# Copying header $^ to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CP) $^ $@ && \
$(TOUCH) $@

$(OBJDIR)/example/% : src/%
	#######################################################################
	# Copying example $^ to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CP) $^ $@ && \
$(TOUCH) $@

ifeq ($(filter $(MAKECMDGOALS),$(AUX_RULES)),)
# If we are not in an auxiliary rule (aka we need to actually build something/need dep tree)

# Include all the make fragments

define _include-mk
MKPATH:=$(dir $(1))
include $(1)
MKPATH:=
endef

# Don't use "-L" if source code directory structure has symlink loops
$(foreach mk,$(shell $(FIND) -L src -type f -name Local.mk),$(eval $(call _include-mk,$(mk))))

# Include all the dependencies.  Must be after the make fragments
# include so that DEPFILES is fully populated (similarly for the
# show-deps target).

show-deps:
	@for d in $(DEPFILES); do echo $$d; done

include $(DEPFILES)

# Define the asm target.  Must be after the make fragments include so that
# DEPFILES is fully populated

asm: $(DEPFILES:.d=.S)

# Define the ppp target.  Must be after the make fragments include so that
# DEPFILES is fully populated

ppp: $(DEPFILES:.d=.i)

endif

run-script-test: bin unit-test
	mkdir -p "$(OBJDIR)/cov/raw" && \
OBJDIR=$(OBJDIR) \
MACHINE=$(MACHINE) \
LLVM_PROFILE_FILE="$(OBJDIR)/cov/raw/script_test-%p.profraw" \
contrib/test/run_script_tests.sh

seccomp-policies:
	$(FIND) . -name '*.seccomppolicy' -exec $(PYTHON) contrib/codegen/generate_filters.py {} \;

##############################
# LLVM Coverage
#
# Below steps create a report which lines of code have been executed/
# "covered" by tests.  For convenience, below supports merging coverage
# data from multiple machine types.
#
# Enabling the 'llvm-cov' extra has two effects on clang-compiled objects:
# - Coverage instrumentation is inserted, which causes profile data
#   to get written out to disk when running code
# - Adds an "__llvm_covmap" section to each object containing "coverage
#   mappings".   Those tells tooling how to translate profile data to
#   source line coverage
#
# Documentation:
#   https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
#   https://llvm.org/docs/CoverageMappingFormat.html
#   https://man.archlinux.org/man/lcov.1.en
#
# We thus have these steps
#
# 1. For each machine
# 1.1. Compile with llvm-cov
# 1.2. Run tests (This Makefile sets $LLVM_PROFILE_DATA appropriately for each kind of test)
# 1.3. Merge raw profiles from test runs into a per-machine profile using 'llvm-profdata merge'
# 1.4. Merge all machine objects into a thin .ar file
# 1.5. Generate lcov tracefile from coverage mappings (step 1.4) and indexed profile data (step 1.3)
# 1.6. Generate machine-specific HTML report using 'genhtml'
#
# 2. Once across all machines
# 2.1. Merge lcov tracefiles using 'lcov -a'
# 2.2. Generate combined HTML report using 'genhtml'

# llvm-cov step 1.3: Merge and index "raw" profile data from test runs
$(OBJDIR)/cov/cov.profdata: $(wildcard $(OBJDIR)/cov/raw/*.profraw)
	$(MKDIR) $(OBJDIR)/cov && $(LLVM_PROFDATA) merge -o $@ $^

# llvm-cov step 1.4
# Create a thin archive containing all objects with coverage mappings.
# Sigh ... llvm-cov has a bug that makes it blow up when it encounters
# any object in the archive without an __llvm_covmap section, such as
# objects compiled from assembly code.
.PHONY: $(OBJDIR)/cov/mappings.ar
$(OBJDIR)/cov/mappings.ar:
	rm -f $(OBJDIR)/cov/mappings.ar &&                       \
  $(MKDIR) $(dir $@) &&                                    \
  find $(addsuffix /obj,$(OBJDIR)) -name '*.o' -exec sh -c \
    '[ -n "`llvm-objdump -h $$1 | grep llvm_covmap`" ]     \
    && llvm-ar --thin q $@ $$1' sh {} \;

# llvm-cov step 1.5
$(OBJDIR)/cov/cov.lcov: $(addsuffix /cov/cov.profdata,$(OBJDIR)) $(OBJDIR)/cov/mappings.ar
ifeq ($(OBJDIR),)
	echo "No profile data found. Did you set OBJDIRS?" >&2 && exit 1
endif
	$(LLVM_COV) export                    \
  -format=lcov                          \
  $(addprefix -instr-profile=,$<)       \
  $(OBJDIR)/cov/mappings.ar             \
  --ignore-filename-regex="test_.*\\.c" \
> $@

# llvm-cov step 2.1
# Merge multiple lcov files together
$(BASEDIR)/cov/cov.lcov: $(shell find $(BASEDIR) -name 'cov.lcov' -print)
	$(MKDIR) $(BASEDIR)/cov && $(LCOV) -o $@ $(addprefix -a ,$^)

# llvm-cov step 1.6, 2.2
# Create HTML coverage report using lcov genhtml
%/cov/html/index.html: %/cov/cov.lcov
	rm -rf $(dir $@) && $(GENHTML) --output $(dir $@) $<
	@echo "Created coverage report at $@"

# `make cov-report` produces a coverage report from test runs for the
# currently selected build profile
cov-report: $(OBJDIR)/cov/html/index.html
	$(LCOV) --summary $(OBJDIR)/cov/cov.lcov

# `make dist-cov-report OBJDIRS="build/native/gcc build/native/clang ..."`
# produces a coverage report from multiple build profiles
dist-cov-report: $(BASEDIR)/cov/html/index.html
	$(LCOV) --summary $(BASEDIR)/cov/cov.lcov
