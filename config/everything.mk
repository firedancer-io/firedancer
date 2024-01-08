MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.SUFFIXES:
.PHONY: all info bin rust include lib unit-test fuzz-test help clean distclean asm ppp show-deps
.PHONY: run-unit-test run-script-test run-fuzz-test run-integration-test
.PHONY: seccomp-policies cov-report dist-cov-report
.SECONDARY:
.SECONDEXPANSION:

OBJDIR:=$(BASEDIR)/$(BUILDDIR)

CPPFLAGS+=-DFD_BUILD_INFO=\"$(OBJDIR)/info\"
CPPFLAGS+=$(EXTRA_CPPFLAGS)

# Auxiliary rules that should not set up dependencies
AUX_RULES:=clean distclean help show-deps run-unit-test cov-report dist-cov-report

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
	# SED             = $(SED)
	# FIND            = $(FIND)
	# SCRUB           = $(SCRUB)
	# FUZZFLAGS       = $(FUZZFLAGS)
	# EXTRAS_CPPFLAGS = $(EXTRA_CPPFLAGS)
	# Explicit goals are: all bin include lib unit-test help clean distclean asm ppp
	# "make all" is equivalent to "make bin include lib unit-test"
	# "make info" makes build info $(OBJDIR)/info for the current platform (if not already made)
	# "make bin" makes all binaries for the current platform (except those requiring the Rust toolchain)
	# "make include" makes all include files for the current platform
	# "make lib" makes all libraries for the current platform
	# "make unit-test" makes all unit-tests for the current platform
	# "make rust" makes all binaries for the current platform that require the Rust toolchain
	# "make run-unit-test" runs all unit-tests for the current platform. NOTE: this will not (re)build the test executables
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
chmod 755 $$@

$(1): $(OBJDIR)/$(1)/$(2)

endef

add-scripts = $(foreach script,$(1),$(eval $(call _add-script,bin,$(script))))
add-test-scripts = $(foreach script,$(1),$(eval $(call _add-script,unit-test,$(script))))

##############################
# Usage: $(call make-bin,name,objs,libs)
# Usage: $(call make-unit-test,name,objs,libs)
# Usage: $(call run-unit-test,name,args)
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
$(LD) -L$(OBJDIR)/lib $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) -Wl,--start-group $(foreach lib,$(3),-l$(lib)) -Wl,--end-group $(LDFLAGS) $(6) -o $$@

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

define _fuzz-test

$(eval $(call _make-exe,$(1)/$(1),$(2),$(3),fuzz-test,fuzz-test,$(LDFLAGS_FUZZ)))

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

make-bin       = $(eval $(call _make-exe,$(1),$(2),$(3),bin,bin))
make-bin-rust  = $(eval $(call _make-exe,$(1),$(2),$(3),rust,bin))
make-unit-test = $(eval $(call _make-exe,$(1),$(2),$(3),unit-test,unit-test))
run-unit-test  = $(eval $(call _run-unit-test,$(1)))
ifdef FD_HAS_FUZZ
make-fuzz-test = $(eval $(call _fuzz-test,$(1),$(2),$(3)))
endif

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
$(CP) $^ $@

$(OBJDIR)/example/% : src/%
	#######################################################################
	# Copying example $^ to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CP) $^ $@

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
LLVM_PROFILE_FILE="$(OBJDIR)/cov/raw/script_tests.profraw" \
contrib/test/run_script_tests.sh

run-integration-test: fddev
	mkdir -p "$(OBJDIR)/cov/raw" && \
OBJDIR=$(OBJDIR) \
LLVM_PROFILE_FILE="$(OBJDIR)/cov/raw/integration_tests.profraw" \
contrib/test/run_integration_tests.sh

seccomp-policies:
	$(FIND) . -name '*.seccomppolicy' -exec $(PYTHON) contrib/test/generate_filters.py {} \;

##############################
# Coverage

# Merge and index "raw" profile data from test runs
$(OBJDIR)/cov/cov.profdata: $(wildcard $(OBJDIR)/cov/raw/*.profraw)
	mkdir -p $(OBJDIR)/cov && $(LLVM_PROFDATA) merge -o $@ $^
#
# Usage: $(call make-lcov,<report_objdir>,<profdata_objdirs>)
# e.g. $(call make-lcov,build/cov,build/machine1 build/machine2)
#      will create build/cov/cov.lcov from build/machine{1,2}/cov/cov.profdata
define _make-lcov
$(1)/cov/cov.lcov: $$(addsuffix /cov/cov.profdata,$(2))
ifeq ($(2),)
	echo "No profile data found. Did you set OBJDIRS?" >&2 && exit 1
endif
	mkdir -p $$(dir $$@) &&				 						   \
$(LLVM_COV) export                             \
  -format=lcov                                 \
  $$(addprefix -instr-profile=,$$<)            \
  $$(foreach dir,$(2),$$(shell find $(2)/obj   \
      -name '*.o'                              \
      -exec printf "-object=%q\n" {} \;))      \
  --ignore-filename-regex="test_.*\\.c"        \
> $$@
endef
make-lcov = $(eval $(call _make-lcov,$(1),$(2)))

# Create lcov report for current target
$(call make-lcov,$(OBJDIR),$(OBJDIR))

# Create HTML coverage report using lcov genhtml
%/cov/html/index.html: %/cov/cov.lcov
	rm -rf $(dir $@) && $(GENHTML) --output $(dir $@) $<
	@echo "Created coverage report at $@"

# `make cov-report` produces a coverage report from test runs for the
# currently selected build profile
cov-report: $(OBJDIR)/cov/html/index.html

# `make dist-cov-report OBJDIRS="build/native/gcc build/native/clang ..."`
# produces a coverage report from multiple build profiles
$(call make-lcov,$(BASEDIR),$(OBJDIRS))
dist-cov-report: $(BASEDIR)/cov/html/index.html
