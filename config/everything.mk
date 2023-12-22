MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.SUFFIXES:
.PHONY: all info bin shared rust include lib unit-test fuzz-test run-unit-test run-script-test help clean distclean asm ppp show-deps seccomp-policies
.SECONDARY:
.SECONDEXPANSION:

OBJDIR:=$(BASEDIR)/$(BUILDDIR)
CORPUSDIR:=corpus

CPPFLAGS+=-DFD_BUILD_INFO=\"$(OBJDIR)/info\"
CPPFLAGS+=$(EXTRA_CPPFLAGS)

# Auxiliary rules that should not set up dependencies
AUX_RULES:=clean distclean help show-deps run-unit-test

all: info bin include lib unit-test

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
	# Explicit goals are: all bin shared include lib unit-test help clean distclean asm ppp
	# "make all" is equivalent to "make bin include lib unit-test"
	# "make info" makes build info $(OBJDIR)/info for the current platform (if not already made)
	# "make bin" makes all binaries for the current platform (except those requiring the Rust toolchain)
	# "make shared" makes all shared objects for the current platform. Requires EXTRAS=shared
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
	#   "make industry-bundle" makes an industry bundle. Requires EXTRAS="fuzz shared"

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
	config/test.sh --tests $(OBJDIR)/unit-test/automatic.txt $(TEST_OPTS)

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

ifeq "$(FD_HAS_MAIN)" "1"
add-scripts = $(foreach script,$(1),$(eval $(call _add-script,bin,$(script))))
add-test-scripts = $(foreach script,$(1),$(eval $(call _add-script,unit-test,$(script))))
endif

##############################
# Usage: $(call make-bin,name,objs,libs)
# Usage: $(call make-unit-test,name,objs,libs)
# Usage: $(call run-unit-test,name,args)
# Usage: $(call fuzz-test,name,objs,libs)

# Note: The library arguments require customization of each target

define _make-exe

DEPFILES+=$(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).d))

$(OBJDIR)/$(5)/$(1): $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) $(foreach lib,$(3),$(OBJDIR)/lib/lib$(lib).a)
	#######################################################################
	# Creating $(5) $$@ from $$^
	#######################################################################
	$(MKDIR) $$(dir $$@) && \
$(LD) -L$(OBJDIR)/lib $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) -Wl,--start-group $(foreach lib,$(3),-l$(lib)) $(LDFLAGS) -Wl,--end-group -o $$@

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

$(eval $(call _make-exe,$(1)/$(1),$(2),$(3),fuzz-test,fuzz-test))

.PHONY: $(1)_unit
$(1)_unit:
	$(MKDIR) "$(CORPUSDIR)/$(1)"
	$(FIND) $(CORPUSDIR)/$(1) -type f -exec $(OBJDIR)/fuzz-test/$(1)/$(1) $(FUZZFLAGS) {} +

.PHONY: $(1)_run
$(1)_run:
	$(MKDIR) "$(CORPUSDIR)/$(1)/explore"
	$(OBJDIR)/fuzz-test/$(1)/$(1) -artifact_prefix=$(CORPUSDIR)/$(1)/ $(FUZZFLAGS) $(CORPUSDIR)/$(1)/explore $(CORPUSDIR)/$(1)

run-fuzz-test: $(1)_unit

endef

define _make-shared
$(eval $(call _make-exe,$(1).so,$(2),$(3),shared,lib))
endef

ifeq "$(FD_HAS_MAIN)" "1"
make-bin       = $(eval $(call _make-exe,$(1),$(2),$(3),bin,bin))
make-bin-rust  = $(eval $(call _make-exe,$(1),$(2),$(3),rust,bin))
make-unit-test = $(eval $(call _make-exe,$(1),$(2),$(3),unit-test,unit-test))
fuzz-test:
	$(error Cannot build fuzz tests on this config. Ensure `fuzz` is part of EXTRAS)
run-unit-test = $(eval $(call _run-unit-test,$(1)))
run-fuzz-test:
	@echo "Requested run-fuzz-test but profile MACHINE=$(MACHINE) does not support fuzzing" >&2
	@exit 1
make-shared = $(eval $(call _make-shared,$(1),$(2),$(3)))
else
make-bin =
make-unit-test =
fuzz-test = $(eval $(call _fuzz-test,$(1),$(2),$(3)))
run-unit-test =
make-shared = $(eval $(call _make-shared,$(1),$(2),$(3)))
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

run-script-test:
	OBJDIR=$(OBJDIR) MACHINE=$(MACHINE) contrib/script-tests.sh

seccomp-policies:
	$(FIND) . -name '*.seccomppolicy' -exec $(PYTHON) contrib/generate_filters.py {} \;

industry-bundle: $(OBJDIR)/industry-bundle.zip

$(OBJDIR)/industry-bundle.zip: shared
	$(SHELL) contrib/package_industry_bundle.sh $(OBJDIR)
