MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.SUFFIXES:
.SUFFIXES: .h .hxx .c .cxx .o .a .d .S .i
.PHONY: all bin include lib unit-test help clean distclean asm ppp show-deps
.SECONDARY:
.SECONDEXPANSION:

BASEDIR:=build
OBJDIR:=$(BASEDIR)/$(BUILDDIR)

all: bin include lib unit-test

help:
	# Configuration
	# MACHINE  = $(MACHINE)
	# SHELL    = $(SHELL)
	# BASEDIR  = $(BASEDIR)
	# OBJDIR   = $(OBJDIR)
	# CPPFLAGS = $(CPPFLAGS)
	# CC       = $(CC)
	# CFLAGS   = $(CFLAGS)
	# CXX      = $(CXX)
	# CXXFLAGS = $(CXXFLAGS)
	# LD       = $(LD)
	# LDFLAGS  = $(LDFLAGS)
	# AR       = $(AR)
	# ARFLAGS  = $(ARFLAGS)
	# RANLIB   = $(RANLIB)
	# CP       = $(CP)
	# RM       = $(RM)
	# MKDIR    = $(MKDIR)
	# RMDIR    = $(RMDIR)
	# SED      = $(SED)
	# FIND     = $(FIND)
	# SCRUB    = $(SCRUB)
	# Explicit goals are: all bin include lib unit-test help clean distclean asm ppp
	# "make all" is equivalent to "make bin include lib unit-test"
	# "make bin" makes all binaries for the current platform
	# "make include" makes all include files for the current platform
	# "make lib" makes all libraries for the current platform
	# "make unit-test" makes all unit-tests for the current platform
	# "make help" prints this message
	# "make clean" removes editor temp files and the current platform build
	# "make distclean" removes editor temp files and all platform builds
	# "make asm" makes all source files into assembly language files
	# "make ppp" run all source files through the preprocessor
	# "make show-deps" shows all the dependencies

clean:
	#######################################################################
	# Cleaning $(OBJDIR)
	#######################################################################
	$(RMDIR) $(OBJDIR) && \
$(SCRUB)

distclean:
	#######################################################################
	# Cleaning $(BASEDIR)
	#######################################################################
	$(RMDIR) $(BASEDIR) && \
$(SCRUB)

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

# Note: The library arguments require customization of each target

define _make-exe

DEPFILES+=$(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).d))

$(OBJDIR)/$(4)/$(1): $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) $(foreach lib,$(3),$(OBJDIR)/lib/lib$(lib).a)
	#######################################################################
	# Creating $(4) $$@ from $$^
	#######################################################################
	$(MKDIR) $$(dir $$@) && \
$(LD) -L$(OBJDIR)/lib $(foreach obj,$(2),$(patsubst $(OBJDIR)/src/%,$(OBJDIR)/obj/%,$(OBJDIR)/$(MKPATH)$(obj).o)) $(foreach lib,$(3),-l$(lib)) $(LDFLAGS) -o $$@

$(4): $(OBJDIR)/$(4)/$(1)

endef

make-bin       = $(eval $(call _make-exe,$(1),$(2),$(3),bin))
make-unit-test = $(eval $(call _make-exe,$(1),$(2),$(3),unit-test))

##############################
## GENERIC RULES

$(OBJDIR)/obj/%.d : src/%.c
	#######################################################################
	# Generating dependencies for C source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -M -MP $< -o $@.tmp && \
$(SED) 's,\($(notdir $*)\)\.o[ :]*,$(OBJDIR)/obj/$*.o $(OBJDIR)/obj/$*.S $(OBJDIR)/obj/$*.i $@ : ,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.d : src/%.cxx
	#######################################################################
	# Generating dependencies for C++ source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MP $< -o $@.tmp && \
$(SED) 's,\($(notdir $*)\)\.o[ :]*,$(OBJDIR)/obj/$*.o $(OBJDIR)/obj/$*.S $(OBJDIR)/obj/$*.i $@ : ,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.o : src/%.c
	#######################################################################
	# Compiling C source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/obj/%.o : src/%.cxx
	#######################################################################
	# Compiling C++ source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/obj/%.o : src/%.S
	#######################################################################
	# Compiling asm source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/obj/%.S : src/%.c
	#######################################################################
	# Compiling C source $< to assembly $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(patsubst -g,,$(CPPFLAGS) $(CFLAGS)) -S -fverbose-asm $< -o $@.tmp && \
$(SED) 's,^#,                                                                                               #,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.S : src/%.cxx
	#######################################################################
	# Compiling C++ source $< to assembly $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CXX) $(patsubst -g,,$(CPPFLAGS) $(CXXFLAGS)) -S -fverbose-asm $< -o $@.tmp && \
$(SED) 's,^#,                                                                                               #,g' < $@.tmp > $@ && \
$(RM) $@.tmp

$(OBJDIR)/obj/%.i : src/%.c
	#######################################################################
	# Preprocessing C source $< to $@
	#######################################################################
	$(MKDIR) $(dir $@) && \
$(CC) $(CPPFLAGS) $(CFLAGS) -E $< -o $@

$(OBJDIR)/obj/%.i : src/%.cxx
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

ifneq ($(MAKECMDGOALS),distclean)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),help)

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
endif
endif

