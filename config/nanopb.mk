# Hooks up nanopb Protobuf generator with system if available
#
# Install using:
#
#     sudo dnf install -y protobuf-compiler python3.11 python3.11-pip
#     git clone https://github.com/nanopb/nanopb
#     cd nanopb
#     mkdir build
#     cd build
#     cmake .. -Dnanopb_PYTHON_INSTDIR_OVERRIDE=/usr/lib64/python3.11/site-packages
#     make -j
#     sudo make install
#
# Verify using: `make nanopb` in Firedancer

# Detect if nanopb is available
ifneq ($(shell command -v $(NANOPB)),)
NANOPB_AVAIL:=1
$(info Detected nanopb)
endif

ifdef NANOPB_AVAIL

##############################
# Usage: $(call gen-protobuf,protos)

.PHONY: nanopb
nanopb:

define _gen-protobuf

$(MKPATH)$(1).pb.h $(MKPATH)$(1).pb.c: $(MKPATH)$(1).proto
	#######################################################################
	# Generating Protobuf C sources from $(MKPATH)$(1).proto
	#######################################################################
	$(NANOPB) -I . $(MKPATH)$(1).proto
	@# Fixup pb.h include path
	$(SED) -i 's|<pb.h>|"src/flamenco/nanopb/pb.h"|g' $(MKPATH)$(1).pb.h
	@# Convert include paths from repo-relative to file-relative
	$(SED) -i -r 's|#include "(src\/.+)"|echo "#include \\"$$$$\(realpath --relative-to="$(MKPATH)" "\1"\)\\""|e' $(MKPATH)$(1).pb.h $(MKPATH)$(1).pb.c

nanopb: $(MKPATH)$(1).pb.h $(MKPATH)$(1).pb.c
GENERATED+=$(MKPATH)$(1).pb.h $(MKPATH)$(1).pb.c

endef

gen-protobuf = $(eval $(call _gen-protobuf,$(1)))

endif
