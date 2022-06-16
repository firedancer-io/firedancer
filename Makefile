ifndef MACHINE
$(warning MACHINE not specified, using default)
MACHINE=rh8_x86_64
endif

$(info Using MACHINE=$(MACHINE))

include config/$(MACHINE).mk
include config/everything.mk

