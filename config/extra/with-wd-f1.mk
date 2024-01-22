# AWS-F1
INCLUDES+=-I$(SDK_DIR)/userspace/include
INCLUDES+=-I$(SDK_DIR)/userspace/fpga_libs/fpga_mgmt/
INCLUDES+=-I $(HDK_DIR)/common/software/include
CPPFLAGS+=-DCONFIG_LOGLEVEL=4 $(INCLUDES)
CPPFLAGS+=-DFD_HAS_WIREDANCER=1
LDFLAGS+=-L /usr/local/lib64 -lfpga_mgmt
