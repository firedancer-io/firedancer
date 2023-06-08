# Makefile

SIM             ?= questa
MODULE          = test
RTL_DIR         = $(pwd)../../rtl
TOPLEVEL        = ed25519_point_add
SIM_ARGS        += sim_build/work.glbl
TOPLEVEL_LANG   ?= verilog

VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/glbl.v
VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/unisims/DSP48E2.v
VERILOG_SOURCES += $(RTL_DIR)/wd_pkg.sv
VERILOG_SOURCES += $(RTL_DIR)/mul_wide.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_add_modp.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_sub_modp.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_mul_modp.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_point_add.sv

include $(shell cocotb-config --makefiles)/Makefile.sim
