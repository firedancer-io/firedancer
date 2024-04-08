# Makefile

SIM             ?= questa
MODULE          = test
RTL_DIR         = $(pwd)../../rtl
TOPLEVEL        = mul_wide
SIM_ARGS        += sim_build/work.glbl
TOPLEVEL_LANG   ?= verilog

VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/glbl.v
VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/unisims/DSP48E2.v
VERILOG_SOURCES += $(RTL_DIR)/wd_pkg.sv
VERILOG_SOURCES += $(RTL_DIR)/mul_wide.sv

include $(shell cocotb-config --makefiles)/Makefile.sim
