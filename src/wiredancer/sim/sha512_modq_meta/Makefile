# Makefile

SIM             ?= questa
MODULE          = test
RTL_DIR         = $(pwd)../../rtl
TOPLEVEL        = sha512_modq_meta
SIM_ARGS        += sim_build/work.glbl
TOPLEVEL_LANG   ?= verilog

VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/glbl.v
VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/unisims/DSP48E2.v
VERILOG_SOURCES += $(XILINX_VIVADO)/data/ip/xpm/xpm_memory/hdl/xpm_memory.sv
VERILOG_SOURCES += $(XILINX_VIVADO)/data/ip/xpm/xpm_fifo/hdl/xpm_fifo.sv
VERILOG_SOURCES += $(RTL_DIR)/simple_dual_port_ram.sv
VERILOG_SOURCES += $(RTL_DIR)/showahead_fifo.sv
VERILOG_SOURCES += $(RTL_DIR)/wd_pkg.sv
VERILOG_SOURCES += $(RTL_DIR)/mul_wide.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_sch.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_msgseq.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_round.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_block.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_modq.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_modq_meta.sv

include $(shell cocotb-config --makefiles)/Makefile.sim
