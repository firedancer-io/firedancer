# Makefile

SIM             ?= questa
MODULE          = test
RTL_DIR         = $(shell pwd)/../../rtl
SIM_DIR 		= $(shell pwd)
TOPLEVEL        = top_f1
SIM_ARGS        += sim_build/work.glbl
TOPLEVEL_LANG   ?= verilog

VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/glbl.v
VERILOG_SOURCES += $(XILINX_VIVADO)/data/verilog/src/unisims/DSP48E2.v
VERILOG_SOURCES += $(XILINX_VIVADO)/data/ip/xpm/xpm_memory/hdl/xpm_memory.sv
VERILOG_SOURCES += $(XILINX_VIVADO)/data/ip/xpm/xpm_fifo/hdl/xpm_fifo.sv
VERILOG_SOURCES += $(XILINX_VIVADO)/data/ip/xpm/xpm_cdc/hdl/xpm_cdc.sv
VERILOG_SOURCES += $(RTL_DIR)/simple_dual_port_ram.sv
VERILOG_SOURCES += $(RTL_DIR)/showahead_fifo.sv
VERILOG_SOURCES += $(RTL_DIR)/dual_clock_showahead_fifo.sv
VERILOG_SOURCES += $(RTL_DIR)/wd_pkg.sv
VERILOG_SOURCES += $(RTL_DIR)/pcie_inorder.sv
VERILOG_SOURCES += $(RTL_DIR)/pcie_tr_ext.sv
VERILOG_SOURCES += $(RTL_DIR)/tid_inorder.sv
VERILOG_SOURCES += $(RTL_DIR)/dma_result.sv
VERILOG_SOURCES += $(RTL_DIR)/key_store.sv
VERILOG_SOURCES += $(RTL_DIR)/mul_wide.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_pre.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_sch.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_msgseq.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_round.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_block.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_modq.sv
VERILOG_SOURCES += $(RTL_DIR)/sha512_modq_meta.sv
VERILOG_SOURCES += $(RTL_DIR)/schl_cpu_instr_rom.sv
VERILOG_SOURCES += $(SIM_DIR)/schl_cpu.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_add_modp.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_sub_modp.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_mul_modp.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_point_add.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_point_dbl.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_sigverify_ecc.sv
VERILOG_SOURCES += $(SIM_DIR)/ed25519_sigverify_dsdp_mul.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_sigverify_0.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_sigverify_1.sv
VERILOG_SOURCES += $(RTL_DIR)/ed25519_sigverify_2.sv
VERILOG_SOURCES += $(RTL_DIR)/top_f1.sv

COMPILE_ARGS    += +define+PATH_TO_INSTR_ROM_MIF=\"$(RTL_DIR)/schl_cpu_instr_rom.mif\"

include $(shell cocotb-config --makefiles)/Makefile.sim
