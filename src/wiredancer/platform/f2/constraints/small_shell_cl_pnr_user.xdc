# =============================================================================
# Amazon FPGA Hardware Development Kit
#
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#    http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================

# Level 1 Wiredancer floorplan for Small Shell


###############################################################################
# Child Pblock in SLR2
###############################################################################
########################################
# Pblock
########################################
create_pblock pblock_CL_SLR2

# Complete CRs in SLR2
# Match the parent pblock width to avoid DRC errors
resize_pblock pblock_CL_SLR2 -add {CLOCKREGION_X0Y8:CLOCKREGION_X5Y11}

set_property parent pblock_CL [get_pblocks pblock_CL_SLR2]

###############################################################################
# Child Pblock in SLR1
###############################################################################
########################################
# Pblock
########################################
create_pblock pblock_CL_SLR1

# Complete CRs in SLR1
resize_pblock pblock_CL_SLR1 -add {CLOCKREGION_X0Y4:CLOCKREGION_X3Y7}
resize_pblock pblock_CL_SLR1 -add {CLOCKREGION_X5Y4:CLOCKREGION_X5Y7}
resize_pblock pblock_CL_SLR1 -add {CLOCKREGION_X4Y6:CLOCKREGION_X4Y7}
resize_pblock pblock_CL_SLR1 -add {CLOCKREGION_X4Y4:CLOCKREGION_X4Y4}

# Partial CRs
resize_pblock pblock_CL_SLR1 -add {SLICE_X122Y300:SLICE_X145Y359 \
                                   DSP48E2_X16Y114:DSP48E2_X19Y137 \
                                   RAMB18_X9Y120:RAMB18_X9Y143 \
                                   RAMB36_X9Y60:RAMB36_X9Y71 \
                                   URAM288_X2Y80:URAM288_X2Y95}
resize_pblock pblock_CL_SLR1 -add {RAMB18_X8Y120:RAMB18_X8Y143 \
                                   RAMB36_X8Y60:RAMB36_X8Y71}

set_property SNAPPING_MODE ON [get_pblocks pblock_CL_SLR1]

set_property parent pblock_CL [get_pblocks pblock_CL_SLR1]

###############################################################################
# Child Pblock in SLR0
###############################################################################
########################################
# Pblock
########################################
create_pblock pblock_CL_SLR0

# Complete CRs
resize_pblock pblock_CL_SLR0 -add {CLOCKREGION_X0Y0:CLOCKREGION_X3Y3}
resize_pblock pblock_CL_SLR0 -add {CLOCKREGION_X4Y0:CLOCKREGION_X7Y0}
resize_pblock pblock_CL_SLR0 -add {CLOCKREGION_X4Y3:CLOCKREGION_X4Y3}
resize_pblock pblock_CL_SLR0 -add {CLOCKREGION_X6Y1:CLOCKREGION_X6Y1}
resize_pblock pblock_CL_SLR0 -add {CLOCKREGION_X5Y1:CLOCKREGION_X5Y3}

# Partial CRs
resize_pblock pblock_CL_SLR0 -add {SLICE_X120Y120:SLICE_X145Y179 \
                                   DSP48E2_X16Y42:DSP48E2_X19Y65 \
                                   RAMB18_X8Y48:RAMB18_X9Y71 \
                                   RAMB36_X8Y24:RAMB36_X9Y35 \
                                   URAM288_X2Y32:URAM288_X2Y47}

resize_pblock pblock_CL_SLR0 -add {SLICE_X118Y60:SLICE_X145Y119 \
                                   DSP48E2_X16Y18:DSP48E2_X19Y41 \
                                   RAMB18_X8Y24:RAMB18_X9Y47 \
                                   RAMB36_X8Y12:RAMB36_X9Y23 \
                                   URAM288_X2Y16:URAM288_X2Y31}

resize_pblock pblock_CL_SLR0 -add {SLICE_X206Y60:SLICE_X219Y119 \
                                   DSP48E2_X30Y18:DSP48E2_X30Y41 \
                                   RAMB18_X12Y24:RAMB18_X12Y47 \
                                   RAMB36_X12Y12:RAMB36_X12Y23}

resize_pblock pblock_CL_SLR0 -add {SLICE_X221Y60:SLICE_X232Y119 \
                                   DSP48E2_X31Y18:DSP48E2_X31Y41 \
                                   RAMB18_X13Y24:RAMB18_X13Y47 \
                                   RAMB36_X13Y12:RAMB36_X13Y23 \
                                   BUFG_GT_X1Y24:BUFG_GT_X1Y47 \
                                   BUFG_GT_SYNC_X1Y15:BUFG_GT_SYNC_X1Y29 \
                                   GTYE4_COMMON_X1Y1:GTYE4_COMMON_X1Y1 \
                                   GTYE4_CHANNEL_X1Y4:GTYE4_CHANNEL_X1Y7}


set_property parent pblock_CL [get_pblocks pblock_CL_SLR0]


########################################
# Wiredancer
########################################

# PCIS logic: appears in DMA/PCIM bridging in cl_wiredancer
add_cells_to_pblock [get_pblocks pblock_CL_SLR2] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/st_in_*}]
add_cells_to_pblock [get_pblocks pblock_CL_SLR2] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/dma_*}]
add_cells_to_pblock [get_pblocks pblock_CL_SLR2] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/pcim_*}]

# PCIM logic: PCIM bridge master interface
add_cells_to_pblock [get_pblocks pblock_CL_SLR1] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/cl_sh_pcim*}]

# OCL AXI-lite logic: control path state machine
add_cells_to_pblock [get_pblocks pblock_CL_SLR1] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/st_ocl*}]
add_cells_to_pblock [get_pblocks pblock_CL_SLR1] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/avmm_fh_*}]


# Monitoring/status (vdip, vled, bresp_status)
add_cells_to_pblock [get_pblocks pblock_CL_SLR0] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/vdip_*}]
add_cells_to_pblock [get_pblocks pblock_CL_SLR0] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/cl_wiredancer/bresp_status}]

# Previously all `top_inst` modules were forced into SLR1. This can lead to
# placement failures due to resource pressure. Allow Vivado to distribute the
# logic across SLRs by not constraining these modules to SLR1.
#add_cells_to_pblock [get_pblocks pblock_CL_SLR1] [get_cells -hierarchical -filter {NAME =~ WRAPPER/CL/top_inst*}]
