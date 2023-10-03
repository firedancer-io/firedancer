// Amazon FPGA Hardware Development Kit
//
// Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Amazon Software License (the "License"). You may not use
// this file except in compliance with the License. A copy of the License is
// located at
//
//    http://aws.amazon.com/asl/
//
// or in the "license" file accompanying this file. This file is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or
// implied. See the License for the specific language governing permissions and
// limitations under the License.

// DDR address space
// The addressing uses ROW/COLUMN/BANK mapping of AXI address to DRAM Row/Col/BankGroup

module cl_dram_dma #(parameter NUM_DDR=4) 

(
   `include "cl_ports.vh"

);

`include "cl_common_defines.vh"      // CL Defines for all examples
`include "cl_id_defines.vh"          // Defines for ID0 and ID1 (PCI ID's)
`include "cl_dram_dma_defines.vh"

// TIE OFF ALL UNUSED INTERFACES
// Including all the unused interface to tie off
// This list is put in the top of the fie to remind
// developers to remve the specific interfaces
// that the CL will use

`include "unused_flr_template.inc"
`include "unused_ddr_a_b_d_template.inc"
`include "unused_ddr_c_template.inc"
// `include "unused_pcim_template.inc"
// `include "unused_dma_pcis_template.inc"
`include "unused_cl_sda_template.inc"
`include "unused_sh_bar1_template.inc"
`include "unused_apppf_irq_template.inc"

// Define the addition pipeline stag
// needed to close timing for the various
// place where ATG (Automatic Test Generator)
// is defined
   
   localparam NUM_CFG_STGS_CL_DDR_ATG = 8;
   localparam NUM_CFG_STGS_SH_DDR_ATG = 4;
   localparam NUM_CFG_STGS_PCIE_ATG = 4;

// To reduce RTL simulation time, only 8KiB of
// each external DRAM is scrubbed in simulations

`ifdef SIM
   localparam DDR_SCRB_MAX_ADDR = 64'h1FFF;
`else   
   localparam DDR_SCRB_MAX_ADDR = 64'h3FFFFFFFF; //16GB 
`endif
   localparam DDR_SCRB_BURST_LEN_MINUS1 = 15;

`ifdef NO_CL_TST_SCRUBBER
   localparam NO_SCRB_INST = 1;
`else
   localparam NO_SCRB_INST = 0;
`endif   

logic clk;
(* dont_touch = "true" *) logic pipe_rst_n;
logic pre_sync_rst_n;
(* dont_touch = "true" *) logic sync_rst_n;
logic sh_cl_flr_assert_q;

logic [3:0] all_ddr_scrb_done;
logic [3:0] all_ddr_is_ready;
logic [2:0] lcl_sh_cl_ddr_is_ready;

logic dbg_scrb_en;
logic [2:0] dbg_scrb_mem_sel;

//---------------------------- 
// End Internal signals
//----------------------------

assign cl_sh_status0 = 32'h0;
assign cl_sh_status1 = 32'h0;

assign cl_sh_id0[31:0] = `CL_SH_ID0;
assign cl_sh_id1[31:0] = `CL_SH_ID1;

// Unused 'full' signals
assign cl_sh_dma_rd_full  = 1'b0;
assign cl_sh_dma_wr_full  = 1'b0;

assign clk = clk_main_a0;

//reset synchronizer
lib_pipe #(.WIDTH(1), .STAGES(4)) PIPE_RST_N (.clk(clk), .rst_n(1'b1), .in_bus(rst_main_n), .out_bus(pipe_rst_n));
   
always_ff @(negedge pipe_rst_n or posedge clk)
   if (!pipe_rst_n)
   begin
      pre_sync_rst_n <= 0;
      sync_rst_n <= 0;
   end
   else
   begin
      pre_sync_rst_n <= 1;
      sync_rst_n <= pre_sync_rst_n;
   end








logic [1-1:0] rst;

always_ff@(posedge clk_main_a0)
    rst <= ~sync_rst_n;

logic [1-1:0] clk_f;
logic [1-1:0] rst_f;

assign clk_f = clk_extra_c1;

areset_sync rst_f_areset_sync_inst (
    .areset                                                         (rst),
    .dclk                                                           (clk_f),
    .dreset                                                         (rst_f)
);










//                AAA               VVVVVVVV           VVVVVVVVMMMMMMMM               MMMMMMMMMMMMMMMM               MMMMMMMM
//               A:::A              V::::::V           V::::::VM:::::::M             M:::::::MM:::::::M             M:::::::M
//              A:::::A             V::::::V           V::::::VM::::::::M           M::::::::MM::::::::M           M::::::::M
//             A:::::::A            V::::::V           V::::::VM:::::::::M         M:::::::::MM:::::::::M         M:::::::::M
//            A:::::::::A            V:::::V           V:::::V M::::::::::M       M::::::::::MM::::::::::M       M::::::::::M
//           A:::::A:::::A            V:::::V         V:::::V  M:::::::::::M     M:::::::::::MM:::::::::::M     M:::::::::::M
//          A:::::A A:::::A            V:::::V       V:::::V   M:::::::M::::M   M::::M:::::::MM:::::::M::::M   M::::M:::::::M
//         A:::::A   A:::::A            V:::::V     V:::::V    M::::::M M::::M M::::M M::::::MM::::::M M::::M M::::M M::::::M
//        A:::::A     A:::::A            V:::::V   V:::::V     M::::::M  M::::M::::M  M::::::MM::::::M  M::::M::::M  M::::::M
//       A:::::AAAAAAAAA:::::A            V:::::V V:::::V      M::::::M   M:::::::M   M::::::MM::::::M   M:::::::M   M::::::M
//      A:::::::::::::::::::::A            V:::::V:::::V       M::::::M    M:::::M    M::::::MM::::::M    M:::::M    M::::::M
//     A:::::AAAAAAAAAAAAA:::::A            V:::::::::V        M::::::M     MMMMM     M::::::MM::::::M     MMMMM     M::::::M
//    A:::::A             A:::::A            V:::::::V         M::::::M               M::::::MM::::::M               M::::::M
//   A:::::A               A:::::A            V:::::V          M::::::M               M::::::MM::::::M               M::::::M
//  A:::::A                 A:::::A            V:::V           M::::::M               M::::::MM::::::M               M::::::M
// AAAAAAA                   AAAAAAA            VVV            MMMMMMMM               MMMMMMMMMMMMMMMM               MMMMMMMM

localparam DMA_N                        = 1;
localparam NO_AVMM_MASTERS              = 1;
localparam NO_BASE_ENGINES              = 1;
localparam NO_DBG_TAPS                  = 1;
localparam DBG_WIDTH                    = 1024*2;
localparam DDR_SIM                      = 0;

logic [NO_DBG_TAPS-1:0][DBG_WIDTH-1:0]  dbg_wires;

logic [NO_AVMM_MASTERS-1:0][1-1:0]      avmm_fh_read = 0;
logic [NO_AVMM_MASTERS-1:0][1-1:0]      avmm_fh_write = 0;
logic [NO_AVMM_MASTERS-1:0][32-1:0]     avmm_fh_address;
logic [NO_AVMM_MASTERS-1:0][32-1:0]     avmm_fh_writedata;
logic [NO_AVMM_MASTERS-1:0][32-1:0]     avmm_fh_readdata;
logic [NO_AVMM_MASTERS-1:0][1-1:0]      avmm_fh_readdatavalid;
logic [NO_AVMM_MASTERS-1:0][1-1:0]      avmm_fh_waitrequest;

logic [3-1:0] st_ocl;
logic [32-1:0] ocl_addr;
logic [3-1:0] ocl_mi;

assign ocl_sh_arready = (st_ocl == 0);
assign ocl_sh_awready = (st_ocl == 0) & ~sh_ocl_arvalid;
assign ocl_sh_wready = (st_ocl == 3);
assign ocl_sh_rresp = '0;
assign ocl_sh_bresp = '0;

always_ff@(posedge clk_main_a0) begin
    integer i;

    case (st_ocl)
        0: begin
            if (sh_ocl_arvalid) begin
                ocl_mi                                                          <= sh_ocl_araddr[10+:3];
                for (i = 0; i < NO_AVMM_MASTERS; i ++) begin
                    avmm_fh_address         [i]                                 <= sh_ocl_araddr[0+:10];
                    if (sh_ocl_araddr[10+:3] == i) begin
                        avmm_fh_read        [i]                                 <= sh_ocl_arvalid;
                    end
                end
                st_ocl                                                          <= 1;
            end else
            if (sh_ocl_awvalid) begin
                ocl_mi                                                          <= sh_ocl_awaddr[10+:3];
                for (i = 0; i < NO_AVMM_MASTERS; i ++) begin
                    avmm_fh_address         [i]                                 <= sh_ocl_awaddr[0+:10];
                end
                st_ocl                                                          <= 3;
            end
        end
        1: begin
            if (~avmm_fh_waitrequest[ocl_mi])
                avmm_fh_read        [ocl_mi]                                    <= 0;

            if (avmm_fh_readdatavalid[ocl_mi]) begin
                ocl_sh_rvalid                                                   <= 1;
                ocl_sh_rdata                                                    <= avmm_fh_readdata[ocl_mi];

                st_ocl                                                          <= 2;
            end
        end
        2: begin
            if (sh_ocl_rready) begin
                ocl_sh_rvalid                                                   <= 0;
                st_ocl                                                          <= 0;
            end
        end

        3: begin
            avmm_fh_write           [ocl_mi]                                    <= sh_ocl_wvalid;
            avmm_fh_writedata       [ocl_mi]                                    <= sh_ocl_wdata;

            if (sh_ocl_wvalid) begin
                st_ocl                                                          <= 4;
            end
        end

        4: begin
            if (~avmm_fh_waitrequest[ocl_mi]) begin
                avmm_fh_write       [ocl_mi]                                    <= 0;
                ocl_sh_bvalid                                                   <= 1;
                st_ocl                                                          <= 5;
            end
        end

        5: begin
            if (sh_ocl_bready) begin
                ocl_sh_bvalid                                                   <= 0;

                st_ocl                                                          <= 0;
            end
        end

    endcase

    if (rst) begin
        st_ocl                                  <= 0;
        ocl_sh_rvalid                           <= '0;
        ocl_sh_bvalid                           <= '0;
        avmm_fh_read                            <= '0;
        avmm_fh_write                           <= '0;
    end
end

logic [4-1:0]                                   vdip_func;
logic [4-1:0]                                   vdip_sel;
logic [8-1:0]                                   vdip_byte;
logic [16-1:0][8-1:0]                           vdip_bytes;

assign {vdip_byte, vdip_sel, vdip_func}         = sh_cl_status_vdip;

always_ff@(posedge clk_main_a0) begin
    cl_sh_status_vled                                                           <= {vdip_bytes[vdip_sel], vdip_sel, vdip_func};
    if (vdip_func == 4'hf) begin
        vdip_bytes[vdip_sel]                                                    <= vdip_byte;
    end
end


// DDDDDDDDDDDDD        DDDDDDDDDDDDD        RRRRRRRRRRRRRRRRR   
// D::::::::::::DDD     D::::::::::::DDD     R::::::::::::::::R  
// D:::::::::::::::DD   D:::::::::::::::DD   R::::::RRRRRR:::::R 
// DDD:::::DDDDD:::::D  DDD:::::DDDDD:::::D  RR:::::R     R:::::R
//   D:::::D    D:::::D   D:::::D    D:::::D   R::::R     R:::::R
//   D:::::D     D:::::D  D:::::D     D:::::D  R::::R     R:::::R
//   D:::::D     D:::::D  D:::::D     D:::::D  R::::RRRRRR:::::R 
//   D:::::D     D:::::D  D:::::D     D:::::D  R:::::::::::::RR  
//   D:::::D     D:::::D  D:::::D     D:::::D  R::::RRRRRR:::::R 
//   D:::::D     D:::::D  D:::::D     D:::::D  R::::R     R:::::R
//   D:::::D     D:::::D  D:::::D     D:::::D  R::::R     R:::::R
//   D:::::D    D:::::D   D:::::D    D:::::D   R::::R     R:::::R
// DDD:::::DDDDD:::::D  DDD:::::DDDDD:::::D  RR:::::R     R:::::R
// D:::::::::::::::DD   D:::::::::::::::DD   R::::::R     R:::::R
// D::::::::::::DDD     D::::::::::::DDD     R::::::R     R:::::R
// DDDDDDDDDDDDD        DDDDDDDDDDDDD        RRRRRRRR     RRRRRRR









// PPPPPPPPPPPPPPPPP           CCCCCCCCCCCCCIIIIIIIIIIEEEEEEEEEEEEEEEEEEEEEE
// P::::::::::::::::P       CCC::::::::::::CI::::::::IE::::::::::::::::::::E
// P::::::PPPPPP:::::P    CC:::::::::::::::CI::::::::IE::::::::::::::::::::E
// PP:::::P     P:::::P  C:::::CCCCCCCC::::CII::::::IIEE::::::EEEEEEEEE::::E
//   P::::P     P:::::P C:::::C       CCCCCC  I::::I    E:::::E       EEEEEE
//   P::::P     P:::::PC:::::C                I::::I    E:::::E             
//   P::::PPPPPP:::::P C:::::C                I::::I    E::::::EEEEEEEEEE   
//   P:::::::::::::PP  C:::::C                I::::I    E:::::::::::::::E   
//   P::::PPPPPPPPP    C:::::C                I::::I    E:::::::::::::::E   
//   P::::P            C:::::C                I::::I    E::::::EEEEEEEEEE   
//   P::::P            C:::::C                I::::I    E:::::E             
//   P::::P             C:::::C       CCCCCC  I::::I    E:::::E       EEEEEE
// PP::::::PP            C:::::CCCCCCCC::::CII::::::IIEE::::::EEEEEEEE:::::E
// P::::::::P             CC:::::::::::::::CI::::::::IE::::::::::::::::::::E
// P::::::::P               CCC::::::::::::CI::::::::IE::::::::::::::::::::E
// PPPPPPPPPP                  CCCCCCCCCCCCCIIIIIIIIIIEEEEEEEEEEEEEEEEEEEEEE

logic [1-1:0] st_addr_v;
logic [3-1:0] st_data_v;
logic [2-1:0] st_v;
logic [1-1:0] st_p;
logic [64-1:0] st_addr;
logic [2-1:0][256-1:0] st_data;

assign cl_sh_dma_pcis_awready                   = 1'b1;
assign cl_sh_dma_pcis_wready                    = 1'b1;
assign cl_sh_dma_pcis_bresp                     = '0;

always_ff@(posedge clk) cl_sh_dma_pcis_bvalid   <= sh_cl_dma_pcis_wvalid & sh_cl_dma_pcis_wlast;
always_ff@(posedge clk) cl_sh_dma_pcis_bid      <= sh_cl_dma_pcis_awid;

showahead_fifo #(
    .WIDTH                              ($bits(sh_cl_dma_pcis_awaddr)),
    .DEPTH                              (32)
) st_in_addr_fifo_inst (
    .aclr                               (rst),

    .wr_clk                             (clk),
    .wr_req                             (sh_cl_dma_pcis_awvalid & cl_sh_dma_pcis_awready),
    .wr_full                            (),
    .wr_data                            ({sh_cl_dma_pcis_awaddr[64-1:6], 6'h0}),

    .rd_clk                             (clk),
    .rd_req                             (st_p),
    .rd_empty                           (),
    .rd_not_empty                       (st_addr_v),
    .rd_count                           (),
    .rd_data                            ({st_addr})
);

showahead_fifo #(
    .WIDTH                              ($bits({sh_cl_dma_pcis_wdata, sh_cl_dma_pcis_wstrb[32], sh_cl_dma_pcis_wstrb[0]})),
    .DEPTH                              (32)
) st_in_data_fifo_inst (
    .aclr                               (rst),

    .wr_clk                             (clk),
    .wr_req                             (sh_cl_dma_pcis_wvalid & cl_sh_dma_pcis_wready),
    .wr_full                            (),
    .wr_data                            ({sh_cl_dma_pcis_wdata, sh_cl_dma_pcis_wstrb[32], sh_cl_dma_pcis_wstrb[0]}),

    .rd_clk                             (clk),
    .rd_req                             (st_p),
    .rd_empty                           (),
    .rd_not_empty                       (st_data_v[2]),
    .rd_count                           (),
    .rd_data                            ({st_data, st_data_v[0+:2]})
);

assign st_p                             = st_addr_v & st_data_v[2];
assign st_v[0]                          = st_addr_v & st_data_v[2] & st_data_v[0];
assign st_v[1]                          = st_addr_v & st_data_v[2] & st_data_v[1];






// DDDDDDDDDDDDD        MMMMMMMM               MMMMMMMM               AAA               
// D::::::::::::DDD     M:::::::M             M:::::::M              A:::A              
// D:::::::::::::::DD   M::::::::M           M::::::::M             A:::::A             
// DDD:::::DDDDD:::::D  M:::::::::M         M:::::::::M            A:::::::A            
//   D:::::D    D:::::D M::::::::::M       M::::::::::M           A:::::::::A           
//   D:::::D     D:::::DM:::::::::::M     M:::::::::::M          A:::::A:::::A          
//   D:::::D     D:::::DM:::::::M::::M   M::::M:::::::M         A:::::A A:::::A         
//   D:::::D     D:::::DM::::::M M::::M M::::M M::::::M        A:::::A   A:::::A        
//   D:::::D     D:::::DM::::::M  M::::M::::M  M::::::M       A:::::A     A:::::A       
//   D:::::D     D:::::DM::::::M   M:::::::M   M::::::M      A:::::AAAAAAAAA:::::A      
//   D:::::D     D:::::DM::::::M    M:::::M    M::::::M     A:::::::::::::::::::::A     
//   D:::::D    D:::::D M::::::M     MMMMM     M::::::M    A:::::AAAAAAAAAAAAA:::::A    
// DDD:::::DDDDD:::::D  M::::::M               M::::::M   A:::::A             A:::::A   
// D:::::::::::::::DD   M::::::M               M::::::M  A:::::A               A:::::A  
// D::::::::::::DDD     M::::::M               M::::::M A:::::A                 A:::::A 
// DDDDDDDDDDDDD        MMMMMMMM               MMMMMMMMAAAAAAA                   AAAAAAA

logic [1-1:0]                           dma_r;
logic [1-1:0]                           dma_push;
logic [64-1:0]                          dma_push_a;
logic [64-1:0]                          dma_push_b;
logic [1-1:0]                           dma_full_a;
logic [1-1:0]                           dma_full_d;
logic [256-1:0]                         dma_push_d;

logic [256-1:0]                         cl_sh_pcim_wdata_h;

assign dma_r                            = (~dma_full_a) & (~dma_full_d);

assign cl_sh_pcim_awid                  = '0;
assign cl_sh_pcim_awlen                 = '0;
assign cl_sh_pcim_awsize                = 'b110;
assign cl_sh_pcim_wlast                 = '1;
assign cl_sh_pcim_wdata                 = {2{cl_sh_pcim_wdata_h}};
assign cl_sh_pcim_bready                = '1;

showahead_fifo #(
    .WIDTH                              ($bits({dma_push_a})),
    .FULL_THRESH                        (512-64),
    .DEPTH                              (512)
) dma_addr_fifo_inst (
    .aclr                               (rst),

    .wr_clk                             (clk),
    .wr_req                             (dma_push & dma_r),
    .wr_full                            (dma_full_a),
    .wr_data                            ({dma_push_a}),

    .rd_clk                             (clk),
    .rd_req                             (cl_sh_pcim_awvalid & sh_cl_pcim_awready),
    .rd_empty                           (),
    .rd_not_empty                       (cl_sh_pcim_awvalid),
    .rd_count                           (),
    .rd_data                            ({cl_sh_pcim_awaddr})
);

showahead_fifo #(
    .WIDTH                              ($bits({dma_push_b, dma_push_d})),
    .FULL_THRESH                        (512-64),
    .DEPTH                              (512)
) dma_data_fifo_inst (
    .aclr                               (rst),

    .wr_clk                             (clk),
    .wr_req                             (dma_push & dma_r),
    .wr_full                            (dma_full_d),
    .wr_data                            ({dma_push_b, dma_push_d}),

    .rd_clk                             (clk),
    .rd_req                             (cl_sh_pcim_wvalid & sh_cl_pcim_wready),
    .rd_empty                           (),
    .rd_not_empty                       (cl_sh_pcim_wvalid),
    .rd_count                           (),
    .rd_data                            ({cl_sh_pcim_wstrb, cl_sh_pcim_wdata_h})
);
















//                AAA               PPPPPPPPPPPPPPPPP   PPPPPPPPPPPPPPPPP   
//               A:::A              P::::::::::::::::P  P::::::::::::::::P  
//              A:::::A             P::::::PPPPPP:::::P P::::::PPPPPP:::::P 
//             A:::::::A            PP:::::P     P:::::PPP:::::P     P:::::P
//            A:::::::::A             P::::P     P:::::P  P::::P     P:::::P
//           A:::::A:::::A            P::::P     P:::::P  P::::P     P:::::P
//          A:::::A A:::::A           P::::PPPPPP:::::P   P::::PPPPPP:::::P 
//         A:::::A   A:::::A          P:::::::::::::PP    P:::::::::::::PP  
//        A:::::A     A:::::A         P::::PPPPPPPPP      P::::PPPPPPPPP    
//       A:::::AAAAAAAAA:::::A        P::::P              P::::P            
//      A:::::::::::::::::::::A       P::::P              P::::P            
//     A:::::AAAAAAAAAAAAA:::::A      P::::P              P::::P            
//    A:::::A             A:::::A   PP::::::PP          PP::::::PP          
//   A:::::A               A:::::A  P::::::::P          P::::::::P          
//  A:::::A                 A:::::A P::::::::P          P::::::::P          
// AAAAAAA                   AAAAAAAPPPPPPPPPP          PPPPPPPPPP          

`ifndef TOP_NAME
`define TOP_NAME top_f1
`endif

`TOP_NAME #(
    .DBG_WIDTH(DBG_WIDTH),
    .DMA_N                                              (DMA_N)
) top_inst (

    .avmm_read                                          (avmm_fh_read[0]),
    .avmm_write                                         (avmm_fh_write[0]),
    .avmm_address                                       (avmm_fh_address[0]),
    .avmm_writedata                                     (avmm_fh_writedata[0]),
    .avmm_readdata                                      (avmm_fh_readdata[0]),
    .avmm_readdatavalid                                 (avmm_fh_readdatavalid[0]),
    .avmm_waitrequest                                   (avmm_fh_waitrequest[0]),

    .priv_bytes                                         (vdip_bytes),

    .pcie_v                                             (st_v),
    .pcie_a                                             (st_addr),
    .pcie_d                                             (st_data),

    .dma_r                                              (dma_r),
    .dma_v                                              (dma_push),
    .dma_a                                              (dma_push_a),
    .dma_b                                              (dma_push_b),
    .dma_f                                              (dma_full_a | dma_full_d),
    .dma_d                                              (dma_push_d),

    // .ddr_rd_en                                          (ddr_rd_en),
    // .ddr_rd_pop                                         (ddr_rd_pop),
    // .ddr_rd_addr                                        (ddr_rd_addr),
    // .ddr_rd_sz                                          (ddr_rd_sz),
    // .ddr_rd_v                                           (ddr_rd_v),
    // .ddr_rd_data                                        (ddr_rd_data),

    // .ddr_wr_en                                          (ddr_wr_en),
    // .ddr_wr_pop                                         (ddr_wr_pop),
    // .ddr_wr_res                                         (ddr_wr_res),
    // .ddr_wr_addr                                        (ddr_wr_addr),
    // .ddr_wr_data                                        (ddr_wr_data),

    .dbg_wire                                           (dbg_wires[0]),

    .clk_f(clk_f),
    .rst_f(rst_f),

    .clk(clk),
    .rst(rst)
);

endmodule   
