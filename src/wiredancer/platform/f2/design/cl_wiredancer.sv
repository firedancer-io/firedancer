// ============================================================================
// Amazon FPGA Hardware Development Kit
//
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
// ============================================================================


//=============================================================================
// Top level module file for CL_WIREDANCER
//=============================================================================

module cl_wiredancer
(
    `include "cl_ports.vh"
);

`include "cl_id_defines.vh"       // Defines for ID0 and ID1 (PCI ID's)
`include "unused_ddr_template.inc"
`include "unused_cl_sda_template.inc"
`include "unused_apppf_irq_template.inc"

///////////////////////////////////////////////////////////////////////
// Unused signals
///////////////////////////////////////////////////////////////////////

  // Tie off unused signals:
  assign cl_sh_dma_rd_full  = 'b0;
  assign cl_sh_dma_wr_full  = 'b0;

  assign cl_sh_status0      = 'b0;
  assign cl_sh_status1      = 'b0;
  assign cl_sh_status2      = 'b0;

  assign cl_sh_id0[31:0] = `CL_SH_ID0;
  assign cl_sh_id1[31:0] = `CL_SH_ID1;



///////////////////////////////////////////////////////////////////////
// Clock and Reset synchronizers
///////////////////////////////////////////////////////////////////////

logic clk;
(* dont_touch = "true" *) logic pipe_rst_n;
logic pre_sync_rst_n;
(* dont_touch = "true" *) logic sync_rst_n;

assign clk = clk_main_a0;

// Reset synchronizer
lib_pipe #(.WIDTH(1), .STAGES(4)) PIPE_RST_N (
    .clk    (clk),
    .rst_n  (1'b1),
    .in_bus (rst_main_n),
    .out_bus(pipe_rst_n)
);

always_ff @(negedge pipe_rst_n or posedge clk) begin
   if (!pipe_rst_n) begin
      pre_sync_rst_n <= 0;
      sync_rst_n     <= 0;
   end
   else begin
      pre_sync_rst_n <= 1;
      sync_rst_n     <= pre_sync_rst_n;
   end
end

///////////////////////////////////////////////////////////////////////
// Local reset for code
///////////////////////////////////////////////////////////////////////

logic rst;
always_ff @(posedge clk_main_a0) begin
    rst <= ~sync_rst_n;
end

///////////////////////////////////////////////////////////////////////
///////////////// FLR resposne ////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

  logic sh_cl_flr_assert_q = 'b0;

  // Auto FLR response
  always_ff @(posedge clk)
    if (!rst) begin
      sh_cl_flr_assert_q <= 0;
      cl_sh_flr_done     <= 0;
    end else begin
      sh_cl_flr_assert_q <= sh_cl_flr_assert;
      cl_sh_flr_done     <= sh_cl_flr_assert_q && !cl_sh_flr_done;
    end


///////////////////////////////////////////////////////////////////////
// WIREDANCER main logic
///////////////////////////////////////////////////////////////////////

// The top-level includes are parameterizable.  For brevity, we keep the code:
localparam DMA_N         = 1;
localparam PCIE_N        = 1;
localparam NO_AVMM_MASTERS = 1;
localparam NO_BASE_ENGINES = 1;
localparam NO_DBG_TAPS     = 1;
localparam DBG_WIDTH       = 1024*2;

// Debug wires for demonstration
logic [NO_DBG_TAPS-1:0][DBG_WIDTH-1:0]  dbg_wires;

// Simple AVMM stubs
logic [NO_AVMM_MASTERS-1:0] avmm_fh_read;
logic [NO_AVMM_MASTERS-1:0] avmm_fh_write;
logic [NO_AVMM_MASTERS-1:0][32-1:0] avmm_fh_address;
logic [NO_AVMM_MASTERS-1:0][32-1:0] avmm_fh_writedata;
logic [NO_AVMM_MASTERS-1:0][32-1:0] avmm_fh_readdata;
logic [NO_AVMM_MASTERS-1:0]         avmm_fh_readdatavalid;
logic [NO_AVMM_MASTERS-1:0]         avmm_fh_waitrequest;

// Drive them to 0 by default
initial begin
  avmm_fh_read         = '0;
  avmm_fh_write        = '0;
  avmm_fh_address      = '0;
  avmm_fh_writedata    = '0;
end

////////////////////////////////////////////////////////////////////////
// AXI‐Lite (sh_ocl*) minimal state machine
////////////////////////////////////////////////////////////////////////

logic [2:0] st_ocl;
logic [2:0] ocl_mi;

always_comb begin
    // Default
    cl_ocl_arready = (st_ocl == 3'b000);
    cl_ocl_awready = (st_ocl == 3'b000) & ~ocl_cl_arvalid;
    cl_ocl_wready  = (st_ocl == 3'b011);
    cl_ocl_rresp   = 2'b00;
    cl_ocl_bresp   = 2'b00;
end

always_ff @(posedge clk) begin
    integer i;

    case (st_ocl)
        0: begin
            if (ocl_cl_arvalid) begin
                ocl_mi <= ocl_cl_araddr[10+:3];
                for (i = 0; i < NO_AVMM_MASTERS; i ++) begin
                    avmm_fh_address[i] <= ocl_cl_araddr[0+:10];
                    if (ocl_cl_araddr[10+:3] == i)
                        avmm_fh_read[i] <= ocl_cl_arvalid;
                end
                st_ocl <= 1;
            end
            else if (ocl_cl_awvalid) begin
                ocl_mi <= ocl_cl_awaddr[10+:3];
                for (i = 0; i < NO_AVMM_MASTERS; i ++) begin
                    avmm_fh_address[i] <= ocl_cl_awaddr[0+:10];
                end
                st_ocl <= 3;
            end
        end

        1: begin
            // Wait for read data
            if (~avmm_fh_waitrequest[ocl_mi])
                avmm_fh_read[ocl_mi] <= 1'b0;

            if (avmm_fh_readdatavalid[ocl_mi]) begin
                cl_ocl_rvalid <= 1'b1;
                cl_ocl_rdata  <= avmm_fh_readdata[ocl_mi];
                st_ocl        <= 2;
            end
        end

        2: begin
            if (ocl_cl_rready) begin
                cl_ocl_rvalid <= 1'b0;
                st_ocl        <= 0;
            end
        end

        3: begin
            // Prepare for write
            avmm_fh_write    [ocl_mi] <= ocl_cl_wvalid;
            avmm_fh_writedata[ocl_mi] <= ocl_cl_wdata;

            if (ocl_cl_wvalid) begin
                st_ocl <= 4;
            end
        end

        4: begin
            if (~avmm_fh_waitrequest[ocl_mi]) begin
                avmm_fh_write[ocl_mi] <= 1'b0;
                cl_ocl_bvalid         <= 1'b1;
                st_ocl                <= 5;
            end
        end

        5: begin
            if (ocl_cl_bready) begin
                cl_ocl_bvalid <= 1'b0;
                st_ocl        <= 0;
            end
        end

        default: st_ocl <= 0;
    endcase

    if (rst) begin
        st_ocl        <= 0;
        cl_ocl_rvalid <= 1'b0;
        cl_ocl_bvalid <= 1'b0;
        avmm_fh_read  <= '0;
        avmm_fh_write <= '0;
    end
end

//------------------------------------------------------------------------------
// vDIP / vLED multiplexer with edge-count and handshake counters
//   func = 0xF : write user-byte page
//   func = 0x0 : read  user-byte page
//   func = 0xE : read  captured AW address (8 B)
//   func = 0xD : read  protocol / BRESP info
//   func = 0xC : read  an edge counter
//       sel_idx[3:2] 00 awvalid  01 awready  10 wvalid  11 wready
//       sel_idx[1:0] byte lane 0-3
//   func = 0xB : read  a handshake counter
//       sel_idx[3:2] 00 aw_hs   01 w_hs   10/11 reserved (returns 0)
//       sel_idx[1:0] byte lane 0-3
//   func = 0xA : read  captured WSTRB mask (8 B)
//       sel_idx       byte lane 0-7
//------------------------------------------------------------------------------

logic [15:0][7:0] vdip_mem;
logic [63:0]      awaddr_lat;
logic [63:0]      wstrb_lat;
logic [7:0]       bresp_lat;
logic [7:0]       led_byte;

// edge counters
logic [31:0] pcim_cnt_awvalid, pcim_cnt_awready;
logic [31:0] pcim_cnt_wvalid , pcim_cnt_wready;

// handshake counters
logic [31:0] pcim_cnt_aw_hs , pcim_cnt_w_hs;

// edge detectors
logic prev_awvalid, prev_awready, prev_wvalid, prev_wready;

wire [3:0] func    = sh_cl_status_vdip[3:0];
wire [3:0] sel_idx = sh_cl_status_vdip[7:4];
wire [7:0] data    = sh_cl_status_vdip[15:8];

always_ff @(posedge clk_main_a0) begin
    if (rst) begin
        awaddr_lat        <= 64'h0;
        wstrb_lat         <= 64'h0;
        bresp_lat         <= 8'h00;
        led_byte          <= 8'h00;
        vdip_mem          <= '{default:8'h00};
        cl_sh_status_vled <= 16'h0000;
        pcim_cnt_awvalid  <= 32'd0;
        pcim_cnt_awready  <= 32'd0;
        pcim_cnt_wvalid   <= 32'd0;
        pcim_cnt_wready   <= 32'd0;
        pcim_cnt_aw_hs    <= 32'd0;
        pcim_cnt_w_hs     <= 32'd0;
        prev_awvalid      <= 1'b0;
        prev_awready      <= 1'b0;
        prev_wvalid       <= 1'b0;
        prev_wready       <= 1'b0;
    end else begin
        // rising-edge counters
        if (~prev_awvalid & cl_sh_pcim_awvalid) pcim_cnt_awvalid <= pcim_cnt_awvalid + 1;
        if (~prev_awready & sh_cl_pcim_awready) pcim_cnt_awready <= pcim_cnt_awready + 1;
        if (~prev_wvalid  & cl_sh_pcim_wvalid ) pcim_cnt_wvalid  <= pcim_cnt_wvalid  + 1;
        if (~prev_wready  & sh_cl_pcim_wready ) pcim_cnt_wready  <= pcim_cnt_wready  + 1;

        // handshake counters (valid & ready high)
        if (cl_sh_pcim_awvalid && sh_cl_pcim_awready) pcim_cnt_aw_hs <= pcim_cnt_aw_hs + 1;
        if (cl_sh_pcim_wvalid  && sh_cl_pcim_wready ) pcim_cnt_w_hs  <= pcim_cnt_w_hs  + 1;

        // update previous levels
        prev_awvalid <= cl_sh_pcim_awvalid;
        prev_awready <= sh_cl_pcim_awready;
        prev_wvalid  <= cl_sh_pcim_wvalid;
        prev_wready  <= sh_cl_pcim_wready;

        // capture last AW address
        if (cl_sh_pcim_awvalid && sh_cl_pcim_awready)
            awaddr_lat <= cl_sh_pcim_awaddr;

        // capture last WSTRB mask
        if (cl_sh_pcim_wvalid && sh_cl_pcim_wready)
            wstrb_lat <= cl_sh_pcim_wstrb;

        // latch non-OK BRESP codes
        if (sh_cl_pcim_bvalid && sh_cl_pcim_bresp != 2'b00)
            bresp_lat <= {6'b0, sh_cl_pcim_bresp};

        // user writes
        if (func == 4'hF)
            vdip_mem[sel_idx] <= data;

        // LED selector
        unique case (func)
            4'h0: led_byte <= vdip_mem[sel_idx];
            4'hE: led_byte <= awaddr_lat >> (sel_idx * 8);
            4'hD: led_byte <= (sel_idx == 0) ? bresp_lat
                           : (sel_idx == 1) ? {
                                 cl_sh_pcim_arvalid, sh_cl_pcim_arready,
                                 sh_cl_pcim_rvalid , cl_sh_pcim_rready ,
                                 cl_sh_pcim_awvalid, sh_cl_pcim_awready,
                                 cl_sh_pcim_wvalid , sh_cl_pcim_wready
                             } : 8'h00;
            // edge counters
            4'hC: begin
                logic [31:0] sel_cnt;
                unique case (sel_idx[3:2])
                    2'b00: sel_cnt = pcim_cnt_awvalid;
                    2'b01: sel_cnt = pcim_cnt_awready;
                    2'b10: sel_cnt = pcim_cnt_wvalid;
                    2'b11: sel_cnt = pcim_cnt_wready;
                endcase
                led_byte <= sel_cnt >> (sel_idx[1:0] * 8);
            end
            // handshake counters
            4'hB: begin
                logic [31:0] sel_cnt;
                unique case (sel_idx[3:2])
                    2'b00: sel_cnt = pcim_cnt_aw_hs;
                    2'b01: sel_cnt = pcim_cnt_w_hs;
                    2'b10: sel_cnt = 32'h0;
                    2'b11: sel_cnt = 32'h0;
                endcase
                led_byte <= sel_cnt >> (sel_idx[1:0] * 8);
            end
            4'hA: led_byte <= wstrb_lat >> (sel_idx * 8);
            default: led_byte <= 8'h00;
        endcase

        cl_sh_status_vled <= {led_byte, sel_idx, func};
    end
end

////////////////////////////////////////////////////////////////////////
// AXI handling for DMA PCIS writes
////////////////////////////////////////////////////////////////////////

logic [1-1:0]                                st_addr_v;
logic [3-1:0]                                st_data_v;
logic [2-1:0]                                st_v;
logic [1-1:0]                                st_p;
logic [64-1:0]                               st_addr;
logic [2-1:0][256-1:0]                        st_data;

assign cl_sh_dma_pcis_awready                   = 1'b1;
assign cl_sh_dma_pcis_wready                    = 1'b1;
assign cl_sh_dma_pcis_bresp                     = '0;

always_ff @(posedge clk) cl_sh_dma_pcis_bvalid   <= sh_cl_dma_pcis_wvalid & sh_cl_dma_pcis_wlast;
always_ff @(posedge clk) cl_sh_dma_pcis_bid      <= sh_cl_dma_pcis_awid;

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

////////////////////////////////////////////////////////////////////////
// PCIM master interface
////////////////////////////////////////////////////////////////////////

logic        dma_r;
logic        dma_push;
logic        dma_full_a;
logic        dma_full_d;
logic [63:0] dma_push_b;   // unused (WSTRB not needed now)
logic [63:0] dma_push_a;   // addresses
logic [255:0] dma_push_d;  // 256-bit data chunk
logic [255:0] cl_sh_pcim_wdata_half;

assign cl_sh_pcim_awuser  = 'b0;
assign cl_sh_pcim_aruser  = 'b0;
assign cl_sh_pcim_arid    = 16'b0;
assign cl_sh_pcim_araddr  = 64'b0;
assign cl_sh_pcim_arlen   = 8'b0;
assign cl_sh_pcim_arsize  = 3'b0;
assign cl_sh_pcim_arburst = 2'b0;
assign cl_sh_pcim_arcache = 4'b0;
assign cl_sh_pcim_arlock  = 1'b0;
assign cl_sh_pcim_arprot  = 3'b0;
assign cl_sh_pcim_arqos   = 4'b0;
assign cl_sh_pcim_arvalid = 1'b0;
assign cl_sh_pcim_rready  = 1'b0;

assign cl_sh_pcim_awid    = 4'b0000;
assign cl_sh_pcim_awlen   = 8'b0;
assign cl_sh_pcim_awsize  = 3'b110;
assign cl_sh_pcim_awburst = 2'b01;   // Incrementing burst
assign cl_sh_pcim_awcache = 4'b0;
assign cl_sh_pcim_awlock  = 1'b0;
assign cl_sh_pcim_awprot  = 3'b0;
assign cl_sh_pcim_awqos   = 4'b0;
assign cl_sh_pcim_wid     = 16'b0;
assign cl_sh_pcim_wlast   = 1'b1;
assign cl_sh_pcim_bready  = 1'b1;  // Always ready to accept BRESP

assign dma_r     = ~dma_full_a & ~dma_full_d;

assign cl_sh_pcim_wdata   = {2{cl_sh_pcim_wdata_half}};  // Duplicate 256b to 512b

// --------------------------------------------------------------------
// PCIM FIFO Instances
// --------------------------------------------------------------------

showahead_fifo #(
    .WIDTH(64),
    .FULL_THRESH(512-64),
    .DEPTH(512)
) dma_addr_fifo_inst (
    .aclr          (rst),

    .wr_clk        (clk),
    .wr_req        (dma_push & dma_r),
    .wr_full       (dma_full_a),
    .wr_data       (dma_push_a),

    .rd_clk        (clk),
    .rd_req        (cl_sh_pcim_awvalid & cl_sh_pcim_awready),
    .rd_empty      (),
    .rd_not_empty  (cl_sh_pcim_awvalid),
    .rd_count      (),
    .rd_data       ({cl_sh_pcim_awaddr})
);

showahead_fifo #(
    .WIDTH(256+64),
    .FULL_THRESH(512-64),
    .DEPTH(512)
) dma_data_fifo_inst (
    .aclr          (rst),

    .wr_clk        (clk),
    .wr_req        (dma_push & dma_r),
    .wr_full       (dma_full_d),
    .wr_full_b     (),
    .wr_count      (),
    .wr_data       ({dma_push_b, dma_push_d}),

    .rd_clk        (clk),
    .rd_req        (cl_sh_pcim_wvalid & cl_sh_pcim_wready),
    .rd_empty      (),
    .rd_not_empty  (cl_sh_pcim_wvalid),
    .rd_count      (),
    .rd_data       ({cl_sh_pcim_wstrb, cl_sh_pcim_wdata_half})
);

////////////////////////////////////////////////////////////////////////
// “top_f2” instance
////////////////////////////////////////////////////////////////////////

`ifndef TOP_NAME
`define TOP_NAME top_wd
`endif

`TOP_NAME #(
  .DBG_WIDTH(DBG_WIDTH),
  .DMA_N     (DMA_N),
  .PCIE_N    (PCIE_N)
) top_inst (
    .avmm_read         (avmm_fh_read [0]),
    .avmm_write        (avmm_fh_write[0]),
    .avmm_address      (avmm_fh_address[0]),
    .avmm_writedata    (avmm_fh_writedata[0]),
    .avmm_readdata     (avmm_fh_readdata[0]),
    .avmm_readdatavalid(avmm_fh_readdatavalid[0]),
    .avmm_waitrequest  (avmm_fh_waitrequest[0]),

    .priv_bytes        (vdip_mem),

    // PCIE bridging
    .pcie_v(st_v),
    .pcie_a(st_addr),
    .pcie_d(st_data),

    // DMA
    .dma_r             (dma_r),
    .dma_v             (dma_push),
    .dma_a             (dma_push_a),
    .dma_b             (dma_push_b),
    .dma_f             (dma_full_a | dma_full_d),
    .dma_d             (dma_push_d),

    .dbg_wire          (dbg_wires[0]),

    // Used to clock SV. Change to faster clock domain for
    // higher throughput. 
    .clk_f             (clk),
    .rst_f             (rst),

    .clk               (clk),
    .rst               (rst)
);

endmodule // cl_wiredancer
