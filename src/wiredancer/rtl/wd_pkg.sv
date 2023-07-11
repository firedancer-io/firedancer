
package wd_sigverify;

localparam logic[32-1:0] PCIE_MAGIC     = 32'hACE0_FBAC;
localparam integer N_PCIE               = 2;
localparam integer EXT_BUFFER_SZ        = 4*1024;

localparam logic [255-1:0] ED25519_P    = 255'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
localparam logic [256-1:0] ED25519_P_N  = 256'h1 + ~256'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
localparam logic [255-1:0] ED25519_D    = 255'h52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
localparam logic [255-1:0] ED25519_2D   = 255'h2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159;
localparam logic [255-1:0] ED25519_Ix   = 255'h0000000000000000000000000000000000000000000000000000000000000000;
localparam logic [255-1:0] ED25519_Iy   = 255'h0000000000000000000000000000000000000000000000000000000000000001;
localparam logic [255-1:0] ED25519_Iz   = 255'h0000000000000000000000000000000000000000000000000000000000000001;
localparam logic [255-1:0] ED25519_It   = 255'h0000000000000000000000000000000000000000000000000000000000000000;
localparam logic [255-1:0] ED25519_Gx   = 255'h216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a;
localparam logic [255-1:0] ED25519_Gy   = 255'h6666666666666666666666666666666666666666666666666666666666666658;
localparam logic [255-1:0] ED25519_Gz   = 255'h0000000000000000000000000000000000000000000000000000000000000001;
localparam logic [255-1:0] ED25519_Gt   = 255'h67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3;

localparam integer N_SCH_O              = 8;

localparam integer SCH_O_RES            = 0;
localparam integer SCH_O_AX             = 1;
localparam integer SCH_O_AT             = 2;
localparam integer SCH_O_RX             = 3;
localparam integer SCH_O_TX             = 4;
localparam integer SCH_O_TY             = 5;
localparam integer SCH_O_TZ             = 6;
localparam integer SCH_O_TT             = 7;

typedef struct packed {
    logic [256-1:0] sig_l;

    logic [32-1:0] dma_chunk;
    logic [64-1:0] dma_seq;
    logic [64-1:0] dma_addr;
    logic [16-1:0] dma_ctrl;
    logic [16-1:0] dma_size;

    logic [16-1:0] size;
    logic [16-1:0] src;
    logic [32-1:0] magic;
} pcie_meta_t;

typedef struct packed {
    logic [64-1:0] tid;
    logic [16-1:0] src;
} sv_meta0_t;

typedef struct packed {
    logic [256-1:0]             pub;
    logic [256-1:0]             sig_h;
    logic [256-1:0]             sig_l;
    sv_meta0_t m;
} sv_meta1_t;

typedef struct packed {
    logic [512-1:0]             data;
    logic [1-1:0]               sop;
    logic [$clog2(512/8)-1:0]   emp;
    logic [16-1:0]              size;
    sv_meta1_t m;
} sv_meta2_t;

typedef struct packed {
    logic [1024-1:0]            d;
    logic [4-1:0]               c;
    logic [1-1:0]               f;
    sv_meta1_t m;
} sv_meta3_t;

typedef struct packed {
    logic [256-1:0] h;
    sv_meta1_t m;
} sv_meta4_t;

typedef struct packed {
    logic [8-1:0][256-1:0] os;
    sv_meta4_t m;
} sv_meta5_t;

typedef struct packed {
    logic [1-1:0] res;
    logic [256-1:0] Rx;
    logic [256-1:0] Zx;
    logic [256-1:0] Zy;
    logic [256-1:0] Zz;
    logic [256-1:0] sig_l;
    sv_meta0_t m;
} sv_meta6_t;

typedef struct packed {
    logic [1-1:0] res;
    sv_meta0_t m;
} sv_meta7_t;

typedef struct packed {
    logic [32-1:0] tspub;
    logic [32-1:0] tsorig;
    logic [16-1:0] ctrl;
    logic [16-1:0] sz;
    logic [32-1:0] chunk;
    logic [64-1:0] sig;
    logic [64-1:0] seq;

    logic [64-1:0] pcim_strb;
    logic [64-1:0] pcim_addr;
} mcache_pcim_t;

endpackage : wd_sigverify
























`default_nettype none

`define WIDE_PIPE(___, _, _W, __) piped_wire #(.WIDTH(_W), .DEPTH(__)) piped_wire_``___`` (.clk(clk), .reset(rst), .in(_), .out(___));
`define SHADD_6_1C(_W, _O, _S0, _S1, _S2, _S3, _S4, _S5, _I0, _I1, _I2, _I3, _I4, _I5) shift_adder_6 #(.W(_W),.S0(_S0),.S1(_S1),.S2(_S2),.S3(_S3),.S4(_S4),.S5(_S5),.R0(0),.R1(0),.R(1),.C(0)) ``_O``_shadd6_inst (.cin0('0), .in0(_I0),.in1(_I1),.in2(_I2),.in3(_I3),.in4(_I4),.in5(_I5),.out0(_O),.clk(clk),.rst(rst), .m_i('0), .m_o(), .cout0());
`define SHADD_6_2C(_W, _O, _S0, _S1, _S2, _S3, _S4, _S5, _I0, _I1, _I2, _I3, _I4, _I5) shift_adder_6 #(.W(_W),.S0(_S0),.S1(_S1),.S2(_S2),.S3(_S3),.S4(_S4),.S5(_S5),.R0(0),.R1(0),.R(1),.C(1)) ``_O``_shadd6_inst (.cin0('0), .in0(_I0),.in1(_I1),.in2(_I2),.in3(_I3),.in4(_I4),.in5(_I5),.out0(_O),.clk(clk),.rst(rst), .m_i('0), .m_o(), .cout0());

(* dont_touch = "yes" *) module piped_wire #(
    parameter integer WIDTH=32,
    parameter integer DEPTH=1
)(
	input wire [WIDTH-1:0] in,
	output bit [WIDTH-1:0] out,
	input wire clk,
	input wire reset
);

generate
	if (DEPTH == 0) begin
		assign out = in;
	end
	else
	if (DEPTH == 1) begin
		always_ff @(posedge clk) begin
			out <= in;
		end
	end
	else
	begin
		bit [DEPTH-1-1:0] pipe [WIDTH-1:0];
		for (genvar g_i = 0; g_i < WIDTH; g_i ++) begin: G_I
			always_ff @(posedge clk) begin
				{out[g_i], pipe[g_i]} <= {pipe[g_i], in[g_i]};
			end
		end
	end
endgenerate

endmodule // piped_wire

module piped_pending #(
    parameter integer W=32,
    parameter integer D=2
)(
    input wire [1-1:0] u,
    input wire [1-1:0] d,
    output logic [W-1:0] p,
    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

logic [1-1:0] uu;
logic [1-1:0] dd;

piped_wire #(
    .WIDTH                                              (2),
    .DEPTH                                              (D)
) ecc_o_pipe_inst (
    .in                                                 ({u, d}),
    .out                                                ({uu, dd}),

    .clk                                                (clk),
    .reset                                              (rst)
);

always_ff@(posedge clk) begin
    case({
        uu,
        dd
    })
        2'b10: p <= p + 1;
        2'b01: p <= p - 1;
    endcase
    if (rst) p <= 0; 
end

endmodule // piped_pending

module piped_counter #(
    parameter integer D=2,
    parameter integer W=32
)(
    output logic [W-1:0] c,
    input wire [1-1:0] p,
    input wire [1-1:0] s,
    input wire [1-1:0] r,
    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

logic [1-1:0] pp, ss, rr;
logic [W-1:0] cnt;

piped_wire #(
    .WIDTH                                              (3),
    .DEPTH                                              (D)
) ecc_o_pipe_inst (
    .in                                                 ({p, s, r}),
    .out                                                ({pp, ss, rr}),

    .clk                                                (clk),
    .reset                                              (rst)
);

always_ff@(posedge clk) begin
    cnt <= rr ? '0 : cnt + pp;
    if (ss)
        c <= cnt;
end

endmodule // piped_counter

module piped_adder #(
    parameter integer W=384,
    parameter integer C=1,
    parameter integer M=1,
    parameter integer R=0
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [1-1:0]                                              cin0,
    input wire [W-1:0]                                              in0,
    input wire [W-1:0]                                              in1,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o,
    output logic [W-1:0]                                            out0,
    output logic [1-1:0]                                            cout0
);

generate
    if (C == 0) begin
        logic [W+1-1:0] s;
        assign s = in0 + in1 + cin0;
        if (R == 0) begin
            assign out0 = s[0+:W];
            assign cout0 = s[W];
            assign m_o = m_i;
        end else begin
            always_ff@(posedge clk) out0 <= s[0+:W];
            always_ff@(posedge clk) cout0 <= s[W];
            always_ff@(posedge clk) m_o <= m_i;
        end
    end else begin
        localparam W1 = W / 2;
        localparam W2 = W - W1;

        logic [2-1:0] c;
        logic [W1-1:0] i00;
        logic [W2-1:0] i01;
        logic [W1-1:0] i10;
        logic [W2-1:0] i11;
        logic [W2-1:0] i0_p;
        logic [W2-1:0] i1_p;
        logic [W1-1:0] s0;
        logic [W1-1:0] s1;
        logic [W2-1:0] s2;
        logic [2-1:0][M-1:0] m_o_p;

        assign {i01, i00} = in0;
        assign {i11, i10} = in1;

        assign out0 = {s2, s1};
        assign m_o = m_o_p[1];
        assign cout0 = c[1];

        piped_adder #(
            .W(W1),
            .C(C-1),
            .R(1),
            .M(M+W2+W2)
        ) piped_adder_inst_0 (
            .clk                                                    (clk),
            .rst                                                    (rst),

            .cin0                                                   (cin0),
            .in0                                                    (i00),
            .in1                                                    (i10),
            .out0                                                   (s0),
            .cout0                                                  (c[0]),
            .m_i                                                    ({m_i, i11, i01}),
            .m_o                                                    ({m_o_p[0], i1_p, i0_p})
        );

        piped_adder #(
            .W(W2),
            .C(C-1),
            .R(1),
            .M(M+W1)
        ) piped_adder_inst_1 (
            .clk                                                    (clk),
            .rst                                                    (rst),

            .cin0                                                   (c[0]),
            .in0                                                    (i0_p),
            .in1                                                    (i1_p),
            .out0                                                   (s2),
            .cout0                                                  (c[1]),
            .m_i                                                    ({m_o_p[0], s0}),
            .m_o                                                    ({m_o_p[1], s1})
        );

    end
endgenerate

endmodule // piped_adder

module shift_adder_6 #(
    parameter integer W                                             = 384,
    parameter integer S0                                            = 0,
    parameter integer S1                                            = 1,
    parameter integer S2                                            = 2,
    parameter integer S3                                            = 3,
    parameter integer S4                                            = 4,
    parameter integer S5                                            = 5,
    parameter integer C                                             = 0,
    parameter integer M                                             = 1,
    parameter integer R                                             = 1,
    parameter integer R0                                            = 0,
    parameter integer R1                                            = 1
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [1-1:0]                                              cin0,
    input wire [W-1:0]                                              in0,
    input wire [W-1:0]                                              in1,
    input wire [W-1:0]                                              in2,
    input wire [W-1:0]                                              in3,
    input wire [W-1:0]                                              in4,
    input wire [W-1:0]                                              in5,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o,
    output logic [W-1:0]                                            out0,
    output logic [1-1:0]                                            cout0
);

logic [1-1:0] cin0_, cin0__;

logic [2-1:0][M-1:0] m_o_p;

wire [W-1:0] i0, i1, i2, i3, i4, i5;

wire [W-1:0] c01_s;
wire [W-1:0] c01_c0;
wire [W-1:0] c01_c1;
wire [W-1:0] c02_s;
wire [W-1:0] c02_c;

assign i0 = in0 << S0;
assign i1 = in1 << S1;
assign i2 = in2 << S2;
assign i3 = in3 << S3;
assign i4 = in4 << S4;
assign i5 = in5 << S5;

red_6_3 #(
    .W(W),
    .R(R0),
    .M($bits({m_i, cin0}))
) red_6_3_inst (
    .in0(i0),
    .in1(i1),
    .in2(i2),
    .in3(i3),
    .in4(i4),
    .in5(i5),
    .sout(c01_s),
    .cout0(c01_c0),
    .cout1(c01_c1),
    .m_i({m_i, cin0}),
    .m_o({m_o_p[0], cin0_}),
    .clk(clk)
);

red_3_2 #(
    .W(W),
    .R(R1),
    .M($bits({m_i, cin0}))
) red_3_2_inst (
    .i0(c01_s),
    .i1(c01_c0 << 1),
    .i2(c01_c1 << 2),
    .s(c02_s),
    .c(c02_c),
    .m_i({m_o_p[0], cin0_}),
    .m_o({m_o_p[1], cin0__}),
    .clk(clk)
);

piped_adder #(
    .W(W),
    .R(R),
    .C(C),
    .M(M)
) a0_inst (
    .clk(clk),
    .rst(rst),
    .cin0(cin0__),
    .in0(c02_s),
    .in1(c02_c << 1),
    .out0(out0),
    .cout0(cout0),
    .m_i(m_o_p[1]),
    .m_o(m_o)
);

endmodule // shift_adder_6

module shift_adder_3 #(
    parameter integer W                                             = 384,
    parameter integer S0                                            = 0,
    parameter integer S1                                            = 1,
    parameter integer S2                                            = 2,
    parameter integer C                                             = 0,
    parameter integer M                                             = 1,
    parameter integer R                                             = 1,
    parameter integer R0                                            = 0
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [1-1:0]                                              cin0,
    input wire [W-1:0]                                              in0,
    input wire [W-1:0]                                              in1,
    input wire [W-1:0]                                              in2,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o,
    output logic [W-1:0]                                            out0,
    output logic [1-1:0]                                            cout0
);

logic [1-1:0][M-1:0] m_o_p;

wire [W-1:0] i0, i1, i2;

wire [W-1:0] c01_s;
wire [W-1:0] c01_c;

assign i0 = in0 << S0;
assign i1 = in1 << S1;
assign i2 = in2 << S2;

red_3_2 #(
    .W(W),
    .R(R0),
    .M(M)
) red_3_2_inst (
    .i0(i0),
    .i1(i1),
    .i2(i2),
    .s(c01_s),
    .c(c01_c),
    .m_i(m_i),
    .m_o(m_o_p[0]),
    .clk(clk)
);

piped_adder #(
    .W(W),
    .R(R),
    .C(C),
    .M(M)
) a0_inst (
    .clk(clk),
    .rst(rst),
    .cin0(cin0),
    .in0(c01_s),
    .in1(c01_c << 1),
    .out0(out0),
    .cout0(cout0),
    .m_i(m_o_p[0]),
    .m_o(m_o)
);

endmodule // shift_adder_3

module red_6_3 #(
    parameter integer W = 1,
    parameter integer R = 0,
    parameter integer M = 1
)(
    input wire [W-1:0] in0,
    input wire [W-1:0] in1,
    input wire [W-1:0] in2,
    input wire [W-1:0] in3,
    input wire [W-1:0] in4,
    input wire [W-1:0] in5,
    output logic [W-1:0][1-1:0] sout,
    output logic [W-1:0][1-1:0] cout0,
    output logic [W-1:0][1-1:0] cout1,
    input wire [M-1:0] m_i,
    output logic [M-1:0] m_o,
    input wire [1-1:0] clk
);

generate
    for (genvar g_i = 0; g_i < W; g_i ++) begin
        logic [3-1:0] ss;

        assign ss = in0[g_i]+in1[g_i]+in2[g_i]+in3[g_i]+in4[g_i]+in5[g_i];

        if (R == 0) begin
            assign sout[g_i] = ss[0];
            assign cout0[g_i] = ss[1];
            assign cout1[g_i] = ss[2];
        end else begin
            always_ff@(posedge clk) sout[g_i] <= ss[0];
            always_ff@(posedge clk) cout0[g_i] <= ss[1];
            always_ff@(posedge clk) cout1[g_i] <= ss[2];
            always_ff@(posedge clk) cout1[g_i] <= ss[2];
        end

    end

    if (R == 0) begin
        assign m_o = m_i;
    end else begin
        always_ff@(posedge clk) m_o <= m_i;
    end
endgenerate

endmodule // red_6_3

module red_3_2 #(
    parameter integer W = 1,
    parameter integer R = 1,
    parameter integer M = 1
)(
    input wire [W-1:0] i0,
    input wire [W-1:0] i1,
    input wire [W-1:0] i2,
    output logic [W-1:0] s,
    output logic [W-1:0] c,
    input wire [M-1:0] m_i,
    output logic [M-1:0] m_o,
    input wire [1-1:0] clk
);

generate
    for (genvar g_i = 0; g_i < W; g_i ++) begin
        logic [2-1:0] ss;

        assign ss = i0[g_i] + i1[g_i] + i2[g_i];

        if (R == 0) begin
            assign s[g_i] = ss[0];
            assign c[g_i] = ss[1];
        end else begin
            always_ff@(posedge clk) s[g_i] <= ss[0];
            always_ff@(posedge clk) c[g_i] <= ss[1];
        end
    end

    if (R == 0) begin
        assign m_o = m_i;
    end else begin
        always_ff@(posedge clk) m_o <= m_i;
    end
endgenerate

endmodule // red_3_2

module throttle #(
) (
    input wire [1-1:0]                          i,
    input wire [1-1:0]                          o,
    input wire [10-1:0]                         f,
    input wire [3-1:0][12-1:0]                  ths,
    output logic [1-1:0]                        w,
    input wire [1-1:0]                          clk,
    input wire [1-1:0]                          rst
);

logic [12-1:0]                                  th0_r;
logic [12-1:0]                                  th1_r;
logic [12-1:0]                                  th2_r;
logic [12-1:0]                                  cnt;
logic [12-1:0]                                  cnt_n;
logic [12-1:0]                                  gap;

piped_wire #(
    .WIDTH                                      ($bits({ths})),
    .DEPTH                                      (2)
) th_pipe_inst (
    .in                                         ({ths}),
    .out                                        ({th2_r, th1_r, th0_r}),

    .clk                                        (clk),
    .reset                                      (rst)
);

always_comb begin
    case ({i, o})
        2'b10   : cnt_n                         = cnt + 1;
        2'b01   : cnt_n                         = cnt - 1;
        default : cnt_n                         = cnt;
    endcase
end

always_ff@(posedge clk) begin
    gap                                         <= i ? 0 : (gap + ~&gap);
    cnt                                         <= cnt_n;
    w <= (0
        | (cnt_n + f >= th0_r)
        | (f >= th1_r)
        | (gap < th2_r)
    );

    if (rst) begin
        gap                                     <= 0;
        cnt                                     <= 0;
        w                                       <= 0;
    end
end

endmodule // throttle

module showahead_pkt_fifo #(
    parameter integer WIDTH = 32,
    parameter integer DEPTH = 32,
    parameter integer D_L = $clog2(DEPTH),
    parameter integer FULL_THRESH = DEPTH-6
)(
   input wire wr_clk,
   input wire wr_req,
   input wire [WIDTH-1:0] wr_data,
   input wire [1-1:0] wr_eop,
   output wire wr_full,
   output wire wr_full_b,
   output wire [D_L+1-1:0] wr_count,
   output wire [D_L+1-1:0] wr_count_pkt,

   input wire rd_clk,
   input wire rd_req,
   output wire [WIDTH-1:0] rd_data,
   output wire [1-1:0] rd_eop,
   output wire rd_empty,
   output wire rd_not_empty,
   output wire [D_L+1-1:0] rd_count,
   output wire [D_L+1-1:0] rd_count_pkt,

   input wire aclr
);

logic [2-1:0]                           rd_not_empty_;

assign rd_not_empty                     = &rd_not_empty_;
assign rd_empty                         = ~rd_not_empty;

showahead_fifo #(
    .WIDTH                              (1),
    .DEPTH                              (DEPTH)
) f0_inst (
    .aclr                               (aclr),

    .wr_clk                             (wr_clk),
    .wr_req                             (wr_req & wr_eop),
    .wr_full                            (),
    .wr_data                            ('0),
    .wr_count                           (wr_count_pkt),

    .rd_clk                             (rd_clk),
    .rd_req                             (rd_req & rd_eop),
    .rd_empty                           (),
    .rd_not_empty                       (rd_not_empty_[0]),
    .rd_count                           (rd_count_pkt),
    .rd_data                            ()
);

showahead_fifo #(
    .WIDTH                              ($bits({wr_data, wr_eop})),
    .DEPTH                              (DEPTH)
) f1_inst (
    .aclr                               (aclr),

    .wr_clk                             (wr_clk),
    .wr_req                             (wr_req),
    .wr_full                            (wr_full),
    .wr_full_b                          (wr_full_b),
    .wr_data                            ({wr_data, wr_eop}),
    .wr_count                           (wr_count),

    .rd_clk                             (rd_clk),
    .rd_req                             (rd_req),
    .rd_empty                           (),
    .rd_not_empty                       (rd_not_empty_[1]),
    .rd_count                           (rd_count),
    .rd_data                            ({rd_data, rd_eop})
);

endmodule // showahead_pkt_fifo

module rrb_merge #(
    parameter integer                   W = 1,
    parameter integer                   N = 2
) (
    output logic [N-1:0][1-1:0]         i_r,
    input wire [N-1:0][1-1:0]           i_v,
    input wire [N-1:0][1-1:0]           i_e,
    input wire [N-1:0][W-1:0]           i_m,

    input wire [1-1:0]                  o_r,
    output logic [1-1:0]                o_v,
    output logic [1-1:0]                o_e,
    output logic [W-1:0]                o_m,

    input wire [1-1:0]                  clk,
    input wire [1-1:0]                  rst
    
);

localparam integer N_L                  = $clog2(N);

logic [1-1:0]                           st;
logic [N_L-1:0]                         rrb;

assign o_v                              = i_v[rrb];
assign o_e                              = i_e[rrb];
assign o_m                              = i_m[rrb];

always_comb begin
    i_r = 0;
    i_r[rrb] = o_r;
end

always_ff@(posedge clk) begin
    case(st)
        0: begin
            casez({o_v, o_e, o_r})
                3'b0zz, 3'b111  : rrb   <= (rrb + 1 == N) ? 0 : rrb + 1;
                3'b10z, 3'b110  : st    <= 1;
            endcase
        end
        1: begin
            if (o_v & o_e & o_r) begin
                rrb                     <= (rrb + 1 == N) ? 0 : rrb + 1;
                st                      <= 0;
            end
        end
    endcase
    if (rst) begin
        st <= 0;
        rrb <= 0;
    end
end

endmodule // rrb_merge

module var_pipe #(
    parameter integer W_D = 512,
    parameter integer D = 512
) (
    output logic [1-1:0]        i_r,
    input wire [1-1:0]          i_v,
    input wire [1-1:0]          i_e,
    input wire [1-1:0]          i_w,
    input wire [W_D-1:0]        i_m,

    output logic [1-1:0]        o_v,
    output logic [1-1:0]        o_e,
    output logic [W_D-1:0]      o_m,

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

logic [64-1:0]                  timestamp = 0;

logic [1-1:0]                   ii_r;
logic [1-1:0]                   ii_v;
logic [16-1:0]                  ii_w;
logic [W_D-1:0]                 ii_d;

logic [1-1:0]                   push_v;
logic [1-1:0]                   push_e;
logic [64-1:0]                  push_t;
logic [W_D-1:0]                 push_m;

logic [1-1:0]                   pop_v;
logic [64-1:0]                  pop_t;

always_ff@(posedge clk) timestamp <= timestamp + 1;

always_comb begin

    i_r = ~i_w;

    push_v = i_v & ~i_w;
    push_e = i_e;
    push_m = i_m;
    push_t = i_m[0+:16] + timestamp;

    o_v = 0;

    if (pop_v) begin
        if (pop_t < timestamp) begin
            i_r = 0;

            push_v = 1;
            push_e = o_e;
            push_m = o_m;
            push_t = pop_t;
        end else begin
            o_v = 1;
        end
    end
end

showahead_fifo #(
    .WIDTH                                              ($bits({push_m, push_e, push_t})),
    .DEPTH                                              (D)
) w_fifo_inst (
    .aclr                                               (rst),

    .wr_clk                                             (clk),
    .wr_req                                             (push_v),
    .wr_full                                            (),
    .wr_full_b                                          (),
    .wr_count                                           (),
    .wr_data                                            ({push_m, push_e, push_t}),

    .rd_clk                                             (clk),
    .rd_req                                             (pop_v),
    .rd_empty                                           (),
    .rd_not_empty                                       (pop_v),
    .rd_count                                           (),
    .rd_data                                            ({o_m, o_e, pop_t})
);

endmodule // var_pipe

`default_nettype wire
