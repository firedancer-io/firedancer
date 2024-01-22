`default_nettype none

import wd_sigverify::*;

module mul_wide #(
    W=127,W0=W,W1=W,L=4,T=32'h07FCCC,
    W2=W/2,
    R_I=0,
    CT = T[0 +: 4],
    ST = T >> 4,
    M=32,
    S=0
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [W0-1:0]                                             in0,
    input wire [W1-1:0]                                             in1,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o,
    output logic [W0+W1-1:0]                                        out0
);

logic [W0-1:0] in0_r;
logic [W1-1:0] in1_r;
logic [M-1:0] m_i_r;

generate

    if (R_I) begin
        always_ff@(posedge clk) in0_r <= in0;
        always_ff@(posedge clk) in1_r <= in1;
        always_ff@(posedge clk) m_i_r <= m_i;
    end else begin
        assign in0_r = in0;
        assign in1_r = in1;
        assign m_i_r = m_i;
    end

    // Native
    if (CT == 0) begin: T0

        // always_ff@(posedge clk) $display("%t: %m. T = %x, W = %0d",$time, T, W);

        if (0) begin
        end else if (S == 0) begin

            if (ST == 0) begin

                always_ff@(posedge clk) out0 <= in0_r * in1_r;
                always_ff@(posedge clk) m_o <= m_i_r;
            
            end else begin

                logic [W0+W1-1:0] m;

                assign m = in0_r * in1_r;

                `WIDE_PIPE(m_o, m_i, M, ST)
                `WIDE_PIPE(out0, m, W0+W1, ST)

            end

        end else begin
            logic signed [W-1:0] i0;
            logic signed [W-1:0] i1;
            logic signed [W*2-1:0] o0;

            assign i0 = in0;
            assign i1 = in1;
            assign out0 = o0;

            always_ff@(posedge clk) o0 <= i0 * i1;
            always_ff@(posedge clk) m_o <= m_i;
        end

    // Naive
    end else if (CT == 1) begin: T1
        logic [2-1:0][W2-1:0] x;
        logic [2-1:0][W2-1:0] y;
        logic [3-1:0][W-1:0] z;
        logic [W+1-1:0] z1;
        logic [4-1:0][W-1:0] m;
        logic [2-1:0][M-1:0] m_o_p;

        assign x = in0;
        assign y = in1;

        always_ff@(posedge clk) z[0]    <= m[0];
        always_ff@(posedge clk) z1      <= m[1] + m[2];
        always_ff@(posedge clk) z[2]    <= m[3];
        always_ff@(posedge clk) m_o_p[1]<= m_o_p[0];

        always_ff@(posedge clk) out0    <= {z[2], {W{1'b0}}} + {z1, {W2{1'b0}}} + z[0];
        always_ff@(posedge clk) m_o     <= m_o_p[1];

        mul_wide #(
            .W(W2),.L(L),
            .T(ST)
        ) mul_wide_m0_inst(
            .clk(clk),
            .rst(rst),
            .in0(x[0]),
            .in1(y[0]),
            .out0(m[0])
        );
        mul_wide #(
            .W(W2),.L(L),
            .T(ST)
        ) mul_wide_m1_inst(
            .clk(clk),
            .rst(rst),
            .in0(x[0]),
            .in1(y[1]),
            .out0(m[1])
        );
        mul_wide #(
            .W(W2),.L(L),
            .T(ST)
        ) mul_wide_m2_inst(
            .clk(clk),
            .rst(rst),
            .in0(x[1]),
            .in1(y[0]),
            .out0(m[2])
        );
        mul_wide #(
            .W(W2),.L(L),
            .T(ST),
            .M(M)
        ) mul_wide_m3_inst(
            .clk(clk),
            .rst(rst),
            .in0(x[1]),
            .in1(y[1]),
            .out0(m[3]),
            .m_i(m_i),
            .m_o(m_o_p[0])
        );

    // W-1
    end else if (CT == 2) begin: T2

        localparam W_M1 = W-1;

        logic [W+1-1:0] a;
        logic [W+1-1:0] b;
        logic [W_M1*2-1:0] m;
        logic [M-1:0] m_o_p;

        assign a = (in0[W-1] ? in1[0 +: W_M1] : '0) + (in1[W-1] ? in0[0 +: W] : '0);

        assign out0 = m + (b << W_M1);
        assign m_o = m_o_p;

        mul_wide #(
            .W(W_M1),
            .T(ST),
            .M(M + W+1)
        ) mul_wide_m0_inst(
            .clk(clk),
            .rst(rst),
            .in0(in0[0 +: W_M1]),
            .in1(in1[0 +: W_M1]),
            .out0(m),
            .m_i({m_i, a}),
            .m_o({m_o_p, b})
        );
    // Karatsuba
    end else if (CT == 12) begin: T12

        // A = x[0] * y[0]
        // B = x[1] * y[1]
        // C = x[0] + x[1]
        // D = y[0] + y[1]
        // E = C * D
        // F = A + (B << W) + (E << W2) - (A << W2) - (B << W2)

        localparam WR = W - W2;
        localparam PA_C_W2  = 0;
        localparam PA_C_WW = W >= 127 ? 1 : 0;

        logic [W2-1:0] c_0_x0, c_a_x0;
        logic [W2-1:0] c_0_y0, c_a_y0;
        logic [WR-1:0] c_0_x1, c_a_x1;
        logic [WR-1:0] c_0_y1, c_a_y1;

        logic [WR-1:0] c_0_x0_, c_0_y0_;

        logic [WR+1-1:0] c_a_C;
        logic [WR+1-1:0] c_a_D;

        logic [W2+W2-1:0] c_am_A;
        logic [WR+WR-1:0] c_am_B;
        logic [WR+WR+2-1:0] c_am_E;

        logic [W+W-1:0] c_am_A_;
        logic [W+W-1:0] c_am_B_;
        logic [W+W-1:0] c_am_E_;

        logic [W+W-1:0] c_amb_F;

        logic [3-1:0][M-1:0] m_o_p;

        assign {c_0_x1, c_0_x0} = in0_r;
        assign {c_0_y1, c_0_y0} = in1_r;

        assign c_0_x0_ = {1'b0, c_0_x0};
        assign c_0_y0_ = {1'b0, c_0_y0};

        assign c_am_A_ = {1'b0, c_am_A};
        assign c_am_B_ = {1'b0, c_am_B};
        assign c_am_E_ = {1'b0, c_am_E};

        assign out0 = c_amb_F;
        assign m_o = m_o_p[2];

        mul_wide #(.W(W2+0), .T(ST), .M(M)) m0_inst (.clk(clk), .rst(rst), .in0(c_a_x0), .in1(c_a_y0), .out0(c_am_A), .m_i(m_o_p[0]), .m_o(m_o_p[1]));
        mul_wide #(.W(WR+0), .T(ST), .M(1)) m1_inst (.clk(clk), .rst(rst), .in0(c_a_x1), .in1(c_a_y1), .out0(c_am_B), .m_i(      '0), .m_o(        ));
        mul_wide #(.W(WR+1), .T(ST), .M(1)) m2_inst (.clk(clk), .rst(rst), .in0( c_a_C), .in1( c_a_D), .out0(c_am_E), .m_i(      '0), .m_o(        ));

        piped_adder #(
            .W(WR),
            .R(1),
            .C(PA_C_W2),
            .M(W+W+M)
        ) a0_inst (
            .clk(clk),
            .rst(rst),
            .cin0('0),
            .in0(c_0_x0_),
            .in1(c_0_x1),
            .out0(c_a_C[0+:WR]),
            .cout0(c_a_C[WR]),
            .m_i({c_0_x1, c_0_x0, c_0_y1, c_0_y0, m_i}),
            .m_o({c_a_x1, c_a_x0, c_a_y1, c_a_y0, m_o_p[0]})
        );
        piped_adder #(
            .W(WR),
            .R(1),
            .C(PA_C_W2)
        ) a1_inst (
            .clk(clk),
            .rst(rst),
            .cin0('0),
            .in0(c_0_y0_),
            .in1(c_0_y1),
            .out0(c_a_D[0+:WR]),
            .cout0(c_a_D[WR]),
            .m_i(),
            .m_o()
        );
        shift_adder_6 #(
            .W          (W+W),
            .S0         (0),
            .S1         (W2+W2),
            .S2         (W2),
            .S3         (W2),
            .S4         (W2),
            .S5         (W2),
            .C          (PA_C_WW),
            .M          (M),
            .R          (1),
            .R0         (0),
            .R1         (0)
        ) a2_inst (
            .clk(clk),
            .rst(rst),
            .cin0('0),
            .in0(c_am_A_),
            .in1(c_am_B_),
            .in2({ c_am_E_}),
            .in3({~c_am_A_}),
            .in4({~c_am_B_}),
            .in5({{(W+W-2){1'b0}}, 2'b10}),
            .out0(c_amb_F),
            .m_i(m_o_p[1]),
            .m_o(m_o_p[2]),
            .cout0()
        );
    // cascaded DSP
    end else if (CT == 15 && ST[0+:4] == 7) begin: T15_7

        localparam DEPTH = W0 < 27 ? 1 : W0 <= 26*2 ? 2 : W0 == 64 ? 2 : 1+4;

        if (W0 < 27) begin
        `include "mul_wide_17nx26_dsp48e2.svh"
        end else if (W0 <= 26*2) begin

            logic [26+W1-1:0] m_0;
            logic [W0-26+W1-1:0] m_1;

            mul_wide #(.W0(26)   , .W1(W1), .T(T)) m_0_inst (.clk(clk), .rst(rst), .in0(in0[  0 +: 26])   , .in1(in1), .out0(m_0));
            mul_wide #(.W0(W0-26), .W1(W1), .T(T)) m_1_inst (.clk(clk), .rst(rst), .in0(in0[ 26 +: W0-26]), .in1(in1), .out0(m_1));

            always_ff@(posedge clk) begin
                out0[0 +:26]                <= m_0[0+:26];
                out0[26+:W0+W1-26]          <= m_1 + m_0[26+:W1];
                // out0 <= m_0 + (m_1 << 26);
            end
        end

        logic [DEPTH-1:0][M-1:0] m_o_p;

        always_ff@(posedge clk) begin
            integer i;
            m_o_p[0] <= m_i;
            for (i = 1; i < DEPTH; i ++)
                m_o_p[i] <= m_o_p[i-1];
            end
        assign m_o = m_o_p[DEPTH-1];

    end else if (CT == 15 && ST[0+:4] == 1) begin: T15_1
        `include "mul_const_ED25519_L0_260.svh"
    end else if (CT == 15 && ST[0+:4] == 2) begin: T15_1
        `include "mul_const_ED25519_L0_133.svh"
    end else if (CT == 15 && ST[0+:4] == 3) begin: T15_1
        `include "mul_const_ED25519_L0_6.svh"
    end
endgenerate

endmodule

`default_nettype wire
