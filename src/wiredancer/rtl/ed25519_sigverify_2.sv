`default_nettype none

import wd_sigverify::*;

module ed25519_sigverify_2 #(
    MUL_T                                               = 32'h007F_CCC2
) (
    output logic [1-1:0]                                i_r,
    input wire [1-1:0]                                  i_w,
    input wire [1-1:0]                                  i_v,
    input wire [$bits(sv_meta6_t)-1:0]                  i_m,

    output logic [1-1:0]                                o_v,
    output logic [$bits(sv_meta7_t)-1:0]                o_m,

    input wire clk,
    input wire rst
);

logic [1-1:0]                                           st_i, st_o;

sv_meta6_t                                              i_mm;
sv_meta7_t                                              o_mm;

sv_meta6_t                                              mul_i_m;
logic [255-1:0]                                         mul_i_A;
logic [255-1:0]                                         mul_i_B;

logic [1-1:0]                                           mul_o_v;
sv_meta6_t                                              mul_o_m;
logic [255-1:0]                                         mul_o_C;

assign i_r                                              = st_i == 1;
assign i_mm                                             = i_m;
assign o_m                                              = o_mm;

always_ff@(posedge clk) begin
    case (st_i)
        0: begin
            mul_i_m                                     <= i_mm;
            mul_i_A                                     <= i_mm.Zz;
            mul_i_B                                     <= i_mm.Rx;
            if (i_v & ~i_w) begin
                st_i                                    <= 1;
            end
        end
        1: begin
            mul_i_B                                     <= i_mm.sig_l[0+:255];
            st_i                                        <= 0;
        end
    endcase
    if (rst) begin
        st_i                                            <= 0;
    end
end

ed25519_mul_modp #(
    .T                                                  (MUL_T),
    .M                                                  ($bits({mul_i_m, st_i}))
) mul_modp_inst (
    .in0                                                (mul_i_A),
    .in1                                                (mul_i_B),
    .m_i                                                ({mul_i_m, st_i}),

    .out0                                               (mul_o_C),
    .m_o                                                ({mul_o_m, mul_o_v}),

    .clk                                                (clk),
    .rst                                                (rst)
);

always_ff@(posedge clk) begin
    case (st_o)
        0: begin
            o_v                                         <= 0;
            o_mm.m                                      <= mul_o_m.m;
            o_mm.res                                    <= mul_o_m.res & (mul_o_m.Zx == mul_o_C);
            if (mul_o_v)
                st_o                                    <= 1;
        end
        1: begin
            o_v                                         <= 1;
            o_mm.res                                    <= o_mm.res & (mul_o_m.Zy == mul_o_C);
            st_o                                        <= 0;
        end
    endcase
    if (rst) begin
        o_v                                             <= 0;
        st_o                                            <= 0;
    end
end

endmodule

`default_nettype wire
