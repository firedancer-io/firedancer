`default_nettype none

import wd_sigverify::*;

module ed25519_sigverify_dsdp_mul #(
    MUL_T                                               = 32'h007F_CCC2,
    MUL_D                                               = 15,
    ADD_D                                               = 4,
    PIPE_D                                              = (MUL_D*3) + ADD_D,
    N_TH                                                = 2+PIPE_D+PIPE_D,
    W_M                                                 = 64,
    W_S                                                 = 2
) (
    output logic [1-1:0]                                i_r,
    input wire [1-1:0]                                  i_v,
    input wire [W_M-1:0]                                i_m,

    input wire [255-1:0]                                i_Ax,
    input wire [255-1:0]                                i_Ay,
    input wire [255-1:0]                                i_Az,
    input wire [255-1:0]                                i_At,

    input wire [255-1:0]                                i_ApGx, // A+G
    input wire [255-1:0]                                i_ApGy,
    input wire [255-1:0]                                i_ApGz,
    input wire [255-1:0]                                i_ApGt,

    input wire [256-1:0]                                i_As,
    input wire [256-1:0]                                i_Gs,

    output logic [1-1:0]                                o_v,
    output logic [W_M-1:0]                              o_m,

    output logic [255-1:0]                              o_Cx,
    output logic [255-1:0]                              o_Cy,
    output logic [255-1:0]                              o_Cz,
    output logic [255-1:0]                              o_Ct,

    input wire clk,
    input wire rst
);

endmodule

`default_nettype wire
