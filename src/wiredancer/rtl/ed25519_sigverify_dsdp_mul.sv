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

localparam N_TH_L                                       = $clog2(N_TH*2);

typedef struct packed {

    logic [N_TH_L-1:0]                                  t_i;
    logic [1-1:0]                                       v;
    logic [10-1:0]                                      PC;
    logic [W_M-1:0]                                     m;
    logic [256-1:0]                                     As;
    logic [256-1:0]                                     Gs;

} meta_t;

logic [1-1:0]                                           c_0_we;
meta_t                                                  c_0_m;

meta_t                                                  c_1_m;
logic [2-1:0]                                           c_1_sel;
logic [255-1:0]                                         c_1_Ax;
logic [255-1:0]                                         c_1_Ay;
logic [255-1:0]                                         c_1_Az;
logic [255-1:0]                                         c_1_At;
logic [255-1:0]                                         c_1_ApGx;
logic [255-1:0]                                         c_1_ApGy;
logic [255-1:0]                                         c_1_ApGz;
logic [255-1:0]                                         c_1_ApGt;
logic [255-1:0]                                         c_1_Cx;
logic [255-1:0]                                         c_1_Cy;
logic [255-1:0]                                         c_1_Cz;
logic [255-1:0]                                         c_1_Ct;
logic [4-1:0][255-1:0]                                  c_1_Px;
logic [4-1:0][255-1:0]                                  c_1_Py;
logic [4-1:0][255-1:0]                                  c_1_Pz;
logic [4-1:0][255-1:0]                                  c_1_Pt;

meta_t                                                  c_2_m;
logic [255-1:0]                                         c_2_Ax;
logic [255-1:0]                                         c_2_Ay;
logic [255-1:0]                                         c_2_Az;
logic [255-1:0]                                         c_2_At;
logic [255-1:0]                                         c_2_Bx;
logic [255-1:0]                                         c_2_By;
logic [255-1:0]                                         c_2_Bz;
logic [255-1:0]                                         c_2_Bt;

meta_t                                                  c_a_m;
meta_t                                                  c_a_m_;
logic [255-1:0]                                         c_a_Cx;
logic [255-1:0]                                         c_a_Cy;
logic [255-1:0]                                         c_a_Cz;
logic [255-1:0]                                         c_a_Ct;

meta_t                                                  po_m;
logic [255-1:0]                                         po_Cx;
logic [255-1:0]                                         po_Cy;
logic [255-1:0]                                         po_Cz;
logic [255-1:0]                                         po_Ct;

always_comb begin

    case (po_m.v)
        0: begin
            i_r                 = 1;

            c_0_we              = i_v;

            c_0_m.v             = i_v;
            c_0_m.PC            = 0;
            c_0_m.m             = i_m;

            c_0_m.As            = i_As;
            c_0_m.Gs            = i_Gs;
        end

        // 1: begin
        default: begin
            i_r                 = 0;

            c_0_we              = 0;

            c_0_m.v             = po_m.v;
            c_0_m.PC            = po_m.PC + 1;
            c_0_m.m             = po_m.m;
            c_0_m.As            = po_m.As;
            c_0_m.Gs            = po_m.Gs;
        end
    endcase

    c_1_Px[0] = ED25519_Ix;
    c_1_Px[1] = ED25519_Gx;
    c_1_Px[2] = c_1_Ax;
    c_1_Px[3] = c_1_ApGx;

    c_1_Py[0] = ED25519_Iy;
    c_1_Py[1] = ED25519_Gy;
    c_1_Py[2] = c_1_Ay;
    c_1_Py[3] = c_1_ApGy;

    c_1_Pz[0] = ED25519_Iz;
    c_1_Pz[1] = ED25519_Gz;
    c_1_Pz[2] = c_1_Az;
    c_1_Pz[3] = c_1_ApGz;

    c_1_Pt[0] = ED25519_It;
    c_1_Pt[1] = ED25519_Gt;
    c_1_Pt[2] = c_1_At;
    c_1_Pt[3] = c_1_ApGt;

    if (rst)
        c_0_m.v = 0;
end

always_comb begin
    c_a_m_ = c_a_m;
    if (c_a_m.PC == (W_S))
        c_a_m_.v = 0;
end

always_ff@(posedge clk) begin

    o_v                         <= c_a_m.v & ~c_a_m_.v;
    o_m                         <= c_a_m.m;
    o_Cx                        <= c_a_Cx;
    o_Cy                        <= c_a_Cy;
    o_Cz                        <= c_a_Cz;
    o_Ct                        <= c_a_Ct;

    c_0_m.t_i                   <= (c_0_m.t_i == N_TH-1) ? 0 : c_0_m.t_i + 1;

    c_1_m                       <= c_0_m;

    c_1_Cx                      <= po_Cx;
    c_1_Cy                      <= po_Cy;
    c_1_Cz                      <= po_Cz;
    c_1_Ct                      <= po_Ct;

    casez({
        c_0_m.PC == 0,
        po_m.As[255],
        po_m.Gs[255]
    })
        3'b1_zz: c_1_sel          <= 0; // I+I
        3'b0_00: c_1_sel          <= 0; // Z+I
        3'b0_01: c_1_sel          <= 1; // Z+G
        3'b0_10: c_1_sel          <= 2; // Z+A
        3'b0_11: c_1_sel          <= 3; // Z+ApG
    endcase

    c_2_m                       <= c_1_m;
    c_2_m.As                    <= (c_1_m.PC == 0) ? c_1_m.As : c_1_m.As << 1;
    c_2_m.Gs                    <= (c_1_m.PC == 0) ? c_1_m.Gs : c_1_m.Gs << 1;

    c_2_Ax                      <= (c_1_m.PC == 0) ? ED25519_Ix : c_1_Cx;
    c_2_Ay                      <= (c_1_m.PC == 0) ? ED25519_Iy : c_1_Cy;
    c_2_Az                      <= (c_1_m.PC == 0) ? ED25519_Iz : c_1_Cz;
    c_2_At                      <= (c_1_m.PC == 0) ? ED25519_It : c_1_Ct;

    c_2_Bx                      <= c_1_Px[c_1_sel];
    c_2_By                      <= c_1_Py[c_1_sel];
    c_2_Bz                      <= c_1_Pz[c_1_sel];
    c_2_Bt                      <= c_1_Pt[c_1_sel];

    if (rst) begin
        c_0_m.t_i               <= 0;
        c_1_m                   <= '0;
    end
end

simple_dual_port_ram #(
    .WRITE_MODE                                     ("read_first"),
    .CLOCKING_MODE                                  ("common_clock"),
    .ADDRESS_WIDTH                                  ($bits({c_0_m.t_i})),
    .DATA_WIDTH                                     ($bits({i_Ax, i_Ay, i_Az, i_At, i_ApGx, i_ApGy, i_ApGz, i_ApGt}))
) mem_ram_inst (
    .wr_clock                                       (clk),
    .wr_en                                          (c_0_we),
    .wr_byteenable                                  ('1),
    .wr_address                                     ({c_0_m.t_i}),
    .data                                           ({i_Ax, i_Ay, i_Az, i_At, i_ApGx, i_ApGy, i_ApGz, i_ApGt}),

    .rd_clock                                       (clk),
    .rd_address                                     ({c_0_m.t_i}),
    .q                                              ({c_1_Ax, c_1_Ay, c_1_Az, c_1_At, c_1_ApGx, c_1_ApGy, c_1_ApGz, c_1_ApGt}),
    .rd_en                                          (1'b1)
);

ed25519_point_add #(
    .T                                              (MUL_T),
    .D_M                                            (MUL_D),
    .M                                              ($bits(c_2_m))
) point_add_inst (

    .in0_x                                          (c_2_Ax),
    .in0_y                                          (c_2_Ay),
    .in0_z                                          (c_2_Az),
    .in0_t                                          (c_2_At),
    .in1_x                                          (c_2_Bx),
    .in1_y                                          (c_2_By),
    .in1_z                                          (c_2_Bz),
    .in1_t                                          (c_2_Bt),
    .out0_x                                         (c_a_Cx),
    .out0_y                                         (c_a_Cy),
    .out0_z                                         (c_a_Cz),
    .out0_t                                         (c_a_Ct),
    .m_i                                            (c_2_m),
    .m_o                                            (c_a_m),
    .clk                                            (clk),
    .rst                                            (rst)
);

ed25519_point_add #(
    .T                                              (MUL_T),
    .D_M                                            (MUL_D),
    .M                                              ($bits(c_2_m))
) point_dbl_inst (

    .in0_x                                          (c_a_Cx),
    .in0_y                                          (c_a_Cy),
    .in0_z                                          (c_a_Cz),
    .in0_t                                          (c_a_Ct),
    .in1_x                                          (c_a_Cx),
    .in1_y                                          (c_a_Cy),
    .in1_z                                          (c_a_Cz),
    .in1_t                                          (c_a_Ct),
    .out0_x                                         (po_Cx),
    .out0_y                                         (po_Cy),
    .out0_z                                         (po_Cz),
    .out0_t                                         (po_Ct),
    .m_i                                            (c_a_m_),
    .m_o                                            (po_m),
    .clk                                            (clk),
    .rst                                            (rst)
);

always_ff@(posedge clk)
if (i_v | po_m.v | c_0_m.v | c_1_m.v | c_2_m.v | c_a_m.v)
$display("%t: i %x %x %x - po %x %x %x - c0 %x %x %x %x %x %x - c1 %x %x %x %x - c2 %x %x %x %x %x - ca %x %x %x %x %x %x %x", $time
    , i_r
    , i_v
    , i_m

    , po_m.t_i
    , po_m.v
    , po_m.PC

    , c_0_m.t_i
    , c_0_m.v
    , c_0_we
    , c_0_m.PC
    , po_m.As[255]
    , po_m.Gs[255]

    , c_1_m.t_i
    , c_1_m.v
    , c_1_m.PC
    , c_1_sel

    , c_2_m.t_i
    , c_2_m.v
    , c_2_m.PC
    , c_2_Ay
    , c_2_By

    , c_a_m.t_i
    , c_a_m.v
    , c_a_m.PC
    , c_a_Cx
    , c_a_Cy
    , c_a_Cz
    , c_a_Ct
);

endmodule

`default_nettype wire
