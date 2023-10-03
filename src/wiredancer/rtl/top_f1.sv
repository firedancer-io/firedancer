`default_nettype none

import wd_sigverify::*;

module top_f1 #(
    // fast sim
    // MUL_T                                               = 32'h0000_0802, // 8-cycle mock mul_wide
    // MUL_D                                               = 15,
    // N_SCH                                               = 2,
    // DSDP_WS                                             = 256,
    // TH_PRE                                              = {12'h0, 12'd2, 12'd2},
    // TH_SHA                                              = {12'h0, 12'd2, 12'd2},
    // TH_SV0                                              = {12'h0, 12'd2, 12'd2},
    // TH_SV1                                              = {12'h0, 12'd2, 12'd2},
    // TH_SV2                                              = {12'h0, 12'd2, 12'd2},

    // small
    // KEY_D                                               = 32,
    // MUL_T                                               = 32'h007F_CCC2,
    // MUL_D                                               = 15,
    // N_SCH                                               = 2,
    // DSDP_WS                                             = 256,
    // TH_PRE                                              = {12'h0, 12'd2, 12'd2},
    // TH_SHA                                              = {12'h0, 12'd2, 12'd2},
    // TH_SV0                                              = {12'h0, 12'd2, 12'd2},
    // TH_SV1                                              = {12'h0, 12'd2, 12'd2},
    // TH_SV2                                              = {12'h0, 12'd2, 12'd2},

    // full
    KEY_D                                               = 512,
    MUL_T                                               = 32'h07F_CCC2,
    MUL_D                                               = 15,
    N_SCH                                               = 5,
    DSDP_WS                                             = 256,
    TH_PRE                                              = {12'h0, 12'd10, 12'd10},
    TH_SHA                                              = {12'h0, 12'd200, 12'd200},
    TH_SV0                                              = {12'h0, 12'd200, 12'd200},
    TH_SV1                                              = {12'h0, 12'd200, 12'd200},
    TH_SV2                                              = {12'h0, 12'd200, 12'd200},

    DBG_WIDTH = 1024,
    NO_DDR = 4,
    DMA_N = 2,
    DDR_BUFF_W = 20
) (

    input wire [1-1:0]                                  avmm_read,
    input wire [1-1:0]                                  avmm_write,
    input wire [32-1:0]                                 avmm_address,
    input wire [32-1:0]                                 avmm_writedata,
    output logic [32-1:0]                               avmm_readdata,
    output logic [1-1:0]                                avmm_readdatavalid,
    output logic [1-1:0]                                avmm_waitrequest,

    input wire [16-1:0][8-1:0]                          priv_bytes,

    input wire [2-1:0]                                  pcie_v,
    input wire [64-1:0]                                 pcie_a,
    input wire [2-1:0][256-1:0]                         pcie_d,

    input wire [1-1:0]                                  dma_r,
    output logic [1-1:0]                                dma_v,
    output logic [64-1:0]                               dma_a,
    output logic [64-1:0]                               dma_b,
    input wire [1-1:0]                                  dma_f,
    output logic [256-1:0]                              dma_d,

    output logic [NO_DDR-1:0][1-1:0]                    ddr_rd_en,
    input wire   [NO_DDR-1:0][1-1:0]                    ddr_rd_pop,
    output logic [NO_DDR-1:0][64-1:0]                   ddr_rd_addr,
    output logic [NO_DDR-1:0][9-1:0]                    ddr_rd_sz,
    input wire   [NO_DDR-1:0][1-1:0]                    ddr_rd_v,
    input wire   [NO_DDR-1:0][512-1:0]                  ddr_rd_data,

    output logic [NO_DDR-1:0][1-1:0]                    ddr_wr_en,
    input wire   [NO_DDR-1:0][1-1:0]                    ddr_wr_pop,
    input wire   [NO_DDR-1:0][1-1:0]                    ddr_wr_res,
    output logic [NO_DDR-1:0][64-1:0]                   ddr_wr_addr,
    output wire  [NO_DDR-1:0][512-1:0]                  ddr_wr_data,

    output logic [DBG_WIDTH-1:0]                        dbg_wire,

    input wire clk_f,
    input wire rst_f,

    input wire clk,
    input wire rst
);

logic [64-1:0]                          timestamp = 0;

logic [32-1:0]                          tr_pending;

(* dont_touch = "yes" *) logic [10-1:0] rst_r;
(* dont_touch = "yes" *) logic [10-1:0] rst_f_r;

logic [1-1:0]                           send_fails = 0;

logic [4-1:0]                           ths_msb;
logic [4-1:0][36-1:0]                   ths = {
    TH_SV1,
    TH_SV0,
    TH_SHA,
    TH_PRE
};

logic [1-1:0]                           pcie_iv     [N_PCIE-1:0];
logic [1-1:0]                           pcie_if     [N_PCIE-1:0];
logic [16-1:0]                          pcie_il     [N_PCIE-1:0];
logic [512-1:0]                         pcie_id     [N_PCIE-1:0];

logic [N_PCIE-1:0][1-1:0]               ext_r;
logic [N_PCIE-1:0][1-1:0]               ext_v;
logic [N_PCIE-1:0][1-1:0]               ext_e;
sv_meta2_t [N_PCIE-1:0]                 ext_m0;
pcie_meta_t [N_PCIE-1:0]                ext_m1;

logic [1-1:0]                           pad_i_r;
logic [1-1:0]                           pad_i_w;
logic [1-1:0]                           pad_i_v;
logic [1-1:0]                           pad_i_e;
sv_meta2_t                              pad_i_m;

logic [1-1:0]                           pad_o_v;
logic [1-1:0]                           pad_o_e;
sv_meta3_t                              pad_o_m;
logic [10-1:0]                          pad_o_f;

logic [1-1:0]                           sha_f_v;
logic [1-1:0]                           sha_f_e;
sv_meta3_t                              sha_f_m;
logic [10-1:0]                          sha_f_f;

logic [1-1:0]                           sha_i_r;
logic [1-1:0]                           sha_i_w;
logic [1-1:0]                           sha_i_v;
logic [1-1:0]                           sha_i_e;
sv_meta3_t                              sha_i_m;

logic [1-1:0]                           sha_o_v;
sv_meta4_t                              sha_o_m;
logic [10-1:0]                          sha_o_f;

logic [1-1:0]                           sv0_f_v;
sv_meta4_t                              sv0_f_m;
logic [10-1:0]                          sv0_f_f;

logic [1-1:0]                           sv0_i_r;
logic [1-1:0]                           sv0_i_w;
logic [1-1:0]                           sv0_i_v;
sv_meta4_t                              sv0_i_m;

logic [1-1:0]                           sv0_o_v;
sv_meta5_t                              sv0_o_m;
logic [10-1:0]                          sv0_o_f;

logic [1-1:0]                           sv1_f_v;
sv_meta5_t                              sv1_f_m;
logic [10-1:0]                          sv1_f_f;

logic [1-1:0]                           sv1_i_r;
logic [1-1:0]                           sv1_i_w;
logic [1-1:0]                           sv1_i_v;
sv_meta5_t                              sv1_i_m;

logic [1-1:0]                           sv1_o_v;
sv_meta6_t                              sv1_o_m;
logic [10-1:0]                          sv1_o_f;

logic [1-1:0]                           sv2_f_v;
sv_meta6_t                              sv2_f_m;
logic [10-1:0]                          sv2_f_f;

logic [1-1:0]                           sv2_i_r;
logic [1-1:0]                           sv2_i_v;
sv_meta6_t                              sv2_i_m;

logic [1-1:0]                           sv2_o_v;
sv_meta7_t                              sv2_o_m;

logic [1-1:0]                           ecc_o_v;
sv_meta7_t                              ecc_o_m;

logic [N_PCIE-1:0][1-1:0]               res_o_v;
logic [N_PCIE-1:0][64-1:0]              res_o_t;
logic [N_PCIE-1:0][1-1:0]               res_o_d;
logic [N_PCIE-1:0][16-1:0]              res_o_c;
logic [N_PCIE-1:0][1-1:0]               res_o_f;
logic [N_PCIE-1:0][1-1:0]               res_o_p;

logic [N_PCIE-1:0][1-1:0]               dma_p_r;
logic [N_PCIE-1:0][1-1:0]               dma_p_v;
logic [N_PCIE-1:0][1-1:0]               dma_p_vv;
logic [N_PCIE-1:0][1-1:0]               dma_p_f;
logic [N_PCIE-1:0][16-1:0]              dma_p_c;
mcache_pcim_t [N_PCIE-1:0]              dma_p_dab;







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

logic [8-1:0] w_i;
logic [1-1:0] cnt_rst;
logic [1-1:0] cnt_snp;
logic [32-1:0][32-1:0] cnt = 0;
logic [32-1:0][32-1:0] cnt_s;

assign avmm_waitrequest = '0;

always_ff@(posedge clk) begin

    timestamp                           <= timestamp + 1;

    avmm_readdatavalid                  <= avmm_read;

    case (avmm_address[2+:8])
        8'h00: avmm_readdata            <= 32'h5000_0000;
        8'h01: avmm_readdata            <= 32'h0002_0006;

        8'h10: avmm_readdata            <= w_i;
        8'h11: avmm_readdata            <= timestamp[0 +:32];
        8'h12: avmm_readdata            <= timestamp[32+:32];

        8'h20: avmm_readdata            <= cnt_s[w_i];
        8'h21: avmm_readdata            <= {tr_pending[0+:10], res_o_c[0][0+:10], pcie_il[0][0+:12]};
        8'h22: avmm_readdata            <= {tr_pending[0+:10], res_o_c[1][0+:10], pcie_il[1][0+:12]};
    endcase

    if (avmm_write) begin
    case (avmm_address[2+:8])

        8'h10: w_i                      <= avmm_writedata;
        8'h11: send_fails               <= avmm_writedata;
        8'h13: ths_msb                  <= avmm_writedata;
        8'h14: ths[w_i]                 <= {ths_msb, avmm_writedata};

        8'h20: begin
            cnt_snp                     <= avmm_writedata[1];
            cnt_rst                     <= avmm_writedata[0];
        end

    endcase
    end else begin
        cnt_rst                         <= 0;
        cnt_snp                         <= 0;
    end
end

`define CNT(ci, expr)       piped_counter #(.D(2),.W(32)) cntr_``ci`` (.clk(clk), .rst(rst), .c(cnt_s[ci]), .p(expr), .r(cnt_rst), .s(cnt_snp));
`define CNM(ci, expr, c)    always_ff@(posedge clk) begin if (cnt_snp) cnt_s[ci] <= cnt[ci]; cnt[ci] <= (cnt_rst) ? '0 : cnt[ci] + ((expr) ? c : 0); end
`define MON(ci, expr)       always_ff@(posedge clk) begin if (cnt_snp) cnt_s[ci] <= cnt[ci]; cnt[ci] <= (expr); end

`CNT( 0, pad_i_v & pad_i_r & pad_i_e)
`CNT( 1, pad_o_v & pad_o_e)
`CNT( 2, sha_o_v)
`CNT( 3, sv0_o_v)
`CNT( 4, sv2_f_v) // sv1_o_v is in clk_f domain
`CNT( 5, sv2_o_v)
`CNT( 6, ecc_o_v)

`MON( 7, tr_pending)

`CNT(10, pcie_iv[0])                    // input count
`MON(11, pcie_il[0])                    // input fill
`CNT(12, pcie_iv[0] & pcie_if[0])       // input drops
`CNT(13, res_o_v[0])                    // result count
`MON(14, res_o_c[0])                    // result fill
`CNT(15, res_o_v[0] & res_o_f[0])       // result drops
`CNT(16, res_o_p[0])                    // result dma count

`CNT(20, pcie_iv[1])                    // input count
`MON(21, pcie_il[1])                    // input fill
`CNT(22, pcie_iv[1] & pcie_if[1])       // input drops
`CNT(23, res_o_v[1])                    // result count
`MON(24, res_o_c[1])                    // result fill
`CNT(25, res_o_v[1] & res_o_f[1])       // result drops
`CNT(26, res_o_p[1])                    // result dma count

`undef CNT
`undef CNM
`undef MON

piped_pending #(
    .W(32),
    .D(2)
) tr_pending_pending (
    .u(pad_i_v & pad_i_r & pad_i_e),
    .d(ecc_o_v),
    .p(tr_pending),
    .clk(clk),
    .rst(rst)
);


(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                              ($bits({rst_r})),
    .DEPTH                                              (2)
) rst_pipe_inst (
    .in                                                 ({10{rst}}),
    .out                                                (rst_r),

    .clk                                                (clk),
    .reset                                              (rst)
);

(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                              ($bits({rst_f_r})),
    .DEPTH                                              (2)
) rst_f_pipe_inst (
    .in                                                 ({10{rst_f}}),
    .out                                                (rst_f_r),

    .clk                                                (clk_f),
    .reset                                              (rst_f)
);

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

generate

    for (genvar g_i = 0; g_i < N_PCIE; g_i ++) begin: P_IN

        localparam logic [64-1:0] PCIE_OFF = {32'h0000_0001 + g_i, 32'h0000_0000};

        pcie_inorder #(
            .W                          (512),
            .D                          (512),
            .REG_O                      (1), // assumes no backpressure
            .ADDR_MASK                  (64'hFFFF_FFFF_0000_0000),
            .ADDR_VAL                   (PCIE_OFF)
        ) pcie_inorder_inst (
            .pcie_v                     (pcie_v),
            .pcie_a                     (pcie_a),
            .pcie_d                     (pcie_d),

            .out_v                      (pcie_iv[g_i]),
            .out_p                      ('1),
            .out_a                      (),
            .out_d                      (pcie_id[g_i]),
            .out_s                      (),

            .clk                        (clk),
            .rst                        (rst_r[0])
        );

        pcie_tr_ext #(
            .BUFF_SZ                    (EXT_BUFFER_SZ)
        ) tr_ext_inst (
            .pcie_v                     (pcie_iv        [g_i]),
            .pcie_d                     (pcie_id        [g_i]),
            .pcie_f                     (pcie_if        [g_i]), // full
            .pcie_l                     (pcie_il        [g_i]), // fill

            .o_v                        (ext_v          [g_i]),
            .o_r                        (ext_r          [g_i]),
            .o_e                        (ext_e          [g_i]),
            .o_m0                       (ext_m0         [g_i]),
            .o_m1                       (ext_m1         [g_i]),

            .clk                        (clk),
            .rst                        (rst_r[1])
        );

        always_ff@(posedge clk) begin
            res_o_v             [g_i]   <= ecc_o_v & (ecc_o_m.m.src[0+:4] == g_i);
            res_o_t             [g_i]   <= ecc_o_m.m.tid;
            res_o_d             [g_i]   <= ecc_o_m.res;
        end

    end
endgenerate

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

dma_result #(
    .N_PCIE                     (N_PCIE)
) dma_result_inst (

    .dma_r                      (dma_r),
    .dma_v                      (dma_v),
    .dma_a                      (dma_a),
    .dma_b                      (dma_b),
    .dma_f                      (dma_f),
    .dma_d                      (dma_d),

    .ext_v                      (ext_v),
    .ext_r                      (ext_r),
    .ext_e                      (ext_e),
    .ext_m                      (ext_m1),

    .res_v                      (res_o_v),
    .res_t                      (res_o_t),
    .res_d                      (res_o_d),
    .res_c                      (res_o_c),
    .res_f                      (res_o_f),
    .res_p                      (res_o_p),

    .send_fails                 (send_fails),

    .priv_base                  (priv_bytes[0+:8]),
    .priv_mask                  (priv_bytes[8+:8]),

    .clk                        (clk),
    .rst                        (rst_r[2])
);

// PPPPPPPPPPPPPPPPP                  AAA               DDDDDDDDDDDDD        
// P::::::::::::::::P                A:::A              D::::::::::::DDD     
// P::::::PPPPPP:::::P              A:::::A             D:::::::::::::::DD   
// PP:::::P     P:::::P            A:::::::A            DDD:::::DDDDD:::::D  
//   P::::P     P:::::P           A:::::::::A             D:::::D    D:::::D 
//   P::::P     P:::::P          A:::::A:::::A            D:::::D     D:::::D
//   P::::PPPPPP:::::P          A:::::A A:::::A           D:::::D     D:::::D
//   P:::::::::::::PP          A:::::A   A:::::A          D:::::D     D:::::D
//   P::::PPPPPPPPP           A:::::A     A:::::A         D:::::D     D:::::D
//   P::::P                  A:::::AAAAAAAAA:::::A        D:::::D     D:::::D
//   P::::P                 A:::::::::::::::::::::A       D:::::D     D:::::D
//   P::::P                A:::::AAAAAAAAAAAAA:::::A      D:::::D    D:::::D 
// PP::::::PP             A:::::A             A:::::A   DDD:::::DDDDD:::::D  
// P::::::::P            A:::::A               A:::::A  D:::::::::::::::DD   
// P::::::::P           A:::::A                 A:::::A D::::::::::::DDD     
// PPPPPPPPPP          AAAAAAA                   AAAAAAADDDDDDDDDDDDD        

rrb_merge #(
    .W                                          ($bits(ext_m0[0])),
    .N                                          (N_PCIE)
) ext_merge_inst (
    .i_r                                        (ext_r),
    .i_v                                        (ext_v),
    .i_e                                        (ext_e),
    .i_m                                        (ext_m0),

    .o_r                                        (pad_i_r),
    .o_v                                        (pad_i_v),
    .o_e                                        (pad_i_e),
    .o_m                                        (pad_i_m),

    .clk                                        (clk),
    .rst                                        (rst)
);

sha512_pre #(
) sha512_pre_inst (

    .i_r                                        (pad_i_r),
    .i_w                                        (pad_i_w),
    .i_v                                        (pad_i_v),
    .i_e                                        (pad_i_e),
    .i_m                                        (pad_i_m),

    .o_v                                        (pad_o_v),
    .o_e                                        (pad_o_e),
    .o_m                                        (pad_o_m),

    .clk                                        (clk),
    .rst                                        (rst_r[4])
);

(* keep_hierarchy = "yes" *) throttle pad_th_inst (
    .i                                          (pad_i_r & pad_i_v & pad_i_e),
    .o                                          (pad_o_v & pad_o_e),
    .f                                          (pad_o_f),
    .w                                          (pad_i_w),
    .ths                                        ({ths[0]}),
    .clk                                        (clk),
    .rst                                        (rst)
);

//    SSSSSSSSSSSSSSS HHHHHHHHH     HHHHHHHHH               AAA               
//  SS:::::::::::::::SH:::::::H     H:::::::H              A:::A              
// S:::::SSSSSS::::::SH:::::::H     H:::::::H             A:::::A             
// S:::::S     SSSSSSSHH::::::H     H::::::HH            A:::::::A            
// S:::::S              H:::::H     H:::::H             A:::::::::A           
// S:::::S              H:::::H     H:::::H            A:::::A:::::A          
//  S::::SSSS           H::::::HHHHH::::::H           A:::::A A:::::A         
//   SS::::::SSSSS      H:::::::::::::::::H          A:::::A   A:::::A        
//     SSS::::::::SS    H:::::::::::::::::H         A:::::A     A:::::A       
//        SSSSSS::::S   H::::::HHHHH::::::H        A:::::AAAAAAAAA:::::A      
//             S:::::S  H:::::H     H:::::H       A:::::::::::::::::::::A     
//             S:::::S  H:::::H     H:::::H      A:::::AAAAAAAAAAAAA:::::A    
// SSSSSSS     S:::::SHH::::::H     H::::::HH   A:::::A             A:::::A   
// S::::::SSSSSS:::::SH:::::::H     H:::::::H  A:::::A               A:::::A  
// S:::::::::::::::SS H:::::::H     H:::::::H A:::::A                 A:::::A 
//  SSSSSSSSSSSSSSS   HHHHHHHHH     HHHHHHHHHAAAAAAA                   AAAAAAA

(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                      ($bits({sha_f_f, pad_o_m, pad_o_e, pad_o_v})),
    .DEPTH                                      (2)
) sha_i_pipe_inst (
    .in                                         ({sha_f_f, pad_o_m, pad_o_e, pad_o_v}),
    .out                                        ({pad_o_f, sha_f_m, sha_f_e, sha_f_v}),

    .clk                                        (clk),
    .reset                                      (rst)
);

(* keep_hierarchy = "yes" *) showahead_pkt_fifo #(
    .WIDTH                                      ($bits({sha_f_m})),
    .DEPTH                                      (512)
) sha_f_inst (
    .aclr                                       (rst),

    .wr_clk                                     (clk),
    .wr_req                                     (sha_f_v),
    .wr_full                                    (),
    .wr_full_b                                  (),
    .wr_data                                    (sha_f_m),
    .wr_eop                                     (sha_f_e),
    .wr_count                                   (),
    .wr_count_pkt                               (sha_f_f),

    .rd_clk                                     (clk),
    .rd_req                                     (sha_i_v & sha_i_r),
    .rd_empty                                   (),
    .rd_not_empty                               (sha_i_v),
    .rd_count                                   (),
    .rd_data                                    (sha_i_m),
    .rd_eop                                     (sha_i_e)
);

(* keep_hierarchy = "yes" *) sha512_modq_meta #(
    .KEY_D                                      (KEY_D)
) sha512_modq_meta_inst (
    .i_r                                        (sha_i_r),
    .i_w                                        (sha_i_w),
    .i_v                                        (sha_i_v),
    .i_e                                        (sha_i_e),
    .i_m                                        (sha_i_m),

    .o_v                                        (sha_o_v),
    .o_e                                        (),
    .o_m                                        (sha_o_m),

    .clk                                        (clk),
    .rst                                        (rst_r[5])
);

(* keep_hierarchy = "yes" *) throttle #(
) sha_th_inst (
    .i                                          (sha_i_r & sha_i_v & sha_i_e),
    .o                                          (sha_o_v),
    .f                                          (sha_o_f),
    .w                                          (sha_i_w),
    .ths                                        ({ths[1]}),
    .clk                                        (clk),
    .rst                                        (rst)
);

//    SSSSSSSSSSSSSSS VVVVVVVV           VVVVVVVV     000000000     
//  SS:::::::::::::::SV::::::V           V::::::V   00:::::::::00   
// S:::::SSSSSS::::::SV::::::V           V::::::V 00:::::::::::::00 
// S:::::S     SSSSSSSV::::::V           V::::::V0:::::::000:::::::0
// S:::::S             V:::::V           V:::::V 0::::::0   0::::::0
// S:::::S              V:::::V         V:::::V  0:::::0     0:::::0
//  S::::SSSS            V:::::V       V:::::V   0:::::0     0:::::0
//   SS::::::SSSSS        V:::::V     V:::::V    0:::::0 000 0:::::0
//     SSS::::::::SS       V:::::V   V:::::V     0:::::0 000 0:::::0
//        SSSSSS::::S       V:::::V V:::::V      0:::::0     0:::::0
//             S:::::S       V:::::V:::::V       0:::::0     0:::::0
//             S:::::S        V:::::::::V        0::::::0   0::::::0
// SSSSSSS     S:::::S         V:::::::V         0:::::::000:::::::0
// S::::::SSSSSS:::::S          V:::::V           00:::::::::::::00 
// S:::::::::::::::SS            V:::V              00:::::::::00   
//  SSSSSSSSSSSSSSS               VVV                 000000000     

(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                      ($bits({sv0_f_f, sha_o_m, sha_o_v})),
    .DEPTH                                      (2)
) sv_0_i_pipe_inst (
    .in                                         ({sv0_f_f, sha_o_m, sha_o_v}),
    .out                                        ({sha_o_f, sv0_f_m, sv0_f_v}),

    .clk                                        (clk),
    .reset                                      (rst)
);

(* keep_hierarchy = "yes" *) showahead_fifo #(
    .WIDTH                                      ($bits({sv0_f_m})),
    .DEPTH                                      (512)
) sv0_f_inst (
    .aclr                                       (rst),

    .wr_clk                                     (clk),
    .wr_req                                     (sv0_f_v),
    .wr_full                                    (),
    .wr_data                                    (sv0_f_m),
    .wr_count                                   (sv0_f_f),

    .rd_clk                                     (clk),
    .rd_req                                     (sv0_i_v & sv0_i_r),
    .rd_empty                                   (),
    .rd_not_empty                               (sv0_i_v),
    .rd_count                                   (),
    .rd_data                                    (sv0_i_m)
);

(* keep_hierarchy = "yes" *) ed25519_sigverify_0 #(
    .MUL_T                                      (MUL_T),
    .MUL_D                                      (MUL_D),
    .N_SCH                                      (N_SCH),
    .KEY_D                                      (KEY_D)
) ed25519_sigverify_0_inst (
    .i_r                                        (sv0_i_r),
    .i_w                                        (sv0_i_w),
    .i_v                                        (sv0_i_v),
    .i_m                                        (sv0_i_m),

    .o_v                                        (sv0_o_v),
    .o_m                                        (sv0_o_m),

    .clk                                        (clk),
    .rst                                        (rst_r[6])
);

(* keep_hierarchy = "yes" *) throttle #(
) sv0_th_inst (
    .i                                          (sv0_i_r & sv0_i_v),
    .o                                          (sv0_o_v),
    .f                                          (sv0_o_f),
    .w                                          (sv0_i_w),
    .ths                                        ({ths[2]}),
    .clk                                        (clk),
    .rst                                        (rst)
);

//    SSSSSSSSSSSSSSS VVVVVVVV           VVVVVVVV  1111111   
//  SS:::::::::::::::SV::::::V           V::::::V 1::::::1   
// S:::::SSSSSS::::::SV::::::V           V::::::V1:::::::1   
// S:::::S     SSSSSSSV::::::V           V::::::V111:::::1   
// S:::::S             V:::::V           V:::::V    1::::1   
// S:::::S              V:::::V         V:::::V     1::::1   
//  S::::SSSS            V:::::V       V:::::V      1::::1   
//   SS::::::SSSSS        V:::::V     V:::::V       1::::l   
//     SSS::::::::SS       V:::::V   V:::::V        1::::l   
//        SSSSSS::::S       V:::::V V:::::V         1::::l   
//             S:::::S       V:::::V:::::V          1::::l   
//             S:::::S        V:::::::::V           1::::l   
// SSSSSSS     S:::::S         V:::::::V         111::::::111
// S::::::SSSSSS:::::S          V:::::V          1::::::::::1
// S:::::::::::::::SS            V:::V           1::::::::::1
//  SSSSSSSSSSSSSSS               VVV            111111111111

(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                      ($bits({sv1_f_f, sv0_o_m, sv0_o_v})),
    .DEPTH                                      (2)
) sv1_i_pipe_inst (
    .in                                         ({sv1_f_f, sv0_o_m, sv0_o_v}),
    .out                                        ({sv0_o_f, sv1_f_m, sv1_f_v}),

    .clk                                        (clk),
    .reset                                      (rst)
);

(* keep_hierarchy = "yes" *) dual_clock_showahead_fifo #(
    .WIDTH                                      ($bits({sv1_f_m})),
    .DEPTH                                      (512)
) sv1_f_inst (
    .aclr                                       (rst),

    .wr_clk                                     (clk),
    .wr_req                                     (sv1_f_v),
    .wr_full                                    (),
    .wr_data                                    (sv1_f_m),
    .wr_count                                   (sv1_f_f),

    .rd_clk                                     (clk_f),
    .rd_req                                     (sv1_i_v & sv1_i_r),
    .rd_empty                                   (),
    .rd_not_empty                               (sv1_i_v),
    .rd_count                                   (),
    .rd_data                                    (sv1_i_m)
);

(* keep_hierarchy = "yes" *) ed25519_sigverify_1 #(
    .DSDP_WS                                    (DSDP_WS),
    .MUL_T                                      (MUL_T),
    .MUL_D                                      (MUL_D),
    .KEY_D                                      (KEY_D)
) ed25519_sigverify_1_inst (
    .i_r                                        (sv1_i_r),
    .i_w                                        (sv1_i_w),
    .i_v                                        (sv1_i_v),
    .i_m                                        (sv1_i_m),

    .o_v                                        (sv1_o_v),
    .o_m                                        (sv1_o_m),

    .clk                                        (clk_f),
    .rst                                        (rst_f_r[0])
);

(* keep_hierarchy = "yes" *) throttle #(
) sv1_th_inst (
    .i                                          (sv1_i_r & sv1_i_v),
    .o                                          (sv1_o_v),
    .f                                          (sv1_o_f),
    .w                                          (sv1_i_w),
    .ths                                        ({ths[3]}),
    .clk                                        (clk_f),
    .rst                                        (rst_f_r[1])
);

//    SSSSSSSSSSSSSSS VVVVVVVV           VVVVVVVV 222222222222222    
//  SS:::::::::::::::SV::::::V           V::::::V2:::::::::::::::22  
// S:::::SSSSSS::::::SV::::::V           V::::::V2::::::222222:::::2 
// S:::::S     SSSSSSSV::::::V           V::::::V2222222     2:::::2 
// S:::::S             V:::::V           V:::::V             2:::::2 
// S:::::S              V:::::V         V:::::V              2:::::2 
//  S::::SSSS            V:::::V       V:::::V            2222::::2  
//   SS::::::SSSSS        V:::::V     V:::::V        22222::::::22   
//     SSS::::::::SS       V:::::V   V:::::V       22::::::::222     
//        SSSSSS::::S       V:::::V V:::::V       2:::::22222        
//             S:::::S       V:::::V:::::V       2:::::2             
//             S:::::S        V:::::::::V        2:::::2             
// SSSSSSS     S:::::S         V:::::::V         2:::::2       222222
// S::::::SSSSSS:::::S          V:::::V          2::::::2222222:::::2
// S:::::::::::::::SS            V:::V           2::::::::::::::::::2
//  SSSSSSSSSSSSSSS               VVV            22222222222222222222

(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                      ($bits({sv2_f_f, sv1_o_m, sv1_o_v})),
    .DEPTH                                      (2)
) sv2_i_pipe_inst (
    .in                                         ({sv2_f_f, sv1_o_m, sv1_o_v}),
    .out                                        ({sv1_o_f, sv2_f_m, sv2_f_v}),

    .clk                                        (clk_f),
    .reset                                      (rst_f_r[2])
);

(* keep_hierarchy = "yes" *) dual_clock_showahead_fifo #(
    .WIDTH                                      ($bits({sv2_f_m})),
    .DEPTH                                      (512)
) sv2_f_inst (
    .aclr                                       (rst_f_r[3]),

    .wr_clk                                     (clk_f),
    .wr_req                                     (sv2_f_v),
    .wr_full                                    (),
    .wr_data                                    (sv2_f_m),
    .wr_count                                   (sv2_f_f),

    .rd_clk                                     (clk),
    .rd_req                                     (sv2_i_v & sv2_i_r),
    .rd_empty                                   (),
    .rd_not_empty                               (sv2_i_v),
    .rd_count                                   (),
    .rd_data                                    (sv2_i_m)
);

(* keep_hierarchy = "yes" *) ed25519_sigverify_2 #(
    .MUL_T                                      (MUL_T)
) ed25519_sigverify_2_inst (
    .i_r                                        (sv2_i_r),
    .i_w                                        ('0),
    .i_v                                        (sv2_i_v),
    .i_m                                        (sv2_i_m),

    .o_v                                        (sv2_o_v),
    .o_m                                        (sv2_o_m),

    .clk                                        (clk),
    .rst                                        (rst_r[8])
);

(* dont_touch = "yes" *) piped_wire #(
    .WIDTH                                      ($bits({sv2_o_m, sv2_o_v})),
    .DEPTH                                      (4)
) ecc_o_pipe_inst (
    .in                                         ({sv2_o_m, sv2_o_v}),
    .out                                        ({ecc_o_m, ecc_o_v}),

    .clk                                        (clk),
    .reset                                      (rst)
);
































































































always_ff@(posedge clk) dbg_wire[DBG_WIDTH-1:2] <= {

    ecc_o_m.m.tid,
    ecc_o_v,

    sv2_o_m.m.tid,
    sv2_o_v,

    sv2_i_m.m.tid,
    sv2_i_v,

    sv0_o_m.m.m.m.tid,
    sv0_o_v,

    sha_o_m.m.m.tid,
    sha_o_v,

    pad_o_m.m.m.tid,
    pad_o_v,

    |{
        ecc_o_v,
        sv2_o_v,
        sv2_i_v,
        sv0_o_v,
        sha_o_v,
        pad_o_v
    }
};

assign dbg_wire[0+:2] = {
    rst,
    clk
};

always_ff@(posedge clk)   if (pad_i_v & pad_i_r & pad_i_e)    $display("%t: pad_i  :", $time);
always_ff@(posedge clk)   if (sha_i_v & sha_i_r & sha_i_e)    $display("%t: sha_i  : %x", $time, sha_i_m.m.m.tid);
always_ff@(posedge clk)   if (sv0_i_v & sv0_i_r)              $display("%t: sv0_i  :", $time);
always_ff@(posedge clk_f) if (sv1_i_v & sv1_i_r)              $display("%t: sv1_i  :", $time);
always_ff@(posedge clk)   if (sv2_i_v & sv2_i_r)              $display("%t: sv2_i  :", $time);

// always_ff@(posedge clk)   if (pad_i_w)            $display("%t: pad_i_w: %0d %0d %0d - %0d - %0d", $time, ths[0][0+:12], ths[0][12+:12], ths[0][24+:12], pad_o_f, pad_th_inst.cnt);
// always_ff@(posedge clk)   if (sha_i_w)            $display("%t: sha_i_w: %0d %0d %0d - %0d - %0d", $time, ths[1][0+:12], ths[1][12+:12], ths[1][24+:12], sha_o_f, sha_th_inst.cnt);
// always_ff@(posedge clk)   if (sv0_i_w)            $display("%t: sv0_i_w: %0d %0d %0d - %0d - %0d", $time, ths[2][0+:12], ths[2][12+:12], ths[2][24+:12], sv0_o_f, sv0_th_inst.cnt);
// always_ff@(posedge clk_f) if (sv1_i_w)            $display("%t: sv1_i_w: %0d %0d %0d - %0d - %0d", $time, ths[3][0+:12], ths[3][12+:12], ths[3][24+:12], sv1_o_f, sv1_th_inst.cnt);

always_ff@(posedge clk)   if (pad_o_v & pad_o_e)  $display("%t: o_pad_o: %x", $time, pad_o_m.m.m.tid);
always_ff@(posedge clk)   if (sha_o_v)            $display("%t: o_sha_o: %x", $time, sha_o_m.m.m.tid);
always_ff@(posedge clk)   if (sv0_o_v)            $display("%t: o_sv0_o: %x", $time, sv0_o_m.m.m.m.tid);
always_ff@(posedge clk_f) if (sv1_o_v)            $display("%t: o_sv1_o: %x", $time, sv1_o_m.m.tid);
always_ff@(posedge clk)   if (sv2_o_v)            $display("%t: o_sv2_o: %x", $time, sv2_o_m.m.tid);
always_ff@(posedge clk)   if (ecc_o_v)            $display("%t: o_ecc_o: %x", $time, ecc_o_m.m.tid);
always_ff@(posedge clk)   if (res_o_v[0])         $display("%t: o_re[0]: %x", $time, res_o_d[0]);

always_ff@(negedge clk) $display("%t: -----------",$time);


endmodule


`default_nettype wire
