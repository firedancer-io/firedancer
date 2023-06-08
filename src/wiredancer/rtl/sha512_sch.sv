`default_nettype none

module sha512_sch #(
    W_BLK                   = 64,
    W_M                     = 64,
    BLKS_PER_TR             = 10,
    RAM_D                   = 512,
    N_CYCLES                = 100,
    RAM_E                   = RAM_D / BLKS_PER_TR,
    N_CYCLES_L              = $clog2(N_CYCLES),
    RAM_D_L                 = $clog2(RAM_D)
) (
    output logic [1-1:0]                    oblk_v, // valid
    output logic [W_BLK-1:0]                oblk_d, // data
    output logic [W_M-1:0]                  oblk_t, // transaction id
    output logic [1-1:0]                    oblk_f, // first blk
    output logic [1-1:0]                    oblk_m, // middle blk
    output logic [1-1:0]                    oblk_l, // last blk

    input wire [1-1:0]                      iblk_v, // valid
    input wire [1-1:0]                      iblk_f, // first blk
    input wire [4-1:0]                      iblk_c, // number of blocks
    input wire [W_BLK-1:0]                  iblk_d, // data
    input wire [W_M-1:0]                    iblk_t, // transaction id
    output logic [1-1:0]                    iblk_p, // backpressure is only applied for the first block

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

logic [N_CYCLES_L-1:0]                              c00_c_addr;
logic [N_CYCLES_L-1:0]                              c01_c_addr;
logic [N_CYCLES_L-1:0]                              c02_c_addr;
logic [N_CYCLES_L-1:0]                              c03_c_addr;

logic [RAM_D_L-1:0]                                 c01_a;
logic [4-1:0]                                       c01_c;
logic [W_M-1:0]                                     c01_t;
bit   [4-1:0]                                       c01_r;

logic [1-1:0]                                       c02_v;
logic [1-1:0]                                       c02_n;
logic [RAM_D_L-1:0]                                 c02_a;
logic [4-1:0]                                       c02_c;
logic [4-1:0]                                       c02_r;
logic [1-1:0]                                       c02_f;
logic [1-1:0]                                       c02_m;
logic [1-1:0]                                       c02_l;
logic [W_M-1:0]                                     c02_t;
logic [W_BLK-1:0]                                   c02_d;
logic [1-1:0]                                       c02_free_v;
logic [RAM_D_L-1:0]                                 c02_free_a;
logic [1-1:0]                                       c02_free_pop;

logic [W_M-1:0]                                     c03_t;
logic [RAM_D_L-1:0]                                 c03_a;
logic [4-1:0]                                       c03_c;
logic [4-1:0]                                       c03_r;
logic [1-1:0]                                       c03_f;
logic [1-1:0]                                       c03_m;
logic [1-1:0]                                       c03_l;

logic [1-1:0]                                       c03_free_push_v;
logic [RAM_D_L-1:0]                                 c03_free_push_d;

logic [1-1:0]                                       c03_d_wr_en;
logic [RAM_D_L-1:0]                                 c03_d_wr_addr;
logic [W_BLK-1:0]                                   c03_d_wr_data;

logic [16-1:0]                                      free_init_cnt;

assign oblk_v                                       = c02_v;
assign oblk_d                                       = c02_d;
assign oblk_t                                       = c02_t;
assign oblk_f                                       = c02_f & c02_v;
assign oblk_m                                       = c02_m & c02_v;
assign oblk_l                                       = c02_l & c02_v;

always_comb begin
    iblk_p = 0
        | (iblk_v & ~iblk_f)
        | ((~c02_n) & iblk_v & c02_free_v)
    ;

    c02_free_pop = iblk_v & iblk_p & iblk_f;
end

always_ff@(posedge clk) begin

    c00_c_addr                                      <= c00_c_addr == (N_CYCLES - 1) ? 0 : (c00_c_addr + 1);

    // c00: read cycle-meta
    c01_c_addr                                      <= c00_c_addr;

    // c01: read blk data

    c02_c_addr                                      <= c01_c_addr;

    c02_v                                           <= (c01_r > 0); // valid this round
    c02_n                                           <= (c01_r > 1); // valid next round
    c02_t                                           <= c01_t;
    c02_a                                           <= c01_a;
    c02_c                                           <= c01_c;
    c02_r                                           <= c01_r - 1;
    c02_f                                           <= (c01_r == c01_c);
    c02_m                                           <= (c01_r != c01_c) & (c01_r != 1);
    c02_l                                           <= (c01_r == 1);

    // c02: mux cycle-meta / send out

    c03_c_addr                                      <= c02_c_addr;

    c03_a                                           <= c02_n ? c02_a - 1    : c02_free_a + iblk_c - 1;
    c03_c                                           <= c02_n ? c02_c        : iblk_c;
    c03_r                                           <= c02_n ? c02_r        : (iblk_v & iblk_p & iblk_f) ? iblk_c : 0;
    c03_t                                           <= c02_n ? c02_t        : iblk_t;

    c03_free_push_v                                 <= ((free_init_cnt >= (1*RAM_E)) & (free_init_cnt < (2*RAM_E))) | (c02_v & ~c02_n);
    if (0
        | ((free_init_cnt >= (1*RAM_E)) & (free_init_cnt < (2*RAM_E)))
        | (c02_v & ~c02_n)
    )
        c03_free_push_d                             <= ((free_init_cnt >= (1*RAM_E)) & (free_init_cnt < (2*RAM_E))) ? (c03_free_push_d + BLKS_PER_TR) : c02_a;

    c03_d_wr_en                                     <= iblk_v & iblk_p;
    c03_d_wr_addr                                   <= iblk_v & iblk_p ? (iblk_f ? c02_free_a + iblk_c - 1 : c03_d_wr_addr - 1) : c03_d_wr_addr - 1;
    c03_d_wr_data                                   <= iblk_d;


    // c03: write cycle-meta

    if (free_init_cnt < (2*RAM_E)) begin
        free_init_cnt                               <= free_init_cnt + 1;
    end

    if (rst) begin
        c00_c_addr                                  <= '0;

        c02_v                                       <= '0;
        c02_n                                       <= '0;

        c03_free_push_v                             <= '0;
        c03_free_push_d                             <= '0 - BLKS_PER_TR;

        free_init_cnt                               <= '0;
    end

end


simple_dual_port_ram #(
    // .CLOCKING_MODE                                  ("common_clock"),
    .ADDRESS_WIDTH                                  (N_CYCLES_L),
    .DATA_WIDTH                                     ($bits({c03_t, c03_r, c03_c, c03_a})),
    .REGISTER_OUTPUT                                (0)
) cycle_ram_inst(

    .wr_clock                                       (clk),
    .wr_address                                     (c03_c_addr),
    .wr_en                                          ('1),
    .wr_byteenable                                  ('1),
    .data                                           ({c03_t, c03_r, c03_c, c03_a}),

    .rd_clock                                       (clk),
    .rd_address                                     (c00_c_addr),
    .q                                              ({c01_t, c01_r, c01_c, c01_a}),
    .rd_en                                          (1'b1)
);

simple_dual_port_ram #(
    // .CLOCKING_MODE                                  ("common_clock"),
    .ADDRESS_WIDTH                                  (RAM_D_L),
    .DATA_WIDTH                                     (W_BLK),
    .REGISTER_OUTPUT                                (0)
) blk_ram_inst(

    .wr_clock                                       (clk),
    .wr_address                                     (c03_d_wr_addr),
    .wr_en                                          (c03_d_wr_en),
    .wr_byteenable                                  ('1),
    .data                                           (c03_d_wr_data),

    .rd_clock                                       (clk),
    .rd_address                                     (c01_a),
    .q                                              (c02_d),
    .rd_en                                          (1'b1)
);

showahead_fifo #(
    .WIDTH                              (RAM_D_L),
    .DEPTH                              (RAM_E <= 512 ? 512 : 1024)
) idx_fifo_inst (
    .aclr                               (rst),

    .wr_clk                             (clk),
    .wr_req                             (c03_free_push_v),
    .wr_full                            (),
    .wr_data                            (c03_free_push_d),

    .rd_clk                             (clk),
    .rd_req                             (c02_free_pop),
    .rd_empty                           (),
    .rd_not_empty                       (c02_free_v),
    .rd_count                           (),
    .rd_data                            (c02_free_a)
);

// always_ff@(posedge clk)
// if (iblk_v)
// $display("%t: %m.iblk: %x - %x %x - %x %x",$time()
//     , iblk_p
//     , iblk_f
//     , iblk_c
//     , iblk_t
//     , iblk_d
// );

// always_ff@(posedge clk)
// if (oblk_v)
// $display("%t: %m.oblk: %x %x %x - %x %x",$time()
//     , oblk_f
//     , oblk_m
//     , oblk_l
//     , oblk_t
//     , oblk_d
// );

// always_ff@(posedge clk)
// if (c02_free_v | c02_free_pop | c03_free_push_v)
// $display("%t: %m.free: %x - %x %x %x - %x %x",$time()
//     , idx_fifo_inst.xpm_fifo_sync_inst.wr_rst_busy
//     , c02_free_pop
//     , c02_free_v
//     , c02_free_a

//     , c03_free_push_v
//     , c03_free_push_d
// );

// always_ff@(posedge clk)
// // if ()
// $display("%t: %m.c01: %x %x %x %x",$time()
//     , c01_a
//     , c01_c
//     , c01_t
//     , c01_r
// );

// always_ff@(negedge clk)
// $display("%t: -----------",$time());

endmodule



`default_nettype wire


