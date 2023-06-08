
/*

                       --+   +-----------+   +------+   +--
                      /  +---> Processor +---+ FIFO +--->  \
                     |   |   +-----------+   +------+   |   |
                     |   |                              |   |
     +-------+       |   |   +-----------+   +------+   |   |         +--------+
-----> FIFO  +---+--->   +---> Processor +---+ FIFO +--->   +---+----->  FIFO  +-------+--->
     +-------+   |   |   |   +-----------+   +------+   |   |   |     +--------+       |
                 |   |   |                              |   |   |                      |
                 |   |   |   +-----------+   +------+   |   |   |   +--------------+   |
                 |    \  +---> Processor +---+ FIFO +--->  /    +--->  Reassemble  +---+
                 |     --+   +-----------+   +------+   +--         +--------------+   |
                 |                                                                     |
                 |                                                                     |
                 |                             +------+                                | 
                 +-----------------------------> Meta +--------------------------------+
                                               +------+            

    Dispatch and merge of sigverify-split-0 jobs to processors.

    Dispatch serializes the three inputs of each invokation
    into the same processor.  Job distribution logic is a 
    simple round-robin policy.  Pointer moves when a job
    is completely taken by a processor.

    Merge is a simple multiplexer with a round robin pocliy for 
    selection.  As multipler processors can produce results at
    the same time, each requires a separate fifo to accept
    backrepssure from the multiplexer.

    Each transaction has multiple (eight) results.  As the
    results of a transaction will be produced in the span tens of
    cycles, reassembly is required to provide all results of a single
    transaction to the output in a single cycle.  The final result
    is stored in a fifo to support backpressure.

    Metadata is stored in a key-storage to avoid sending
    wide metadata into the processors.

*/

`default_nettype none

import wd_sigverify::*;

module ed25519_sigverify_0 #(
    MUL_T                                               = 32'h007F_CCC2,
    MUL_D                                               = 15,
    N_SCH                                               = 2,
    KEY_D                                               = 512,
    KEY_D_L                                             = $clog2(KEY_D)
) (
    output logic [1-1:0]                                i_r, // backpressure
    input wire [1-1:0]                                  i_w, // wait
    input wire [1-1:0]                                  i_v,
    input wire [$bits(sv_meta4_t)-1:0]                  i_m,

    output logic [1-1:0]                                o_v,
    output logic [$bits(sv_meta5_t)-1:0]                o_m,

    input wire clk,
    input wire rst
);

logic [KEY_D_L-1:0]                                     i_k;
sv_meta4_t                                              i_mm;
sv_meta5_t                                              o_mm;

logic [1-1:0]                                           key_i_r;
logic [1-1:0]                                           key_i_v;

logic [$clog2(N_SCH):0]                                 sch_i_rrb;                      // round robin index
logic [N_SCH-1:0]                                       sch_i_r;                        // individual ready signals from schedulers

logic [1-1:0]                                           sch_o_r         [N_SCH-1:0];
logic [1-1:0]                                           sch_o_v         [N_SCH-1:0];
logic [6-1:0]                                           sch_o_a         [N_SCH-1:0];
logic [KEY_D_L-1:0]                                     sch_o_k         [N_SCH-1:0];
logic [256-1:0]                                         sch_o_d         [N_SCH-1:0];
logic [$clog2(N_SCH):0]                                 sch_o_rrb;

logic [1-1:0]                                           sch_m_v;
logic [6-1:0]                                           sch_m_a;
logic [KEY_D_L-1:0]                                     sch_m_k;
logic [256-1:0]                                         sch_m_d;

logic [1-1:0]                                           sch_a_v;

assign i_r                                              = |sch_i_r;
assign i_mm                                             = i_m;
assign o_m                                              = o_mm;

assign key_i_v                                          = |sch_i_r;

key_store #(
    .D                                                  (KEY_D),
    .W                                                  ($bits({i_mm}))
) keystore_inst (
    .i_r                                                (key_i_r),
    .i_v                                                (key_i_v),
    .i_k                                                (i_k),
    .i_d                                                ({i_mm}),

    .o_r                                                (sch_m_v & (sch_m_a == (N_SCH_O-1))),
    .o_k                                                (sch_m_k),
    .o_d                                                ({o_mm.m}),

    .clk                                                (clk),
    .rst                                                (rst)
);

always_ff@(posedge clk) begin
    if (i_r)
        sch_i_rrb                                       <= (sch_i_rrb == N_SCH-1) ? 0 : sch_i_rrb + 1;
    if (rst)
        sch_i_rrb                                       <= 0;
end

generate;
    for (genvar g_i = 0; g_i < N_SCH; g_i ++) begin: G_SCH

        logic [1-1:0]                               rst_r;

        logic [3-1:0]                               sch_ii_st;
        logic [1-1:0]                               sch_ii_r;
        logic [1-1:0]                               sch_ii_v;
        logic [KEY_D_L-1:0]                         sch_ii_k;
        logic [256-1:0]                             sch_ii_d;

        logic [1-1:0]                               sch_oo_v;
        logic [KEY_D_L-1:0]                         sch_oo_k;
        logic [6-1:0]                               sch_oo_a;
        logic [256-1:0]                             sch_oo_d;

        // serialize scheduler inputs
        always_ff@(posedge clk) begin
            case (sch_ii_st)
                0: begin
                    if (i_v & (~i_w) & key_i_r & (sch_i_rrb == g_i)) begin
                        sch_ii_v                    <= 1;
                        sch_ii_k                    <= i_k;
                        sch_ii_d                    <= i_mm.m.pub;
                        sch_ii_st                   <= 1;
                    end
                end
                1: begin
                    if (sch_ii_r) begin
                        sch_ii_d                    <= i_mm.m.sig_l;
                        sch_ii_st                   <= 2;
                    end
                end
                2: begin
                    if (sch_ii_r) begin
                        sch_i_r[g_i]                <= 1;
                        sch_ii_d                    <= i_mm.m.sig_h;
                        sch_ii_st                   <= 3;
                    end
                end
                3: begin
                    sch_i_r[g_i]                    <= 0;
                    if (sch_ii_r) begin
                        sch_ii_v                    <= 0;
                        sch_ii_st                   <= 0;
                    end
                end
            endcase

            if (rst) begin
                sch_ii_st                           <= 0;
                sch_ii_v                            <= 0;
                sch_i_r[g_i]                        <= 0;
            end
        end

        (* dont_touch = "yes" *) piped_wire #(
            .WIDTH                      ($bits({rst})),
            .DEPTH                      (2)
        ) rst_pipe_inst (
            .in                         ({rst}),
            .out                        ({rst_r}),

            .clk                        (clk),
            .reset                      (rst)
        );

        shcl_cpu #(
            .MUL_T                                  (MUL_T),
            .MUL_D                                  (MUL_D),
            .W_HASH                                 (256),
            .W_IN_MEM                               (6),
            .W_T                                    ($bits(sch_ii_k))
        ) schl_cpu_inst (
            .in_hash_ready                          (sch_ii_r), 
            .in_hash_valid                          (sch_ii_v),
            .in_hash_ref                            (sch_ii_k),
            .in_hash_data                           (sch_ii_d),

            .out_hash_valid                         (sch_oo_v),
            .out_ref                                (sch_oo_k),
            .out_d_addr                             (sch_oo_a),
            .out_hash_data                          (sch_oo_d),

            .clk                                    (clk),
            .rst                                    (rst_r)
        );

        showahead_fifo #(
            .WIDTH                                  ($bits({sch_oo_d, sch_oo_a, sch_oo_k})),
            .DEPTH                                  (512)
        ) sch_o_fifo_inst (
            .aclr                                   (rst),

            .wr_clk                                 (clk),
            .wr_req                                 (sch_oo_v),
            .wr_full                                (),
            .wr_full_b                              (),
            .wr_count                               (),
            .wr_data                                ({sch_oo_d, sch_oo_a, sch_oo_k}),

            .rd_clk                                 (clk),
            .rd_req                                 (sch_o_v[g_i] & sch_o_r[g_i]),
            .rd_empty                               (),
            .rd_not_empty                           (sch_o_v[g_i]),
            .rd_count                               (),
            .rd_data                                ({sch_o_d[g_i], sch_o_a[g_i], sch_o_k[g_i]})
        );

        assign sch_o_r[g_i]                         = (sch_o_rrb == g_i);

        always_ff@(posedge clk) if (sch_oo_v | sch_ii_v) $display("%t: %m: %x %x %x %x - %x %x %x %x - %x %x", $time
            , sch_ii_r
            , sch_ii_v
            , sch_ii_k
            , sch_ii_d[0+:64]

            , sch_oo_v
            , sch_oo_a
            , sch_oo_k
            , sch_oo_d[0+:64]

            , sch_o_v   [g_i]
            , sch_o_k   [g_i]
        );
    end
endgenerate

// merge scheduler outputs
always_ff@(posedge clk) begin
    sch_o_rrb                                       <= (sch_o_rrb == N_SCH-1) ? 0 : sch_o_rrb + 1;
    if (rst)
        sch_o_rrb                                   <= 0;

    sch_m_v                                         <= sch_o_v[sch_o_rrb];
    sch_m_a                                         <= sch_o_a[sch_o_rrb];
    sch_m_k                                         <= sch_o_k[sch_o_rrb];
    sch_m_d                                         <= sch_o_d[sch_o_rrb];
end

// reassemble sch outputs, no need to store the last output
generate
    for (genvar g_i = 0; g_i < N_SCH_O-1; g_i ++) begin: G_O
        simple_dual_port_ram #(
            .WRITE_MODE                 ("read_first"),
            .CLOCKING_MODE              ("common_clock"),
            .ADDRESS_WIDTH              (KEY_D_L),
            .DATA_WIDTH                 (256)
        ) reassemble_ram_inst (
            .wr_clock                   (clk),
            .wr_en                      (sch_m_v & (sch_m_a == g_i)),
            .wr_byteenable              ('1),
            .wr_address                 (sch_m_k),
            .data                       (sch_m_d),

            .rd_clock                   (clk),
            .rd_address                 (sch_m_k),
            .q                          (o_mm.os[g_i]),
            .rd_en                      (1'b1)
        );
    end
endgenerate

always_ff@(posedge clk) begin
    o_v                                             <= sch_m_v & (sch_m_a == (N_SCH_O-1));
    o_mm.os[N_SCH_O-1]                              <= sch_m_d;
    if (rst)
        o_v                                         <= 0;
end

always_ff@(posedge clk) if ((i_v & i_r) | sch_m_v | o_v)
$display("%t: %m: %x %x %x %x - %x %x %x %x - %x %x", $time
    , i_v
    , i_w
    , sch_i_rrb
    , sch_i_r

    , sch_m_v
    , sch_m_a
    , sch_m_k
    , sch_m_d

    , o_v
    , o_m
);

endmodule

`default_nettype wire
