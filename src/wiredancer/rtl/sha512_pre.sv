`default_nettype none

import wd_sigverify::*;

module sha512_pre #(
    parameter integer W_BLK = 1024,
    parameter integer W_D   = 512,
    BUFF_SZ                 = 512
) (

    output logic [1-1:0]                    i_r,
    input wire [1-1:0]                      i_w,
    input wire [1-1:0]                      i_v,
    input wire [1-1:0]                      i_e,
    input wire [$bits(sv_meta2_t)-1:0]      i_m,

    output logic [1-1:0]                    o_v,
    output logic [1-1:0]                    o_e,
    output logic [$bits(sv_meta3_t)-1:0]    o_m,

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

function logic [4-1:0] n_blks(logic [11-1:0] sz);
    logic [11-1:0] sz2;
    sz2 = sz + 1 + (128/8);
    return sz2[7+:4] + |sz2[0+:7];
endfunction

function logic [1024-1:0] l_to_b(logic [1024-1:0] l);
    integer i;
    logic [1024/8-1:0][8-1:0] b;
    for (i = 0; i < 1024/8; i ++)
        b[(1024/8)-i-1] = l[i*8+:8];
    return b;
endfunction

typedef struct packed {
    logic [128-1:0]                 size;
    logic [7-1:0]                   last;
    logic [1-1:0]                   extra;
    logic [1-1:0]                   ready;
    logic [1-1:0]                   o_v;
    logic [1-1:0]                   o_f;
    logic [1-1:0]                   o_l;
    logic [4-1:0]                   o_c;
    sv_meta1_t                      o_m;
    logic [1024/8-1:0][8-1:0]       o_d;
    logic [3-1:0]                   st;
} self_t;

self_t                              self, next;

sv_meta2_t                          i_mm;
sv_meta3_t                          o_mm;

assign i_mm                         = i_m;
assign i_r                          = next.ready;

assign o_v                          = self.o_v;
assign o_e                          = self.o_l;
assign o_m                          = o_mm;
assign o_mm.m                       = self.o_m;
assign o_mm.f                       = self.o_f;
assign o_mm.c                       = self.o_c;
assign o_mm.d                       = l_to_b(self.o_d);

always_comb begin
    integer i;

    next = self;

    case (self.st)
        0: begin
            next.ready              = ~i_w;
            if (1) begin
                next.o_v            = 0;
                next.o_f            = 1;
                next.o_l            = 0;
                next.o_c            = n_blks(i_mm.size);
                next.o_m            = i_mm.m;
                next.o_d[0+:64]     = i_mm.data;
                next.last           = i_mm.size;
                next.size           = i_mm.size;
                next.extra          = i_mm.size[0+:7] > ((1024/8) - 16 - 1);

                if (i_v & ~i_w)
                    next.st         = i_e ? 3 : 2;
            end
        end

        1: begin
            next.ready              = 1;
            if (1) begin
                next.o_v            = 0;
                next.o_f            = 0;
                next.o_d[0+:64]     = i_mm.data;

                if (i_v)
                    next.st         = i_e ? 3 : 2;
            end
        end

        2: begin
            next.ready              = 1;
            next.o_v                = i_v & ((~i_e) | (i_mm.emp == 0));
            if (1) begin
                next.o_d[64+:64]    = i_mm.data;
                if (i_v)
                    next.st         = i_e ? (self.extra ? 4 : 3) : 1;
            end
        end

        3: begin
            next.ready              = 0;
            next.o_v                = 1;
            next.o_f                = (self.o_v) ? 1'b0 : self.o_f;
            if (1) begin
                for (i = 0; i < 128-16; i ++) begin
                    case({
                        i == self.last,
                        i > self.last
                    })
                        2'b10: next.o_d[i] = 8'h80;
                        2'b01: next.o_d[i] = 8'h00;
                    endcase
                end
                next.o_d[128-16+:14]= 112'h0;
                next.o_d[128-2+:1]  = (self.size << 3) >> 8;
                next.o_d[128-1+:1]  = (self.size << 3) >> 0;

                next.o_l            = 1;

                next.st             = 0;
            end
        end
        4: begin
            next.ready              = 0;
            next.o_v                = 1;
            next.o_f                = (self.o_v) ? 1'b0 : self.o_f;
            if (1) begin
                for (i = 0; i < 128; i ++) begin
                    case({
                        i == self.last,
                        i > self.last
                    })
                        2'b10: next.o_d[i] = 8'h80;
                        2'b01: next.o_d[i] = 8'h00;
                    endcase
                end
                next.st             = 5;
            end
        end
        5: begin
            next.ready              = 0;
            next.o_v                = 1;
            next.o_f                = (self.o_v) ? 1'b0 : self.o_f;
            if (1) begin
                for (i = 0; i < 128-16; i ++) begin
                    next.o_d[i] = 8'h00;
                end
                next.o_d[128-16+:14]= 112'h0;
                next.o_d[128-2+:1]  = (self.size << 3) >> 8;
                next.o_d[128-1+:1]  = (self.size << 3) >> 0;

                next.o_l            = 1;

                next.st             = 0;
            end
        end
    endcase
end

always_ff@(posedge clk) begin

    self <= next;
    if (rst) begin
        self <= '0;
    end
end

// always_ff@(posedge clk) $display("%t: %x %x %x %x %x %x %x %x - ", $time
//     , i_r
//     , i_v
//     , i_sop
//     , i_e
//     , i_emp
//     , i_s
//     , i_m
//     , i_d
// );

endmodule



`default_nettype wire
