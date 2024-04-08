`default_nettype none

module schl_cpu_instr_rom #(
  ROM_WIDTH       ,
  ROM_DEPTH = 4096,
  W_ROM_DEPTH = $clog2(ROM_DEPTH)
)
(
  input wire  clk,
  input wire  rst,

  input wire   [W_ROM_DEPTH-1:0]  a_addr,
  input wire   [1-1:0]            a_en,
  output logic [ROM_WIDTH-1:0]    a_data,

  input wire   [W_ROM_DEPTH-1:0]  b_addr,
  input wire   [1-1:0]            b_en,
  output logic [ROM_WIDTH-1:0]    b_data
);

reg [ROM_WIDTH-1:0] IR [0:ROM_DEPTH-1];
initial begin
  $readmemb(`PATH_TO_INSTR_ROM_MIF, IR, 0, ROM_DEPTH-1);
end
always_ff@(posedge clk)begin
  if(a_en==1'b1) begin
    a_data<=IR[a_addr];
  end
  if(b_en==1'b1) begin
    b_data<=IR[b_addr];
  end
end

endmodule

`default_nettype wire
