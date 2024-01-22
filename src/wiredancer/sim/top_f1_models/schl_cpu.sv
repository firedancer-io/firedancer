`default_nettype none

module shcl_cpu
#(
  MUL_T    = 32'h007F_CCC2,
  MUL_D    = 15,
  W_HASH   = 256,
  W_IN_MEM = 6,
  W_T      = 16,
  MAX_INFLIGHT = (MUL_D+1)+6
)
(
  input var logic clk,
  input var logic rst,

  input var logic [W_HASH-1:0] in_hash_data,
  input var logic              in_hash_valid,
  input var logic [W_T-1:0]    in_hash_ref,
  output    logic              in_hash_ready, 

  output    logic [W_HASH-1:0]   out_hash_data,
  output    logic [W_T-1:0]      out_ref,
  output    logic [W_IN_MEM-1:0] out_d_addr,
  output    logic                out_hash_valid
);


endmodule

`default_nettype wire
