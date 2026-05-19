#ifndef HEADER_fd_src_disco_gui_fd_gui_tile_h
#define HEADER_fd_src_disco_gui_fd_gui_tile_h

/* fd_gui_txn_ns_dt contains nanosecond duration for an executed solana
   transaction relative to the publish event by pack for its
   corresponding microblock.

   In Firedancer, these states align with the struct declaration order,
   but in Frankendancer the "check" phase happens before "load". */
struct __attribute__((packed)) fd_gui_txn_ns_dt {
  float load_start;
  float check_start;
  float exec_start;
  float commit_start;
  float end;
};

typedef struct fd_gui_txn_ns_dt fd_gui_txn_ns_dt_t;

#endif /* HEADER_fd_src_disco_gui_fd_gui_tile_h */
