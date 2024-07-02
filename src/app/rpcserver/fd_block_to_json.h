typedef enum {
  FD_ENC_BASE58, FD_ENC_BASE64, FD_ENC_BASE64_ZSTD, FD_ENC_JSON, FD_ENC_JSON_PARSED
} fd_rpc_encoding_t;

enum fd_block_detail { FD_BLOCK_DETAIL_FULL, FD_BLOCK_DETAIL_ACCTS, FD_BLOCK_DETAIL_SIGS, FD_BLOCK_DETAIL_NONE };

int fd_txn_meta_to_json( fd_textstream_t * ts,
                         const void * meta_raw,
                         ulong meta_raw_sz );

const char* fd_txn_to_json( fd_textstream_t * ts,
                            fd_txn_t* txn,
                            const uchar* raw,
                            ulong raw_sz,
                            fd_rpc_encoding_t encoding,
                            long maxvers,
                            enum fd_block_detail detail,
                            int rewards );

const char* fd_block_to_json( fd_textstream_t * ts,
                              long call_id,
                              fd_block_t * blk,
                              const uchar * blk_data,
                              ulong blk_sz,
                              fd_hash_t * blk_hash,
                              ulong parent,
                              fd_rpc_encoding_t encoding,
                              long maxvers,
                              enum fd_block_detail detail,
                              int rewards);

#define FD_LONG_UNSET (1L << 63L)

const char* fd_account_to_json( fd_textstream_t * ts,
                                fd_pubkey_t acct,
                                fd_rpc_encoding_t enc,
                                uchar const * val,
                                ulong val_sz,
                                long off,
                                long len );
