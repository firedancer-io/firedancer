enum fd_block_encoding { FD_BLOCK_ENC_BASE58, FD_BLOCK_ENC_BASE64, FD_BLOCK_ENC_JSON, FD_BLOCK_ENC_JSON_PARSED };

enum fd_block_detail { FD_BLOCK_DETAIL_FULL, FD_BLOCK_DETAIL_ACCTS, FD_BLOCK_DETAIL_SIGS, FD_BLOCK_DETAIL_NONE };

int fd_txn_to_json( fd_textstream_t * ts,
                    fd_txn_t* txn,
                    const uchar* raw,
                    const void * meta_raw,
                    ulong meta_raw_sz,
                    enum fd_block_encoding encoding,
                    long maxvers,
                    enum fd_block_detail detail,
                    int rewards );

int fd_block_to_json( fd_textstream_t * ts,
                      long call_id,
                      const void* block,
                      ulong block_sz,
                      const void* stat_block,
                      ulong stat_block_sz,
                      enum fd_block_encoding encoding,
                      long maxvers,
                      enum fd_block_detail detail,
                      int rewards);
