if set_plugin_info then
    local my_info = {
        version = "0.1",
        author  = "Philip Taffet",
        license = "Apache-2.0",
        details = "Wireshark plugin for Firedancer Tango messages",
    }
    set_plugin_info(my_info)
end

-- Installation instructions:
-- Add this file and the contents of
-- https://github.com/firedancer-io/solana_dissector to the Wireshark Lua
-- dissectors director, e.g. %APPDATA%\Wireshark\plugins on Windows.  In
-- Wireshark, go to Edit -> Preferences -> Protocols -> DLT_USER -> Edit... .
-- Add a row with the +, and set the DLT to User 0 (147) and the Payload
-- dissector to fd_tango.

---------------------------------------
-- Protocols                         --
---------------------------------------

local tango = Proto("fd_tango",    "Tango Frag")

---------------------------------------
-- Data Types                        --
---------------------------------------

local tango_seq = ProtoField.uint64("fd_tango.seq", "Sequence Number", base.DEC)
local tango_sig = ProtoField.uint64("fd_tango.sig", "Sig", base.HEX)
local tango_chunk = ProtoField.uint32("fd_tango.chunk", "Chunk", base.HEX)
local tango_sz = ProtoField.uint16("fd_tango.sz", "Size", base.DEC)
local tango_ctl = ProtoField.uint16("fd_tango.ctl", "Control", base.HEX)
local tango_ctl_som = ProtoField.uint16("fd_tango.ctl.som", "Start-of-message", base.DEC, NULL, 1)
local tango_ctl_eom = ProtoField.uint16("fd_tango.ctl.eom", "End-of-message", base.DEC, NULL, 2)
local tango_ctl_err = ProtoField.uint16("fd_tango.ctl.err", "Err", base.DEC, NULL, 4)
local tango_ctl_orig = ProtoField.uint16("fd_tango.ctl.orig", "Origin", base.DEC, NULL, 0xFFF8)
local tango_tsorig = ProtoField.uint32("fd_tango.tsorig", "Origin Timestamp", base.DEC)
local tango_tspub = ProtoField.uint32("fd_tango.tspub", "Publish Timestamp", base.DEC)
local tango_link = ProtoField.uint32("fd_tango.link", "Link Hash", base.HEX)
local tango_link_name = ProtoField.string("fd_tango.linkname", "Link Name")
local tango_contents = ProtoField.bytes("fd_tango.contents", "DCache Contents")

local tpu_payload_sz = ProtoField.uint16("fd_tpu.payload_sz", "Payload Size")
local tpu_txn = ProtoField.bytes("fd_tpu.txn_t", "Packed Transaction")
local tpu_non_execution_cus = ProtoField.uint32("fd_tpu.non_execution_cus", "Non-execution CUs")
local tpu_requested_cus = ProtoField.uint32("fd_tpu.requested_cus", "Requested CUs")
local tpu_rebated_cus = ProtoField.uint32("fd_tpu.rebated_cus", "Rebated CUs")
local tpu_executed_cus = ProtoField.uint32("fd_tpu.executed_cus", "Executed CUs")
local sched_arrival_ns = ProtoField.int64("fd_tpu.sched_arrival_ns", "Arrival Time (ns)")
local tpu_first_seen_nanos = ProtoField.int64("fd_tpu.first_seen_nanos", "First Seen (ns)")
local tpu_flags = ProtoField.uint32("fd_tpu.flags", "Flags")

local yesno_types = {
    [0] = "No",
    [1] = "Yes"
}
local status_codes = {
  [0] = "Success",
  [1] = "AccountInUse",
  [2] = "AccountLoadedTwice",
  [3] = "AccountNotFound",
  [4] = "ProgramAccountNotFound",
  [5] = "InsufficientFundsForFee",
  [6] = "InvalidAccountForFee",
  [7] = "AlreadyProcessed",
  [8] = "BlockhashNotFound",
  [9] = "InstructionError",
  [10] = "CallChainTooDeep",
  [11] = "MissingSignatureForFee",
  [12] = "InvalidAccountIndex",
  [13] = "SignatureFailure",
  [14] = "InvalidProgramForExecution",
  [15] = "SanitizeFailure",
  [16] = "ClusterMaintenance",
  [17] = "AccountBorrowOutstanding",
  [18] = "WouldExceedMaxBlockCostLimit",
  [19] = "UnsupportedVersion",
  [20] = "InvalidWritableAccount",
  [21] = "WouldExceedMaxAccountCostLimit",
  [22] = "WouldExceedAccountDataBlockLimit",
  [23] = "TooManyAccountLocks",
  [24] = "AddressLookupTableNotFound",
  [25] = "InvalidAddressLookupTableOwner",
  [26] = "InvalidAddressLookupTableData",
  [27] = "InvalidAddressLookupTableIndex",
  [28] = "InvalidRentPayingAccount",
  [29] = "WouldExceedMaxVoteCostLimit",
  [30] = "WouldExceedAccountDataTotalLimit",
  [31] = "DuplicateInstruction",
  [32] = "InsufficientFundsForRent",
  [33] = "MaxLoadedAccountsDataSizeExceeded",
  [34] = "InvalidLoadedAccountsDataSizeLimit",
  [35] = "ResanitizationNeeded",
  [36] = "ProgramExecutionTemporarilyRestricted",
  [37] = "UnbalancedTransaction",
  [38] = "ProgramCacheHitMaxLimit"
}

local tpu_simple_vote = ProtoField.uint32("fd_tpu.flags.simple_vote", "Simple Vote", base.DEC, yesno_types, 0x1)
local tpu_bundle = ProtoField.uint32("fd_tpu.flags.bundle", "Bundle", base.DEC, yesno_types, 0x2)
local tpu_initializer = ProtoField.uint32("fd_tpu.flags.initializer_bundle", "Initializer Bundle", base.DEC, yesno_types, 0x4)
local tpu_sanitized = ProtoField.uint32("fd_tpu.flags.sanitized", "Sanitize Success", base.DEC, yesno_types, 0x8)
local tpu_executed = ProtoField.uint32("fd_tpu.flags.executed", "Execute Success", base.DEC, yesno_types, 0x10)
local tpu_fees_only = ProtoField.uint32("fd_tpu.flags.fees_only", "Fees Only", base.DEC, yesno_types, 0x20)
local tpu_nonce = ProtoField.uint32("fd_tpu.flags.is_nonce", "Durable Nonce", base.DEC, yesno_types, 0x40)
local tpu_status   = ProtoField.uint32("fd_tpu.flags.status", "Status", base.DEC, status_codes, 0xFF000000)

tango.fields = {
  tango_link,
  tango_link_name,
  tango_seq,
  tango_sig,
  tango_chunk,
  tango_sz,
  tango_ctl,
  tango_tsorig,
  tango_tspub,
  tango_ctl_som,
  tango_ctl_eom,
  tango_ctl_err,
  tango_ctl_orig,
  tango_contents,

  tpu_payload_sz,
  tpu_txn,
  tpu_non_execution_cus,
  tpu_requested_cus,
  tpu_rebated_cus,
  tpu_executed_cus,
  sched_arrival_ns,
  tpu_first_seen_nanos,
  tpu_flags,

  tpu_simple_vote,
  tpu_bundle,
  tpu_initializer,
  tpu_sanitized,
  tpu_executed,
  tpu_fees_only,
  tpu_nonce,
  tpu_status
}

local link_hashes = {
  [0x18a945] = "shred_net",
  [0x2aabab] = "quic_verify",
  [0x1efba0] = "verify_dedup",
  [0x59bd91] = "resolv_pack",
  [0xe959ef] = "pack_execle",
  [0x458b11] = "execle_poh",
  [0xdb6a44] = "poh_shred",
  [0x1eb6fd] = "shred_out",
  [0xc650c9] = "shred_sign",
  [0xd408b5] = "sign_shred",
  [0x0d274e] = "quic_net",
  [0xf680c5] = "net_quic",
  [0x6f928b] = "net_shred",
  [0x409d3f] = "dedup_resolv",
  [0x01a062] = "replay_out",
  [0xbfa307] = "replay_epoch",
  [0x8b0b77] = "poh_replay",
  [0x1f1be9] = "txsend_out",
  [0xef3ca0] = "gossip_out",
  [0x02a21a] = "tower_out",
  [0x9e4bf4] = "bundle_verif",
  [0xc7e9e7] = "bundle_sign" ,
  [0x81114e] = "sign_bundle" ,
  [0x2259d5] = "bundle_status",
  [0x06c577] = "pack_sign",
  [0x6a974e] = "sign_pack",
  [0x257632] = "execle_pack",
  [0x534f91] = "pack_poh",
  [0xd5cc48] = "net_repair",
  [0xf005bb] = "repair_net",
  [0x629712] = "repair_out",
  [0xfb0d59] = "net_gossvf",
  [0x287af8] = "net_txsend",
  [0x6a2cc7] = "net_rserve",
  [0xc52ff4] = "net_votor",
  [0x3c9510] = "gossip_net",
  [0xf7b150] = "txsend_net",
  [0x6a67d3] = "rserve_net",
  [0xd607e8] = "votor_net"
}

function tango.dissector (tvb, pinfo, tree)
  local subtree = tree:add(tango, tvb())
  local packet_len = tvb:len()

  if packet_len < 36 then
    return
  end

  local link_hash = tvb(packet_len-4, 4):le_uint()
  local link_name = link_hashes[bit.rshift(link_hash, 8)] or "unknown"
  local sig = tvb(8, 8):le_uint64()

  subtree:add_le(tango_link, tvb(packet_len-4, 4)):append_text( " (" .. link_name .. ")" )
  subtree:add(tango_link_name, tvb(packet_len-4, 4), link_name)

  subtree:add_le(tango_seq, tvb(0, 8))
  subtree:add_le(tango_sig, tvb(8, 8))
  subtree:add_le(tango_chunk, tvb(16, 4))
  subtree:add_le(tango_sz, tvb(20, 2))
  local ctl_node = subtree:add_le(tango_ctl, tvb(22, 2))
  ctl_node:add_le(tango_ctl_som, tvb(22,2))
  ctl_node:add_le(tango_ctl_eom, tvb(22,2))
  ctl_node:add_le(tango_ctl_err, tvb(22,2))
  ctl_node:add_le(tango_ctl_orig, tvb(22,2))

  subtree:add_le(tango_tsorig, tvb(24, 4))
  subtree:add_le(tango_tspub, tvb(28, 4))


  local dcache_contents = tvb:range(32, packet_len-36):tvb()
  local dcache_tree = subtree:add(tango_contents, tvb(32, packet_len-36))
  if dcache_contents:len() == 0 then
    return
  end

  if link_name:match("^net_") or link_name:match("_net$") then
    local dissector = Dissector.get("eth_withoutfcs")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "verify_dedup" or link_name == "dedup_resolv" or link_name == "resolv_pack" or link_name == "bundle_verif" or link_name == "quic_verify" or link_name == "txsend_out" then
    local dissector = Dissector.get("fd_txn_m_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "poh_shred" then
    local dissector = Dissector.get("fd_poh_shred")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "execle_pack" then
    local dissector = Dissector.get("fd_pack_rebate_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "pack_execle" or link_name == "execle_poh" then
    local dissector = Dissector.get("solana.tpu.udp")
    local dissector2 = Dissector.get("fd_txn_t")
    local stride = link_name == "pack_execle" and 7040 or 4992
    local trailer_sz = link_name == "pack_execle" and 56 or 96

    for offset=0,dcache_contents:len()-trailer_sz-stride,stride do
      local txn = dcache_contents(offset, stride):tvb()
      local txn_tree = dcache_tree:add(tpu_txn, txn())
      local payload_sz = txn(4096, 2):le_uint()
      if payload_sz > 4096 then return end
      dissector:call(txn(0, payload_sz):tvb(), pinfo, txn_tree)
      txn_tree:add_le(tpu_payload_sz, txn(4096, 2))
      if link_name == "pack_execle" then
        txn_tree:add_le(tpu_non_execution_cus, txn(4104, 4))
        txn_tree:add_le(tpu_requested_cus, txn(4108, 4))
      else
        txn_tree:add_le(tpu_rebated_cus, txn(4104, 4))
        txn_tree:add_le(tpu_executed_cus, txn(4108, 4))
      end
      txn_tree:add_le(sched_arrival_ns, txn(4112, 8))
      txn_tree:add_le(tpu_first_seen_nanos, txn(4120, 8))
      local flag_tvb = txn(4132,4)
      local flag_node = txn_tree:add_le(tpu_flags, flag_tvb)
      flag_node:add_le(tpu_simple_vote, flag_tvb)
      flag_node:add_le(tpu_bundle,flag_tvb)
      flag_node:add_le(tpu_initializer,flag_tvb)
      flag_node:add_le(tpu_sanitized,  flag_tvb)
      flag_node:add_le(tpu_executed, flag_tvb)
      flag_node:add_le(tpu_fees_only, flag_tvb)
      flag_node:add_le(tpu_nonce, flag_tvb)
      flag_node:add_le(tpu_status, flag_tvb)

      local txn_t_tvb = txn(4136, 854):tvb()
      dissector2:call(txn_t_tvb, pinfo, txn_tree)
    end
  elseif link_name == "replay_out" and sig == UInt64(4) then
    local dissector = Dissector.get("fd_became_leader_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "pack_poh" then
    if sig == UInt64(0xfffffffe, 0xffffffff) then
      dcache_tree:append_text(" (Reduced Microblock Bound)")
    elseif sig ~= UInt64(0xffffffff, 0xffffffff) then
      local dissector = Dissector.get("fd_done_packing_t")
      dissector:call(dcache_contents, pinfo, dcache_tree)
    end
  end
end





local p_fd_txn = Proto("fd_txn_t", "FD Transaction Struct")
local f = p_fd_txn.fields
f.transaction_version = ProtoField.uint8("fd_txn.transaction_version", "Transaction Version", base.DEC)
f.signature_cnt = ProtoField.uint8("fd_txn.signature_cnt", "Signature Count", base.DEC)
f.signature_off = ProtoField.uint16("fd_txn.signature_off", "Signature Offset", base.DEC)
f.message_off = ProtoField.uint16("fd_txn.message_off", "Message Offset", base.DEC)
f.readonly_signed_cnt = ProtoField.uint8("fd_txn.readonly_signed_cnt", "Readonly Signed Count", base.DEC)
f.readonly_unsigned_cnt = ProtoField.uint8("fd_txn.readonly_unsigned_cnt", "Readonly Unsigned Count", base.DEC)
f.acct_addr_cnt = ProtoField.uint16("fd_txn.acct_addr_cnt", "Account Address Count", base.DEC)
f.acct_addr_off = ProtoField.uint16("fd_txn.acct_addr_off", "Account Address Offset", base.DEC)
f.recent_blockhash_off = ProtoField.uint16("fd_txn.recent_blockhash_off", "Recent Blockhash Offset", base.DEC)
f.addr_table_lookup_cnt = ProtoField.uint8("fd_txn.addr_table_lookup_cnt", "Address Table Lookup Count", base.DEC)
f.addr_table_adtl_writable_cnt = ProtoField.uint8("fd_txn.addr_table_adtl_writable_cnt", "Additional Writable Count", base.DEC)
f.addr_table_adtl_cnt = ProtoField.uint8("fd_txn.addr_table_adtl_cnt", "Additional Address Count", base.DEC)
f.v1_txn_config_values_off = ProtoField.uint16("fd_txn.v1_txn_config_values_off", "V1 Config Values Offset", base.DEC)
f.instr_cnt = ProtoField.uint16("fd_txn.instr_cnt", "Instruction Count", base.DEC)

f.instrs = ProtoField.none("fd_txn.instr", "Instructions")
f.instr = ProtoField.none("fd_txn_instr", "Instruction")
f.program_id = ProtoField.uint8("fd_txn_instr.program_id", "Program ID Index", base.DEC)
f.acct_cnt = ProtoField.uint16("fd_txn_instr.acct_cnt", "Account Count", base.DEC)
f.data_sz = ProtoField.uint16("fd_txn_instr.data_sz", "Data Size", base.DEC)
f.acct_off = ProtoField.uint16("fd_txn_instr.acct_off", "Account Offset", base.DEC)
f.data_off = ProtoField.uint16("fd_txn_instr.data_off", "Data Offset", base.DEC)

f.alts = ProtoField.none("fd_txn.address_tables", "Address Tables")
f.alt = ProtoField.none("fd_txn_acct_addr_lut", "Table")
f.addr_off = ProtoField.uint16("fd_txn_acct_addr_lut.addr_off", "Address Offset", base.DEC)
f.writable_cnt = ProtoField.uint8("fd_txn_acct_addr_lut.writable_cnt", "Writable Count", base.DEC)
f.readonly_cnt = ProtoField.uint8("fd_txn_acct_addr_lut.readonly_cnt", "Readonly Count", base.DEC)
f.writable_off = ProtoField.uint16("fd_txn_acct_addr_lut.writable_off", "Writable Offset", base.DEC)
f.readonly_off = ProtoField.uint16("fd_txn_acct_addr_lut.readonly_off", "Readonly Offset", base.DEC)

-- Dissector function
function p_fd_txn.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = p_fd_txn.name

  -- Create subtree for FD Transaction Protocol
  local subtree = tree:add(p_fd_txn, buffer(), "FD Transaction Struct Data")

  -- Add fields to subtree
  local offset = 0
  subtree:add_le(f.transaction_version, buffer(offset, 1)); offset = offset + 1
  subtree:add_le(f.signature_cnt, buffer(offset, 1)); offset = offset + 1
  subtree:add_le(f.signature_off, buffer(offset, 2)); offset = offset + 2
  subtree:add_le(f.message_off, buffer(offset, 2)); offset = offset + 2
  subtree:add_le(f.readonly_signed_cnt, buffer(offset, 1)); offset = offset + 1
  subtree:add_le(f.readonly_unsigned_cnt, buffer(offset, 1)); offset = offset + 1
  subtree:add_le(f.acct_addr_cnt, buffer(offset, 2)); offset = offset + 2
  subtree:add_le(f.acct_addr_off, buffer(offset, 2)); offset = offset + 2
  subtree:add_le(f.recent_blockhash_off, buffer(offset, 2)); offset = offset + 2
  local addr_table_cnt = buffer(offset,1):le_uint()
  subtree:add_le(f.addr_table_lookup_cnt, buffer(offset, 1)); offset = offset + 1
  subtree:add_le(f.addr_table_adtl_writable_cnt, buffer(offset, 1)); offset = offset + 1
  subtree:add_le(f.addr_table_adtl_cnt, buffer(offset, 1)); offset = offset + 2
  subtree:add_le(f.v1_txn_config_values_off, buffer(offset, 2)); offset = offset + 2
  local instr_cnt = buffer(offset,2):le_uint()
  subtree:add_le(f.instr_cnt, buffer(offset, 2)); offset = offset + 2

  if instr_cnt > 0 then
    local instr_tree = subtree:add(f.instrs, buffer(offset, 10*instr_cnt))
    for i=1,instr_cnt,1 do
      local instr = instr_tree:add(f.instr, buffer(offset, 10)):append_text(" #" .. i-1 )
      parse_instr( buffer(offset, 10), instr )
      offset = offset+10;
    end
  end
  if addr_table_cnt > 0 then
    local alt_tree = subtree:add(f.alts, buffer(offset, 8*addr_table_cnt))
    for i=1,addr_table_cnt,1 do
      local alt = alt_tree:add(f.alt, buffer(offset, 8)):append_text(" #".. i-1 )
      parse_alt( buffer(offset, 8), alt )
      offset = offset+8;
    end
  end
end

function parse_instr(buffer,instr_tree)
  local offset=0
  instr_tree:add_le(f.program_id, buffer(offset, 1)); offset = offset + 2 -- includes padding
  instr_tree:add_le(f.acct_cnt, buffer(offset, 2)); offset = offset + 2
  instr_tree:add_le(f.data_sz, buffer(offset, 2)); offset = offset + 2
  instr_tree:add_le(f.acct_off, buffer(offset, 2)); offset = offset + 2
  instr_tree:add_le(f.data_off, buffer(offset, 2)); offset = offset + 2
end

function parse_alt(buffer,alt_tree)
  local offset=0
  alt_tree:add_le(f.addr_off,     buffer(offset, 2)); offset = offset + 2
  alt_tree:add_le(f.writable_cnt, buffer(offset, 1)); offset = offset + 1
  alt_tree:add_le(f.readonly_cnt, buffer(offset, 1)); offset = offset + 1
  alt_tree:add_le(f.writable_off, buffer(offset, 2)); offset = offset + 2
  alt_tree:add_le(f.readonly_off, buffer(offset, 2)); offset = offset + 2
end






-- Define a new protocol
local poh_shred = Proto("fd_poh_shred", "FD PoH to Shred Messages")

-- Define fields
local f_parent_offset = ProtoField.uint64("fd_poh_shred.parent_offset", "Parent Offset")
local f_reference_tick = ProtoField.uint64("fd_poh_shred.reference_tick", "Reference Tick")
local f_block_complete = ProtoField.int32("fd_poh_shred.block_complete", "Block Complete")
local f_parent_block_id = ProtoField.bytes("fd_poh_shred.parent_block_id", "Parent Block ID")
local f_parent_block_id_valid = ProtoField.bool("fd_poh_shred.parent_block_id_valid", "Parent Block ID Valid")
local f_hashcnt_delta = ProtoField.uint64("fd_poh_shred.hashcnt_delta", "Hash Count Delta")
local f_hash = ProtoField.bytes("fd_poh_shred.hash", "Hash")
local f_txn_cnt = ProtoField.uint64("fd_poh_shred.txn_cnt", "Transaction Count")
local f_txns = ProtoField.none("fd_poh_shred.txns", "Transactions")

-- Add the fields to the protocol
poh_shred.fields = { f_parent_offset, f_reference_tick, f_block_complete, f_parent_block_id, f_parent_block_id_valid, f_hashcnt_delta, f_hash, f_txn_cnt, f_txns }

function poh_shred.dissector(buffer, pinfo, tree)
  if buffer:len() < 104 then return end
  local txn_cnt = buffer(96, 8):le_uint64():tonumber()
  tree:add_le(f_parent_offset, buffer(0, 8))
  tree:add_le(f_reference_tick, buffer(8, 8))
  tree:add_le(f_block_complete, buffer(16, 4))
  tree:add_le(f_parent_block_id, buffer(20, 32))
  tree:add_le(f_parent_block_id_valid, buffer(52, 1))
  tree:add_le(f_hashcnt_delta, buffer(56, 8))
  tree:add_le(f_hash, buffer(64, 32))
  tree:add_le(f_txn_cnt, buffer(96, 8))

  if txn_cnt>0 then
    local tvb = buffer(104)
    local subtree = tree:add(f_txns, tvb)
    local dissector = Dissector.get("solana.tpu.udp")
    for i=1,txn_cnt,1 do
      if tvb:len() == 0 then return end
      pinfo.private.bytes_consumed = nil
      dissector:call(tvb:tvb(), pinfo, subtree)
      local consumed = tonumber(pinfo.private.bytes_consumed)
      if not consumed or consumed <= 0 or consumed > tvb:len() then return end
      tvb = tvb(consumed)
    end
  end
end


-- Define a new protocol
local rebate = Proto("fd_pack_rebate_t", "FD CU Rebate Message")

-- Define fields
local f_total_cost_rebate = ProtoField.uint64("fd_pack_rebate_t.total_cost_rebate", "Total Cost Rebate")
local f_vote_cost_rebate = ProtoField.uint64("fd_pack_rebate_t.vote_cost_rebate", "Vote Cost Rebate")
local f_data_bytes_rebate= ProtoField.uint64("fd_pack_rebate_t.data_bytes_rebate", "Data Bytes Rebate")
local f_microblock_cnt_rebate= ProtoField.uint64("fd_pack_rebate_t.microblock_cnt_rebate", "Microblock Count Rebate")
local f_alloc_rebate = ProtoField.uint64("fd_pack_rebate_t.alloc_rebate", "Allocation Rebate")

local f_ib_result= ProtoField.int32("fd_pack_rebate_t.ib_result", "IB Result")
local f_writer_cnt= ProtoField.uint32("fd_pack_rebate_t.writer_cnt", "Writer Count")
local f_writers = ProtoField.none("fd_pack_rebate_t.writers", "Written Pubkeys")

local f_writer = ProtoField.none("fd_pack_rebate_t.writer", "Written Pubkey")
local f_pubkey= ProtoField.bytes("fd_pack_rebate_t.pubkey", "Writer Pubkey")
local f_rebate_cus= ProtoField.uint64("fd_pack_rebate_t.rebate_cus", "Rebate CUs")


-- Add the fields to the protocol
rebate.fields = { f_total_cost_rebate, f_vote_cost_rebate, f_data_bytes_rebate, f_microblock_cnt_rebate, f_alloc_rebate, f_ib_result, f_writer_cnt, f_pubkey, f_rebate_cus, f_writers, f_writer }

function rebate.dissector(buffer, pinfo, tree)
    if buffer:len() < 48 then return end
    local writer_cnt = buffer(44, 4):le_uint()
    -- Add fields to the tree
    tree:add_le(f_total_cost_rebate, buffer(0, 8))
    tree:add_le(f_vote_cost_rebate, buffer(8, 8))
    tree:add_le(f_data_bytes_rebate, buffer(16, 8))
    tree:add_le(f_microblock_cnt_rebate, buffer(24, 8))
    tree:add_le(f_alloc_rebate, buffer(32, 8))
    tree:add_le(f_ib_result, buffer(40, 4))
    tree:add_le(f_writer_cnt, buffer(44, 4))

    if writer_cnt>0 then
      local tvb = buffer(48)
      local subtree = tree:add(f_writers, tvb)
      for i=1,writer_cnt,1 do
        local s2 = subtree:add(f_writer, tvb(i*40-40, 40))
        s2:add_le(f_pubkey, tvb(i*40-40, 32))
        s2:add_le(f_rebate_cus, tvb(i*40-8, 8))
      end
    end
end
-- Define a new protocol
local fd_became_leader = Proto("fd_became_leader_t", "FD Replay Became Leader Message")

-- Define fields
local f_slot = ProtoField.uint64("fd_became_leader_t.slot", "Slot")
local f_slot_start = ProtoField.absolute_time("fd_became_leader_t.slot_start", "Slot start time", base.UTC)
local f_slot_end   = ProtoField.absolute_time("fd_became_leader_t.slot_end", "Slot end time", base.UTC)
local f_bank_idx   = ProtoField.uint64("fd_became_leader_t.bank_idx", "Bank Index")
local f_bank_seq   = ProtoField.uint64("fd_became_leader_t.bank_seq", "Bank Sequence")
local f_max_microblocks_in_slot = ProtoField.uint64("fd_became_leader_t.max_microblocks_in_slot", "Maximum allowed microblocks in slot")
local f_ticks_per_slot = ProtoField.uint64("fd_became_leader_t.ticks_per_slot", "Ticks per slot")

-- Add the fields to the protocol
fd_became_leader.fields = { f_slot, f_slot_start, f_slot_end, f_bank_idx, f_bank_seq, f_max_microblocks_in_slot, f_ticks_per_slot }

function fd_became_leader.dissector(buffer, pinfo, tree)
  if buffer:len() < 64 then return end
  local subtree = tree:add(fd_became_leader, buffer(), "fd_became_leader_t")

  -- Extract fields from buffer
  local slot_start = buffer(8, 8):le_int64()
  local slot_end   = buffer(16, 8):le_int64()

  -- Add fields to the tree
  subtree:add_le(f_slot, buffer(0, 8))
  subtree:add(f_slot_start, buffer(8, 8), NSTime.new( (slot_start/1000000000):tonumber(), (slot_start%1000000000):lower()) )
  subtree:add(f_slot_end,   buffer(16, 8), NSTime.new( (slot_end  /1000000000):tonumber(), (slot_end  %1000000000):lower()) )
  subtree:add_le(f_bank_idx, buffer(32, 8))
  subtree:add_le(f_bank_seq, buffer(40, 8))
  subtree:add_le(f_max_microblocks_in_slot, buffer(48, 8))
  subtree:add_le(f_ticks_per_slot, buffer(56, 8))
end


-- Define a new protocol
local fd_done_packing = Proto("fd_done_packing_t", "FD Pack to PoH Done Packing Message")

local f_microblocks_in_slot = ProtoField.uint64("fd_done_packing_t.microblocks_in_slot", "Microblocks in slot")

fd_done_packing.fields = { f_microblocks_in_slot }

function fd_done_packing.dissector(buffer, pinfo, tree)
  local subtree = tree:add(fd_done_packing, buffer(), "fd_done_packing_t")
  subtree:add_le(f_microblocks_in_slot, buffer(0, 8))
end


-- Define a new protocol
local fd_txnm = Proto("fd_txn_m_t", "FD Transaction with Payload and Metadata")

-- Define fields
local f_ref_slot = ProtoField.uint64("fd_txn_m_t.reference_slot", "Reference Slot"  )
local f_txn_t_sz = ProtoField.uint16("fd_txn_m_t.txn_t_sz",       "Size of fd_txn_t")
local f_source_ipv4 = ProtoField.ipv4("fd_txn_m_t.source_ipv4",       "IP Address")

local source_tpu_enum = {
    [1] = "QUIC",
    [2] = "UDP",
    [3] = "GOSSIP",
    [4] = "BUNDLE",
    [5] = "TXSEND"
}
local f_source_tpu = ProtoField.uint8("fd_txn_m_t.source_tpu",       "Source TPU", base.DEC, source_tpu_enum)
local f_payload_sz = ProtoField.uint16("fd_txn_m_t.payload_sz",       "Size of payload")
local f_first_seen_nanos = ProtoField.int64("fd_txn_m_t.first_seen_nanos", "First Seen (ns)")
local f_bundle_id = ProtoField.uint64("fd_txn_m_t.bundle_id",       "Bundle ID")
local f_bundle_txn_cnt = ProtoField.uint64("fd_txn_m_t.bundle_txn_cnt",       "Bundle Transaction Count")
local f_bundle_commission = ProtoField.uint8("fd_txn_m_t.bundle_commission",       "Bundle Commission")
local f_bundle_pubkey = ProtoField.bytes("fd_txn_m_t.bundle_commission_pubkey",       "Bundle Commission Pubkey")
local f_alt_entry = ProtoField.bytes("fd_txn_m_t.alt_entry",       "Address Lookup Table Account Address")

-- Add the fields to the protocol
fd_txnm.fields = { f_ref_slot, f_txn_t_sz, f_source_ipv4, f_source_tpu, f_payload_sz, f_first_seen_nanos, f_bundle_id, f_bundle_txn_cnt, f_bundle_commission, f_bundle_pubkey, f_alt_entry }

function fd_txnm.dissector(buffer, pinfo, tree)
  local payload_start = 88 -- sizeof(fd_txn_m_t)
  if buffer:len() < payload_start then return end
  local subtree = tree:add(fd_txnm, buffer(), "fd_txn_m_t")

  local payload_sz   = buffer(8,2):le_uint()
  local txn_t_sz     = buffer(10,2):le_uint()
  -- Add fields to the tree
  subtree:add_le(f_ref_slot, buffer(0, 8))
  subtree:add_le(f_payload_sz, buffer(8, 2))
  subtree:add_le(f_txn_t_sz, buffer(10, 2))
  subtree:add(f_source_ipv4, buffer(12, 4))
  subtree:add_le(f_source_tpu, buffer(16, 1))

  subtree:add_le(f_first_seen_nanos, buffer(24, 8))
  subtree:add_le(f_bundle_id, buffer(32, 8))
  subtree:add_le(f_bundle_txn_cnt, buffer(40, 8))
  subtree:add_le(f_bundle_commission, buffer(48, 1))
  subtree:add(f_bundle_pubkey, buffer(49, 32))
  if payload_start + payload_sz > buffer:len() then return end

  local payload_tree = tree:add(buffer(payload_start,payload_sz), "Solana Transaction")
  local udp_dissector = Dissector.get("solana.tpu.udp")
  udp_dissector:call(buffer(payload_start,payload_sz):tvb(), pinfo, payload_tree)

  local offset = payload_start + payload_sz

  -- Pre-verify frags don't have fields after the payload.
  if offset == buffer:len() or txn_t_sz == 0 then
    return
  end

  -- Align to 2
  if offset % 2 == 1 then
    offset = offset+1
  end
  if txn_t_sz < 22 or offset + txn_t_sz > buffer:len() then return end

  local txn_dissector = Dissector.get("fd_txn_t")
  local parsed_tree = tree:add(buffer(offset,txn_t_sz), "fd_txn_t")
  txn_dissector:call(buffer(offset,txn_t_sz):tvb(), pinfo, parsed_tree)

  offset = offset + txn_t_sz
  local alt_addr = math.floor((buffer:len() - offset) / 32)
  if alt_addr > 0 then
    local alt_subtree = tree:add(buffer(offset, alt_addr*32), "Expanded Address Lookup Tables")
    for i=0, alt_addr-1 do
      alt_subtree:add(f_alt_entry, buffer(offset + 32*i, 32))
    end
  end
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(9001, Dissector.get("solana.tpu.udp"))
