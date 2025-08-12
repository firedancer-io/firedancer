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
local tpu_txn = ProtoField.bytes("fd_tpu.txn_t", "fd_txn_t")
local tpu_requested_cus = ProtoField.uint32("fd_tpu.requested_cus", "Requested CUs")
local tpu_executed_cus = ProtoField.uint32("fd_tpu.executed_cus", "Executed CUs")
local sched_arrival_ns = ProtoField.int64("fd_tpu.sched_arrival_ns", "Arrival Time (ns)")
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
local tpu_executed = ProtoField.uint32("fd_tpu.flags.excuted", "Execute Success", base.DEC, yesno_types, 0x10)
local tpu_nonce = ProtoField.uint32("fd_tpu.flags.is_nonce", "Durable Nonce", base.DEC, yesno_types, 0x20)
local tpu_status   = ProtoField.uint32("fd_tpu.flags.status", "Status", base.DEC, status_codes, 0xFF000000)

-- local tpu_simple_vote = ProtoField.uint32("fd_tpu.flags.simple_vote", "Simple Vote")
-- local tpu_bundle      = ProtoField.uint32("fd_tpu.flags.bundle", "Bundle")
-- local tpu_initializer = ProtoField.uint32("fd_tpu.flags.init_bundle", "Initializer Bundle")
-- local tpu_sanitized   = ProtoField.uint32("fd_tpu.flags.sanitized", "Sanitize Success")
-- local tpu_executed    = ProtoField.uint32("fd_tpu.flags.executed", "Execute Success")

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
  tpu_requested_cus,
  tpu_executed_cus,
  sched_arrival_ns,
  tpu_flags,

  tpu_simple_vote,
  tpu_bundle,
  tpu_initializer,
  tpu_sanitized,
  tpu_executed,
  tpu_nonce,
  tpu_status
}

local link_hashes = {
  [0xc67c71] = "net_netmux",
  [0x641266] = "quic_netmux",
  [0xbbbcde] = "shred_netmux",
  [0x18a945] = "shred_net",
  [0x2aabab] = "quic_verify",
  [0x1efba0] = "verify_dedup",
  [0x59ac4d] = "dedup_pack",
  [0x9e5973] = "gossip_dedup",
  [0x27193a] = "stake_out",
  [0x59bd91] = "resolv_pack",
  [0x7b8342] = "pack_bank",
  [0xfe7bbf] = "bank_poh",
  [0xdb6a44] = "poh_shred",
  [0xb8e9a5] = "crds_shred",
  [0x6e5d41] = "shred_store",
  [0x3845f5] = "shred_storei",
  [0xc650c9] = "shred_sign",
  [0xd408b5] = "sign_shred",
  [0x0d274e] = "quic_net",
  [0xf680c5] = "net_quic",
  [0xee5444] = "poh_pack",
  [0x6f928b] = "net_shred",
  [0x9e5973] = "gossip_dedup",
  [0x409d3f] = "dedup_resolv",
  [0x3fb62b] = "replay_resol",
  [0x8c8ec7] = "plugin_out"  ,
  [0x7277f4] = "replay_plugi",
  [0x95c8b9] = "gossip_plugi",
  [0xff8c5d] = "poh_plugin"  ,
  [0x016c76] = "startp_plugi",
  [0x875140] = "votel_plugin",
  [0x9e4bf4] = "bundle_verif",
  [0xc7e9e7] = "bundle_sign" ,
  [0x81114e] = "sign_bundle" ,
  [0x8ebf3e] = "bundle_plugi",
  [0x06c577] = "pack_sign",
  [0x6a974e] = "sign_pack",
  [0x2080d6] = "bank_pack"
}



function tango.dissector (tvb, pinfo, tree)
    local subtree = tree:add(tango, tvb())
  packet_len = tvb:len()

    if packet_len == 0 then
    return
  end

  local link_hash = tvb(packet_len-4, 4):le_uint()
  local link_name = link_hashes[bit.rshift(link_hash, 8)]

  local link_element = subtree:add_le(tango_link, tvb(packet_len-4, 4)):append_text( " (" .. link_name .. ")" )
  subtree:add(tango_link_name, tvb(packet_len-4, 4), link_name)

  subtree:add_le(tango_seq, tvb(0, 8))
  subtree:add_le(tango_sig, tvb(8, 8))
  subtree:add_le(tango_chunk, tvb(16, 4))
  subtree:add_le(tango_sz, tvb(20, 2))
  local ctl_node = subtree:add(tango_ctl, tvb(22, 2))
  local ctl = tvb(22,2):le_uint()

  ctl_node:add(tango_ctl_som, tvb(22,2), bit.band(ctl, 1))
  ctl_node:add(tango_ctl_eom, tvb(22,2), bit.band(ctl, 2))
  ctl_node:add(tango_ctl_err, tvb(22,2), bit.band(ctl, 4))
  ctl_node:add(tango_ctl_orig, tvb(22,2), bit.band(ctl, 0xFFF8))

  subtree:add_le(tango_tsorig, tvb(24, 4))
  subtree:add_le(tango_tspub, tvb(28, 4))


  local dcache_contents = tvb:range(32, packet_len-36):tvb()
  local dcache_tree = subtree:add(tango_contents, tvb(32, packet_len-36))

  if link_name == "net_netmux" or link_name == "quic_netmux" or link_name == "shred_netmux" or link_name == "net_quic" or link_name == "quic_net" or link_name == "shred_net" or link_name == "net_shred" then
    local dissector = Dissector.get("eth_withoutfcs")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "verify_dedup" or link_name == "dedup_pack" or link_name == "dedup_resolv" or link_name == "resolv_pack" or link_name == "bundle_verif" or "quic_verify" or link_name == "gossip_verif" or link_name == "send_txns" or link_name == "gossip_dedup" then
    local dissector = Dissector.get("fd_txn_m_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "poh_shred" then
    local dissector = Dissector.get("fd_poh_shred")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "bank_pack" then
    local dissector = Dissector.get("fd_pack_rebate_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "pack_bank" or link_name == "bank_poh" then
    local dissector = Dissector.get("solana.tpu.udp")
    local dissector2 = Dissector.get("fd_txn_t")

    for j=1,dcache_contents:len()-2111,2112 do
      local txn_tree = dcache_tree:add(tpu_txn, dcache_contents(j-1,2112))

      dissector:call(dcache_contents(j-1,1232):tvb(), pinfo, txn_tree)
      txn_tree:add_le(tpu_payload_sz, dcache_contents(j+1231, 2))
      txn_tree:add_le(tpu_requested_cus, dcache_contents(j+1239, 4))
      txn_tree:add_le(tpu_executed_cus, dcache_contents(j+1243, 4))
      txn_tree:add_le(sched_arrival_ns, dcache_contents(j+1247, 8))
      local flag_tvb = dcache_contents(j+1255,4)
      local flag_val = flag_tvb:le_uint()
      local flag_node = txn_tree:add_le(tpu_flags, dcache_contents(j+1255, 4))
      flag_node:add_le(tpu_simple_vote, flag_tvb)
      flag_node:add_le(tpu_bundle,flag_tvb)
      flag_node:add_le(tpu_initializer,flag_tvb)
      flag_node:add_le(tpu_sanitized,  flag_tvb)
      flag_node:add_le(tpu_executed, flag_tvb)
      flag_node:add_le(tpu_nonce, flag_tvb)
      flag_node:add_le(tpu_status, flag_tvb)

      local txn_t_tvb = dcache_contents(j+1259, 852):tvb()
      dissector2:call(txn_t_tvb, pinfo, txn_tree)
    end
    -- If bank_poh, the trailer
  elseif link_name == "shred_store" or link_name == "shred_storei" then
    local dissector = Dissector.get("fd_shred34_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
  elseif link_name == "poh_pack" then
    local dissector = Dissector.get("fd_became_leader_t")
    dissector:call(dcache_contents, pinfo, dcache_tree)
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

local f_slot_start_ns = ProtoField.int64("fd_poh_shred.slot_start_ns", "Slot Start Time (ns)")
local f_bank_ptr = ProtoField.uint64("fd_poh_shred.bank", "Bank", base.HEX)

-- Add the fields to the protocol
poh_shred.fields = { f_parent_offset, f_reference_tick, f_block_complete, f_parent_block_id, f_parent_block_id_valid, f_hashcnt_delta, f_hash, f_txn_cnt, f_txns, f_slot_start_ns, f_bank_ptr }

function poh_shred.dissector(buffer, pinfo, tree)
  if buffer:len() < 64 then
    -- Became leader.  This should use the sig field, but we don't have it here
    tree:set_text("Became Leader")
    tree:add_le(f_slot_start_ns, buffer(0, 8))
    tree:add_le(f_bank_ptr, buffer(8, 8))
  else
    local txn_cnt = buffer(96, 4):le_uint()
    -- Add fields to the tree
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
        dissector:call(tvb:tvb(), pinfo, subtree)
        tvb = tvb(tonumber(pinfo.private.bytes_consumed))
      end
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

local f_ib_result= ProtoField.int32("fd_pack_rebate_t.ib_result", "IB Result")
local f_writer_cnt= ProtoField.uint32("fd_pack_rebate_t.writer_cnt", "Writer Count")
local f_writers = ProtoField.none("fd_pack_rebate_t.writers", "Written Pubkeys")

local f_writer = ProtoField.none("fd_pack_rebate_t.writer", "Written Pubkey")
local f_pubkey= ProtoField.bytes("fd_pack_rebate_t.pubkey", "Writer Pubkey")
local f_rebate_cus= ProtoField.uint64("fd_pack_rebate_t.rebate_cus", "Rebate CUs")


-- Add the fields to the protocol
rebate.fields = { f_total_cost_rebate, f_vote_cost_rebate, f_data_bytes_rebate, f_microblock_cnt_rebate, f_ib_result, f_writer_cnt, f_pubkey, f_rebate_cus, f_writers, f_writer }

function rebate.dissector(buffer, pinfo, tree)
    local writer_cnt = buffer(36, 4):le_uint()
    -- Add fields to the tree
    tree:add_le(f_total_cost_rebate, buffer(0, 8))
    tree:add_le(f_vote_cost_rebate, buffer(8, 8))
    tree:add_le(f_data_bytes_rebate, buffer(16, 8))
    tree:add_le(f_microblock_cnt_rebate, buffer(24, 8))
    tree:add_le(f_ib_result, buffer(32, 4))
    tree:add_le(f_writer_cnt, buffer(36, 4))

    if writer_cnt>0 then
      local tvb = buffer(40)
      local subtree = tree:add(f_writers, tvb)
      for i=1,writer_cnt,1 do
        local s2 = subtree:add(f_writer, tvb(i*40-40, 40))
        s2:add_le(f_pubkey, tvb(i*40-40, 32))
        s2:add_le(f_rebate_cus, tvb(i*40-8, 8))
      end
    end
end




-- Define a new protocol
local fd_shred34 = Proto("fd_shred34_t", "FD Shred to Store Message")

-- Define fields
local f_shred_cnt = ProtoField.uint64("fd_shred34_t.shred_cnt", "Shred Count")
local f_est_txn_cnt = ProtoField.uint64("fd_shred34_t.est_txn_cnt", "Estimated Transaction Count")
local f_stride = ProtoField.uint64("fd_shred34_t.stride", "Stride")
local f_offset = ProtoField.uint64("fd_shred34_t.offset", "Offset")
local f_shred_sz = ProtoField.uint64("fd_shred34_t.shred_sz", "Shred Size")
local f_shred_payload = ProtoField.bytes("fd_shred34_t.shred_payload", "Shred Payload")

-- Add the fields to the protocol
fd_shred34.fields = { f_shred_cnt, f_est_txn_cnt, f_stride, f_offset, f_shred_sz, f_shred_payload }

function fd_shred34.dissector(buffer, pinfo, tree)
  local subtree = tree:add(fd_shred34, buffer(), "fd_shred34_t")

  -- Extract fields from buffer
  local shred_cnt = buffer(0, 4):le_uint()
  local est_txn_cnt = buffer(8, 4):le_uint()
  local stride = buffer(16, 4):le_uint()
  local offset = buffer(24, 4):le_uint()
  local shred_sz = buffer(32, 4):le_uint()

  -- Add fields to the tree
  subtree:add_le(f_shred_cnt, buffer(0, 8))
  subtree:add_le(f_est_txn_cnt, buffer(8, 8))
  subtree:add_le(f_stride, buffer(16, 8))
  subtree:add_le(f_offset, buffer(24, 8))
  subtree:add_le(f_shred_sz, buffer(32, 8))

  local dissector = Dissector.get("solana.shreds")
  -- Process each shred
  local shred_start = 32
  for i = 0, shred_cnt-1 do
    local tvb = buffer(i * stride + offset, shred_sz):tvb()
    dissector:call(tvb, pinfo, subtree)
  end
end


-- Define a new protocol
local fd_became_leader = Proto("fd_became_leader_t", "FD PoH to Pack Became Leader Message")

-- Define fields
local f_slot_start = ProtoField.absolute_time("fd_became_leader_t.slot_start", "Slot start time", base.UTC)
local f_slot_end   = ProtoField.absolute_time("fd_became_leader_t.slot_end", "Slot end time", base.UTC)
local f_bank_ptr   = ProtoField.uint64("fd_became_leader_t.bank", "Bank Pointer")
local f_max_microblocks_in_slot = ProtoField.uint64("fd_became_leader_t.max_microblocks_in_slot", "Maximum allowed microblocks in slot")
local f_ticks_per_slot = ProtoField.uint64("fd_became_leader_t.ticks_per_slot", "Ticks per slot")

-- Add the fields to the protocol
fd_became_leader.fields = { f_slot_start, f_slot_end, f_bank_ptr, f_max_microblocks_in_slot, f_ticks_per_slot }

function fd_became_leader.dissector(buffer, pinfo, tree)
  local subtree = tree:add(fd_became_leader, buffer(), "fd_became_leader_t")

  -- Extract fields from buffer
  local slot_start = buffer(0, 8):le_int64()
  local slot_end   = buffer(8, 8):le_int64()

  -- Add fields to the tree
  subtree:add(f_slot_start, buffer(0, 8), NSTime.new( (slot_start/1000000000):tonumber(), (slot_start%1000000000):lower()) )
  subtree:add(f_slot_end,   buffer(8, 8), NSTime.new( (slot_end  /1000000000):tonumber(), (slot_end  %1000000000):lower()) )
  subtree:add_le(f_bank_ptr, buffer(16, 8))
  subtree:add_le(f_max_microblocks_in_slot, buffer(24, 8))
  subtree:add_le(f_ticks_per_slot, buffer(32, 8))
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
    [4] = "GOSSIP",
    [8] = "BUNDLE",
    [16] = "SEND"
}
local f_source_tpu = ProtoField.uint8("fd_txn_m_t.source_tpu",       "Source TPU", base.DEC, source_tpu_enum)
local f_payload_sz = ProtoField.uint16("fd_txn_m_t.payload_sz",       "Size of payload")
local f_bundle_id = ProtoField.uint64("fd_txn_m_t.bundle_id",       "Bundle ID")
local f_bundle_txn_cnt = ProtoField.uint64("fd_txn_m_t.bundle_txn_cnt",       "Bundle Transaction Count")
local f_bundle_commission = ProtoField.uint8("fd_txn_m_t.bundle_commission",       "Bundle Commission")
local f_bundle_pubkey = ProtoField.bytes("fd_txn_m_t.bundle_commission_pubkey",       "Bundle Commission Pubkey")
local f_alt_entry = ProtoField.bytes("fd_txn_m_t.alt_entry",       "Address Lookup Table Account Address")

-- Add the fields to the protocol
fd_txnm.fields = { f_ref_slot, f_txn_t_sz, f_source_ipv4, f_source_tpu, f_payload_sz, f_bundle_id, f_bundle_txn_cnt, f_bundle_commission, f_bundle_pubkey, f_alt_entry }

function fd_txnm.dissector(buffer, pinfo, tree)
  local subtree = tree:add(fd_txnm, buffer(), "fd_txn_m_t")

  local payload_sz   = buffer(8,2):le_uint()
  local txn_t_sz     = buffer(10,2):le_uint()
  -- Add fields to the tree
  subtree:add_le(f_ref_slot, buffer(0, 8))
  subtree:add_le(f_payload_sz, buffer(8, 2))
  subtree:add_le(f_txn_t_sz, buffer(10, 2))
  subtree:add(f_source_ipv4, buffer(12, 4))
  subtree:add_le(f_source_tpu, buffer(16, 1))

  subtree:add_le(f_bundle_id, buffer(24, 8))
  subtree:add_le(f_bundle_txn_cnt, buffer(32, 8))
  subtree:add_le(f_bundle_commission, buffer(40, 1))
  subtree:add(f_bundle_pubkey, buffer(41, 32))
  local payload_start = 80

  local payload_tree = tree:add(buffer(payload_start,payload_sz), "Solana Transaction")
  local udp_dissector = Dissector.get("solana.tpu.udp")
  udp_dissector:call(buffer(payload_start,payload_sz):tvb(), pinfo, payload_tree)

  local offset = payload_start + payload_sz

  -- pre-dedup frags don't have fields after the payload
  if offset == buffer:len() then
    return
  end

  -- Align to 2
  if offset % 2 == 1 then
    offset = offset+1
  end

  local txn_dissector = Dissector.get("fd_txn_t")
  local parsed_tree = tree:add(buffer(offset,txn_t_sz), "fd_txn_t")
  txn_dissector:call(buffer(offset,txn_t_sz):tvb(), pinfo, parsed_tree)

  offset = offset + txn_t_sz
  -- Align to 8
  if offset % 8 > 0 then
    offset = offset + 8 - (offset % 8)
  end
  local alt_addr = buffer(offset):len() / 32
  if alt_addr > 0 then
    local alt_subtree = tree:add(buffer(offset, alt_addr*32), "Expanded Address Lookup Tables")
    for i=0, alt_addr-1 do
      alt_subtree:add(f_alt_entry, buffer(offset + 32*i, 32))
    end
  end
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(9001, Dissector.get("solana.tpu.udp"))
