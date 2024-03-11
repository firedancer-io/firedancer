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
local tango_tspub = ProtoField.uint32("fd_tango.tspub", "Publish Timesatamp", base.DEC)
local tango_link = ProtoField.uint32("fd_tango.link", "Link Hash", base.HEX)
local tango_link_name = ProtoField.string("fd_tango.linkname", "Link Name")
local tango_contents = ProtoField.bytes("fd_tango.contents", "DCache Contents")

local tpu_payload_sz = ProtoField.uint16("fd_tpu.payload_sz", "Payload Size")
local tpu_txn = ProtoField.bytes("fd_tpu.txn_t", "fd_txn_t")

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
	tpu_txn
}

local link_hashes = {
	[0xc67c71] = "net_netmux",
	[0x641266] = "quic_netmux",
	[0xbbbcde] = "shred_netmux",
	[0x1efba0] = "verify_dedup",
	[0x1efba0] = "verify_dedup",
	[0x59ac4d] = "dedup_pack",    
	[0xf5fa3d] = "gossip_pack",   
	[0x27193a] = "stake_out",  
	[0x7b8342] = "pack_bank", 
	[0xfe7bbf] = "bank_poh",
	[0xdb6a44] = "poh_shred",
	[0xb8e9a5] = "crds_shred",
	[0x6e5d41] = "shred_store",
	[0x863a9a] = "quic_sign",
	[0x9b7f2f] = "sign_quic",
	[0xc650c9] = "shred_sign",
	[0xd408b5] = "sign_shred"       
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

	if link_name == "net_netmux" or link_name == "quic_netmux" or link_name == "shred_netmux" then
		local dissector = Dissector.get("eth_withoutfcs")
		dissector:call(dcache_contents, pinfo, dcache_tree)
	elseif link_name == "gossip_pack" then
		local dissector = Dissector.get("solana.tpu.udp")
		dissector:call(dcache_contents, pinfo, dcache_tree)
	elseif link_name == "verify_dedup" or link_name == "dedup_pack" then
		local dissector = Dissector.get("solana.tpu.udp")
		dissector:call(dcache_contents, pinfo, dcache_tree)
		-- Also parse fd_txn_t at end
		local payload_sz = dcache_contents(dcache_contents:len()-2, 2):le_uint()
		dcache_tree:add_le(tpu_payload_sz, dcache_contents(dcache_contents:len()-2, 2))
		if payload_sz % 2 == 1 then
			payload_sz = payload_sz+1
		end
		local dissector2 = Dissector.get("fd_txn_t")
		local txn_t_tvb = dcache_contents:range(payload_sz, dcache_contents:len()-2-payload_sz):tvb()
		dissector2:call(txn_t_tvb, pinfo, dcache_tree)
	elseif link_name == "poh_shred" then
		local dissector = Dissector.get("fd_poh_shred")
		dissector:call(dcache_contents, pinfo, dcache_tree)
	elseif link_name == "pack_bank" or link_name == "bank_poh" then
		local dissector = Dissector.get("solana.tpu.udp")
		local dissector2 = Dissector.get("fd_txn_t")

		for j=1,dcache_contents:len()-2103,2104 do
			local txn_tree = dcache_tree:add(tpu_txn, dcache_contents(j-1,2104))

			dissector:call(dcache_contents(j-1,1232):tvb(), pinfo, txn_tree)
			txn_tree:add_le(tpu_payload_sz, dcache_contents(j+1231, 2))
			-- Skip meta, flags
			local txn_t_tvb = dcache_contents(j-1+1232+20, 2104-1232-20):tvb()
			dissector2:call(txn_t_tvb, pinfo, txn_tree)
		end
		-- If bank_poh, the trailer
	elseif link_name == "shred_store" then
		local dissector = Dissector.get("fd_shred34_t")
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
		  local alt = alt_tree:add(f.instr, buffer(offset, 8)):append_text(" #".. i-1 )
		  parse_alt( buffer(offset, 8), instr )
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
local f_hashcnt_delta = ProtoField.uint64("fd_poh_shred.hashcnt_delta", "Hash Count Delta")
local f_hash = ProtoField.bytes("fd_poh_shred.hash", "Hash")
local f_txn_cnt = ProtoField.uint64("fd_poh_shred.txn_cnt", "Transaction Count")
local f_txns = ProtoField.none("fd_poh_shred.txns", "Transactions")

local f_slot_start_ns = ProtoField.int64("fd_poh_shred.slot_start_ns", "Slot Start Time (ns)")
local f_bank_ptr = ProtoField.uint64("fd_poh_shred.bank", "Bank", base.HEX)

-- Add the fields to the protocol
poh_shred.fields = { f_parent_offset, f_reference_tick, f_block_complete, f_hashcnt_delta, f_hash, f_txn_cnt, f_txns, f_slot_start_ns, f_bank_ptr }

function poh_shred.dissector(buffer, pinfo, tree)
	if buffer:len() < 64 then
		-- Became leader.  This should use the sig field, but we don't have it here
		tree:set_text("Became Leader")
		tree:add_le(f_slot_start_ns, buffer(0, 8))
		tree:add_le(f_bank_ptr, buffer(8, 8))
	else
		local txn_cnt = buffer(64, 4):le_uint()
		-- Add fields to the tree
		tree:add_le(f_parent_offset, buffer(0, 8))
		tree:add_le(f_reference_tick, buffer(8, 8))
		tree:add_le(f_block_complete, buffer(16, 4))
		tree:add_le(f_hashcnt_delta, buffer(24, 8))
		tree:add_le(f_hash, buffer(32, 32))
		tree:add_le(f_txn_cnt, buffer(64, 8))

		if txn_cnt>0 then
			local tvb = buffer(72)
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
local fd_shred34 = Proto("fd_shred34_t", "FD Shred to Store Message")

-- Define fields
local f_shred_cnt = ProtoField.uint64("fd_shred34_t.shred_cnt", "Shred Count")
local f_stride = ProtoField.uint64("fd_shred34_t.stride", "Stride")
local f_offset = ProtoField.uint64("fd_shred34_t.offset", "Offset")
local f_shred_sz = ProtoField.uint64("fd_shred34_t.shred_sz", "Shred Size")
local f_shred_payload = ProtoField.bytes("fd_shred34_t.shred_payload", "Shred Payload")

-- Add the fields to the protocol
fd_shred34.fields = { f_shred_cnt, f_stride, f_offset, f_shred_sz, f_shred_payload }

function fd_shred34.dissector(buffer, pinfo, tree)
	local subtree = tree:add(fd_shred34, buffer(), "fd_shred34_t")

    -- Extract fields from buffer
    local shred_cnt = buffer(0, 4):le_uint()
    local stride = buffer(8, 4):le_uint()
    local offset = buffer(16, 4):le_uint()
    local shred_sz = buffer(24, 4):le_uint()

    -- Add fields to the tree
    subtree:add_le(f_shred_cnt, buffer(0, 8))
    subtree:add_le(f_stride, buffer(8, 8))
    subtree:add_le(f_offset, buffer(16, 8))
    subtree:add_le(f_shred_sz, buffer(24, 8))

	local dissector = Dissector.get("solana.shreds")
    -- Process each shred
    local shred_start = 32
    for i = 0, shred_cnt-1 do
        local tvb = buffer(i * stride + offset, shred_sz):tvb()
		dissector:call(tvb, pinfo, subtree)
    end
end







local udp_port = DissectorTable.get("udp.port")
udp_port:add(9001, Dissector.get("solana.tpu.udp"))
