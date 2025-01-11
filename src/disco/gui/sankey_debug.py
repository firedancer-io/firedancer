import re
import sys
import requests

from typing import Dict, Tuple, Optional

def scrape_url(url: str) -> str:
    response = requests.get(url)
    response.raise_for_status()
    response.encoding = 'utf-8'
    return response.text
    
def parse_prometheus_text(text: str) -> Dict[Tuple[str, Optional[str]], int]:
    pattern = re.compile(r'(\w+){kind="(\w+)",kind_id="(\d+)"(,link_kind="(\w+)",link_kind_id="\d+")?(,\w+="(\w+)")?} (\d+)')
    result: Dict[Tuple[str, Optional[str]], int] = {}
    
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            metric_name, _kind, _kind_id, _link, link_kind_id, _, variant, value = match.groups()
            if link_kind_id is not None:
                variant = link_kind_id
            if (metric_name, variant) not in result:
                result[(metric_name, variant)] = 0
            result[(metric_name, variant)] += int(value)

    return result

def print_sankey(summed: Dict[Tuple[str, Optional[str]], int]):
    in_block_engine = summed[('bundle_transaction_received', None)] if ('bundle_transaction_received', None) in summed else 0
    in_gossip = summed[('dedup_gossiped_votes_received', None)]
    in_udp = summed[('quic_txns_received', 'udp')]
    in_quic = summed[('quic_txns_received', 'quic_fast')] + summed[('quic_txns_received', 'quic_frag')]

    verify_overrun = summed[('link_overrun_reading_frag_count', 'quic_verify')] + \
                     int(summed[('link_overrun_polling_frag_count', 'quic_verify')] / 6)
    verify_failed = summed[('verify_transaction_verify_failure', None)] + summed[('verify_transaction_bundle_peer_failure', None)]
    verify_parse = summed[('verify_transaction_parse_failure', None)]
    verify_dedup = summed[('verify_transaction_dedup_failure', None)]

    dedup_dedup = summed[('dedup_transaction_dedup_failure', None)] + summed[('dedup_transaction_bundle_peer_failure', None)]

    resolv_failed = summed[('resolv_blockhash_expired', None)] + \
                    summed[('resolv_no_bank_drop', None)] + \
                    summed[('resolv_transaction_bundle_peer_failure', None)] + \
                    summed[('resolv_lut_resolved', 'account_not_found')] + \
                    summed[('resolv_lut_resolved', 'account_uninitialized')] + \
                    summed[('resolv_lut_resolved', 'invalid_account_data')] + \
                    summed[('resolv_lut_resolved', 'invalid_account_owner')] + \
                    summed[('resolv_lut_resolved', 'invalid_lookup_index')]
    
    pack_retained = summed[('pack_available_transactions', None)]

    pack_leader_slot = summed[('pack_transaction_inserted', 'priority')] + \
                       summed[('pack_transaction_inserted', 'nonvote_replace')] + \
                       summed[('pack_transaction_inserted', 'vote_replace')]
    
    pack_expired = summed[('pack_transaction_expired', None)] + \
                   summed[('pack_transaction_inserted', 'expired')]

    pack_invalid = summed[('pack_transaction_inserted', 'bundle_blacklist')] + \
                   summed[('pack_transaction_inserted', 'write_sysvar')] + \
                   summed[('pack_transaction_inserted', 'estimation_fail')] + \
                   summed[('pack_transaction_inserted', 'duplicate_account')] + \
                   summed[('pack_transaction_inserted', 'too_many_accounts')] + \
                   summed[('pack_transaction_inserted', 'too_large')] + \
                   summed[('pack_transaction_inserted', 'addr_lut')] + \
                   summed[('pack_transaction_inserted', 'unaffordable')] + \
                   summed[('pack_transaction_inserted', 'duplicate')]
    
    bank_invalid = summed[('bank_processing_failed', None)] + \
                   summed[('bank_precompile_verify_failure', None)] + \
                   summed[('bank_transaction_load_address_tables', 'account_not_found')] + \
                   summed[('bank_transaction_load_address_tables', 'invalid_account_data')] + \
                   summed[('bank_transaction_load_address_tables', 'invalid_account_owner')] + \
                   summed[('bank_transaction_load_address_tables', 'invalid_index')] + \
                   summed[('bank_transaction_load_address_tables', 'slot_hashes_sysvar_not_found')]
    
    block_fail = summed[('bank_executed_failed_transactions', None)] + summed[('bank_fee_only_transactions', None)]

    block_success = summed[('bank_successful_transactions', None)]

    recon_verify_in = summed[('link_consumed_count', 'quic_verify')] + (summed[('link_consumed_count', 'bundle_verif')] if ('link_consumed_count', 'bundle_verif') in summed else 0)
    recon_verify_out = summed[('link_consumed_count', 'verify_dedup')]

    recon_dedup_in = summed[('link_consumed_count', 'verify_dedup')] + summed[('link_consumed_count', 'gossip_dedup')]
    recon_dedup_out = summed[('link_consumed_count', 'dedup_resolv')]

    recon_resolv_in = summed[('link_consumed_count', 'dedup_resolv')]
    recon_resolv_out = summed[('link_consumed_count', 'resolv_pack')]

    recon_pack_in = summed[('link_consumed_count', 'resolv_pack')]

    print(f"""
block_engine:         {in_block_engine:10,}
gossip:               {in_gossip:10,}
udp:                  {in_udp:10,}
quic:                 {in_quic:10,}
----------------------------------------
IN TOTAL:             {in_block_engine + in_gossip + in_udp + in_quic:10,}

verify_overrun:       {verify_overrun:10,}
verify_failed:        {verify_failed:10,}
verify_parse:         {verify_parse:10,}
verify_dedup:         {verify_dedup:10,}

COMPUTED VERIFY IN:   {in_block_engine + in_udp + in_quic:10,}
COMPUTED VERIFY OUT:  {in_block_engine + in_udp + in_quic - verify_overrun - verify_failed - verify_parse - verify_dedup:10,}
RECONCILE VERIFY IN:  {recon_verify_in:10,}
RECONCILE VERIFY OUT: {recon_verify_out:10,}

dedup_dedup:          {dedup_dedup:10,}

COMPUTED DEDUP IN:    {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup:10,}
COMPUTED DEDUP OUT:   {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup:10,}
RECONCILE DEDUP IN:   {recon_dedup_in:10,}
RECONCILE DEDUP OUT:  {recon_dedup_out:10,}

resolv_failed:        {resolv_failed:10,}

COMPUTED RESOLV IN:   {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup:10,}
COMPUTED RESOLV OUT:  {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_failed:10,}
RECONCILE RESOLV IN:  {recon_resolv_in:10,}
RECONCILE RESOLV OUT: {recon_resolv_out:10,}

pack_retained:        {pack_retained:10,}
pack_leader_slot:     {pack_leader_slot:10,}
pack_expired:         {pack_expired:10,}
pack_invalid:         {pack_invalid:10,}

COMPUTED PACK IN:     {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_failed:10,}
COMPUTED PACK OUT:    {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_failed - pack_retained - pack_leader_slot - pack_expired - pack_invalid:10,}
RECONCILE PACK IN:    {recon_pack_in:10,}

bank_invalid:         {bank_invalid:10,}

block_fail:           {block_fail:10,}
block_success:        {block_success:10,}
----------------------------------------
COMPUTED TOTAL IN:    {in_block_engine + in_gossip + in_udp + in_quic:10,}
COMPUTED TOTAL OUT:   {verify_overrun + verify_failed + verify_parse + verify_dedup + dedup_dedup + resolv_failed + pack_retained + pack_leader_slot + pack_expired + pack_invalid + bank_invalid + block_fail + block_success:10,}
UNACCOUNTED:          {in_block_engine + in_gossip + in_udp + in_quic - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_failed - pack_retained - pack_leader_slot - pack_expired - pack_invalid - bank_invalid - block_fail - block_success:10,}
""")

def main():
    if len(sys.argv) != 2:
        print("Usage: python sankey_debug.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    if url.startswith("http"):
        content = scrape_url(url)
    else:
        content = open(url).read()
    parsed_data = parse_prometheus_text(content)
    import pprint
    pprint.pprint(parsed_data)
    print_sankey(parsed_data)

if __name__ == "__main__":
    main()
