import re
import sys
import requests

from typing import Dict, Tuple, Optional

def scrape_url(url: str) -> str:
    response = requests.get(url)
    response.raise_for_status()
    response.encoding = 'utf-8'
    return response.text

def parse_prometheus_text(text: str) -> Dict[Tuple[str, str, Optional[str]], int]:
    pattern = re.compile(r'(\w+){kind="(\w+)",kind_id="(\d+)"(,link_kind="(\w+)",link_kind_id="\d+")?(,\w+="(\w+)")?} (\d+)')
    result: Dict[Tuple[str, str, Optional[str]], int] = {}

    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            metric_name, kind, _kind_id, _link, link_kind_id, _, variant, value = match.groups()
            result.setdefault((kind, metric_name, variant if link_kind_id is None else link_kind_id), 0)
            result[(kind, metric_name, variant if link_kind_id is None else link_kind_id)] += int(value)

    return result

def get_link_count(summed: Dict[Tuple[str, str, Optional[str]], int], metric: str, link: Optional[str] = None, consumer: Optional[str] = None) -> int:
    if consumer is not None:
        return summed.get((consumer, metric, link), 0)

    all_consumers = set(key[0] for key in summed if key[1:] == (metric, link))
    return sum(summed.get((consumer, metric, link), 0) for consumer in all_consumers)

def print_sankey(summed: Dict[Tuple[str, str, Optional[str]], int]):
    in_block_engine = get_link_count(summed, metric='bundle_transaction_received')
    in_gossip = get_link_count(summed, metric='dedup_gossiped_votes_received')
    in_udp = get_link_count(summed, metric='quic_txns_received', link='udp')
    in_quic = get_link_count(summed, metric='quic_txns_received', link='quic_fast') + get_link_count(summed, metric='quic_txns_received', link='quic_frag')

    verify_overrun = get_link_count(summed, metric='link_overrun_reading_frag_count', link='quic_verify') + \
                     int(get_link_count(summed, metric='link_overrun_polling_frag_count', link='quic_verify') / 6)
    verify_failed = get_link_count(summed, metric='verify_transaction_verify_failure') + get_link_count(summed, metric='verify_transaction_bundle_peer_failure')
    verify_parse = get_link_count(summed, metric='verify_transaction_parse_failure')
    verify_dedup = get_link_count(summed, metric='verify_transaction_dedup_failure')

    dedup_dedup = get_link_count(summed, metric='dedup_transaction_dedup_failure') + get_link_count(summed, metric='dedup_transaction_bundle_peer_failure')

    resolv_failed = get_link_count(summed, metric='resolv_blockhash_expired') + \
                    get_link_count(summed, metric='resolv_no_bank_drop') + \
                    get_link_count(summed, metric='resolv_transaction_bundle_peer_failure') + \
                    get_link_count(summed, metric='resolv_lut_resolved', link='account_not_found') + \
                    get_link_count(summed, metric='resolv_lut_resolved', link='account_uninitialized') + \
                    get_link_count(summed, metric='resolv_lut_resolved', link='invalid_account_data') + \
                    get_link_count(summed, metric='resolv_lut_resolved', link='invalid_account_owner') + \
                    get_link_count(summed, metric='resolv_lut_resolved', link='invalid_lookup_index') + \
                    get_link_count(summed, metric='resolv_stash_operation', link='overrun')

    resolv_retained = get_link_count(summed, metric='resolv_stash_operation', link='inserted') - \
                      get_link_count(summed, metric='resolv_stash_operation', link='overrun') - \
                      get_link_count(summed, metric='resolv_stash_operation', link='published') - \
                      get_link_count(summed, metric='resolv_stash_operation', link='removed')

    pack_cranked = get_link_count(summed, metric='pack_bundle_crank_status', link='inserted') + \
                   get_link_count(summed, metric='pack_bundle_crank_status_insertion_failed') + \
                   get_link_count(summed, metric='pack_bundle_crank_status_creation_failed')

    pack_retained = get_link_count(summed, metric='pack_available_transactions', link='all')

    pack_leader_slow = get_link_count(summed, metric='pack_transaction_inserted', link='priority')

    pack_expired = get_link_count(summed, metric='pack_transaction_expired') + \
                   get_link_count(summed, metric='pack_transaction_deleted') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='expired') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='nonce_priority')

    pack_invalid_bundle = get_link_count(summed, metric='pack_transaction_dropped_partial_bundle') + \
                          get_link_count(summed, metric='pack_bundle_crank_status_insertion_failed') + \
                          get_link_count(summed, metric='pack_bundle_crank_status_creation_failed')

    pack_invalid = get_link_count(summed, metric='pack_transaction_inserted', link='nonce_conflict') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='bundle_blacklist') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='invalid_nonce') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='write_sysvar') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='estimation_fail') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='duplicate_account') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='too_many_accounts') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='too_large') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='addr_lut') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='unaffordable') + \
                   get_link_count(summed, metric='pack_transaction_inserted', link='duplicate') - \
                   get_link_count(summed, metric='pack_bundle_crank_status_insertion_failed')

    bank_invalid = get_link_count(summed, metric='bank_processing_failed') + \
                   get_link_count(summed, metric='bank_precompile_verify_failure') + \
                   get_link_count(summed, metric='bank_transaction_load_address_tables', link='account_not_found') + \
                   get_link_count(summed, metric='bank_transaction_load_address_tables', link='invalid_account_data') + \
                   get_link_count(summed, metric='bank_transaction_load_address_tables', link='invalid_account_owner') + \
                   get_link_count(summed, metric='bank_transaction_load_address_tables', link='invalid_index') + \
                   get_link_count(summed, metric='bank_transaction_load_address_tables', link='slot_hashes_sysvar_not_found')

    block_fail = get_link_count(summed, metric='bank_executed_failed_transactions') + get_link_count(summed, metric='bank_fee_only_transactions')

    block_success = get_link_count(summed, metric='bank_successful_transactions')

    recon_verify_in = get_link_count(summed, metric='link_consumed_count', link='quic_verify') + get_link_count(summed, metric='link_consumed_count', link='bundle_verif')
    recon_verify_out = get_link_count(summed, metric='link_consumed_count', link='verify_dedup')

    recon_dedup_in = get_link_count(summed, metric='link_consumed_count', link='verify_dedup') + get_link_count(summed, metric='link_consumed_count', link='gossip_dedup')
    recon_dedup_out = get_link_count(summed, metric='link_consumed_count', link='dedup_resolv')

    recon_resolv_in = get_link_count(summed, metric='link_consumed_count', link='dedup_resolv')
    recon_resolv_out = get_link_count(summed, metric='link_consumed_count', link='resolv_pack')

    recon_pack_in = get_link_count(summed, metric='link_consumed_count', link='resolv_pack') + get_link_count(summed, metric='pack_bundle_crank_status', link='inserted')
    recon_pack_out = get_link_count(summed, metric='link_consumed_count', link='pack_bank', consumer='gui') # the gui only consumes txn frags on the pack_bank link, so we can use to for reconciling the pack_out count

    print(f"""
block_engine:         {in_block_engine:10,}
gossip:               {in_gossip:10,}
udp:                  {in_udp:10,}
quic:                 {in_quic:10,}
pack_cranked          {pack_cranked:10,}
----------------------------------------
IN TOTAL:             {in_block_engine + in_gossip + in_udp + in_quic + pack_cranked:10,}

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

resolv_retained:      {resolv_retained:10,}
resolv_failed:        {resolv_failed:10,}

COMPUTED RESOLV IN:   {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup:10,}
COMPUTED RESOLV OUT:  {in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_retained - resolv_failed:10,}
RECONCILE RESOLV IN:  {recon_resolv_in:10,}
RECONCILE RESOLV OUT: {recon_resolv_out:10,}

pack_cranked:         {pack_cranked:10,}
pack_retained:        {pack_retained:10,}
pack_leader_slow:     {pack_leader_slow:10,}
pack_expired:         {pack_expired:10,}
pack_invalid:         {pack_invalid:10,}
pack_invalid_bundle   {pack_invalid_bundle:10,}

COMPUTED PACK IN:     {pack_cranked + in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_retained - resolv_failed:10,}
COMPUTED PACK OUT:    {pack_cranked + in_block_engine + in_udp + in_quic + in_gossip - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_retained - resolv_failed - pack_retained - pack_leader_slow - pack_expired - pack_invalid - pack_invalid_bundle:10,}
RECONCILE PACK IN:    {recon_pack_in:10,}
RECONCILE PACK OUT:   {recon_pack_out:10,}

bank_invalid:         {bank_invalid:10,}

block_fail:           {block_fail:10,}
block_success:        {block_success:10,}
----------------------------------------
COMPUTED TOTAL IN:    {pack_cranked + in_block_engine + in_gossip + in_udp + in_quic:10,}
COMPUTED TOTAL OUT:   {verify_overrun + verify_failed + verify_parse + verify_dedup + dedup_dedup + resolv_retained + resolv_failed + pack_retained + pack_leader_slow + pack_expired + pack_invalid + pack_invalid_bundle + bank_invalid + block_fail + block_success:10,}
UNACCOUNTED:          {pack_cranked + in_block_engine + in_gossip + in_udp + in_quic - verify_overrun - verify_failed - verify_parse - verify_dedup - dedup_dedup - resolv_retained - resolv_failed - pack_retained - pack_leader_slow - pack_expired - pack_invalid - pack_invalid_bundle - bank_invalid - block_fail - block_success:10,}
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
