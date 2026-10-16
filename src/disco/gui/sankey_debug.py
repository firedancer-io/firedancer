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
    in_block_engine = get_link_count(summed, metric='bundle_txn_rx_total')
    in_gossip = get_link_count(summed, metric='verify_vote_gossip_rx_total') + \
                get_link_count(summed, metric='verify_own_vote_rx_total')
    in_udp = get_link_count(summed, metric='quic_txn_rx_total', link='udp')
    in_quic = get_link_count(summed, metric='quic_txn_rx_total', link='quic_fast') + get_link_count(summed, metric='quic_txn_rx_total', link='quic_frag')

    verify_overrun = get_link_count(summed, metric='link_frag_reading_overrun_total', link='quic_verify') + \
                     int(get_link_count(summed, metric='link_frag_polling_overrun_total', link='quic_verify') / 6)
    verify_failed = get_link_count(summed, metric='verify_txn_processed_total', link='signature_failed') + get_link_count(summed, metric='verify_txn_processed_total', link='bundle_peer_failed')
    verify_parse = get_link_count(summed, metric='verify_txn_processed_total', link='parse_failed')
    verify_dedup = get_link_count(summed, metric='verify_txn_processed_total', link='duplicate')

    dedup_dedup = get_link_count(summed, metric='dedup_txn_processed_total', link='duplicate') + get_link_count(summed, metric='dedup_txn_processed_total', link='bundle_peer_failed')

    resolv_failed = 0
    resolv_retained = 0
    for resolv in ('resolv', 'resolh'):
        resolv_failed += get_link_count(summed, metric=f'{resolv}_txn_dropped_total', link='blockhash_expired') + \
                         get_link_count(summed, metric=f'{resolv}_txn_dropped_total', link='no_bank') + \
                         get_link_count(summed, metric=f'{resolv}_txn_dropped_total', link='bundle_peer_failed') + \
                         get_link_count(summed, metric=f'{resolv}_txn_lut_resolve_attempted_total', link='account_not_found') + \
                         get_link_count(summed, metric=f'{resolv}_txn_lut_resolve_attempted_total', link='account_uninitialized') + \
                         get_link_count(summed, metric=f'{resolv}_txn_lut_resolve_attempted_total', link='invalid_account_data') + \
                         get_link_count(summed, metric=f'{resolv}_txn_lut_resolve_attempted_total', link='invalid_account_owner') + \
                         get_link_count(summed, metric=f'{resolv}_txn_lut_resolve_attempted_total', link='invalid_lookup_index') + \
                         get_link_count(summed, metric=f'{resolv}_stash_txn_removed_total', link='evicted')

        resolv_retained += get_link_count(summed, metric=f'{resolv}_stash_txn_inserted_total') - \
                           get_link_count(summed, metric=f'{resolv}_stash_txn_removed_total', link='evicted') - \
                           get_link_count(summed, metric=f'{resolv}_stash_txn_removed_total', link='published') - \
                           get_link_count(summed, metric=f'{resolv}_stash_txn_removed_total', link='failed')

    pack_cranked = get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='inserted') + \
                   get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='insertion_failed') + \
                   get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='creation_failed')

    pack_retained = sum(get_link_count(summed, metric='pack_txn_pending_used', link=t) for t in ('regular', 'vote', 'conflicting', 'bundle'))

    pack_leader_slow = get_link_count(summed, metric='pack_txn_insert_attempted_total', link='priority_too_low')

    pack_expired = get_link_count(summed, metric='pack_txn_dropped_total', link='expired') + \
                   get_link_count(summed, metric='pack_txn_evicted_total') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='expired') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='nonce_priority_too_low')

    pack_invalid_bundle = get_link_count(summed, metric='pack_txn_dropped_total', link='partial_bundle') + \
                          get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='insertion_failed') + \
                          get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='creation_failed')

    pack_invalid = get_link_count(summed, metric='pack_txn_insert_attempted_total', link='instr_too_many_accounts') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='nonce_conflict') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='bundle_blocklisted') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='invalid_nonce') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='write_sysvar') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='estimation_failed') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='duplicate_account') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='too_many_accounts') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='too_many_cu') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='lut_unsupported') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='unaffordable') + \
                   get_link_count(summed, metric='pack_txn_insert_attempted_total', link='duplicate') - \
                   get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='insertion_failed')

    bank_invalid = get_link_count(summed, metric='bank_txn_processed_by_landing_total', link='dropped') + \
                   get_link_count(summed, metric='execle_txn_processed_by_landing_total', link='dropped') + \
                   get_link_count(summed, metric='bank_txn_lut_resolve_attempted_total', link='account_not_found') + \
                   get_link_count(summed, metric='bank_txn_lut_resolve_attempted_total', link='account_uninitialized') + \
                   get_link_count(summed, metric='bank_txn_lut_resolve_attempted_total', link='invalid_account_data') + \
                   get_link_count(summed, metric='bank_txn_lut_resolve_attempted_total', link='invalid_account_owner') + \
                   get_link_count(summed, metric='bank_txn_lut_resolve_attempted_total', link='invalid_lookup_index')

    block_fail = 0
    block_success = 0
    for exec_tile in ('bank', 'execle'):
        block_fail += get_link_count(summed, metric=f'{exec_tile}_txn_processed_by_landing_total', link='failed') + \
                      get_link_count(summed, metric=f'{exec_tile}_txn_processed_by_landing_total', link='fees_only')
        block_success += get_link_count(summed, metric=f'{exec_tile}_txn_processed_by_landing_total', link='success')

    recon_verify_in = get_link_count(summed, metric='link_frag_consumed_total', link='quic_verify') + get_link_count(summed, metric='link_frag_consumed_total', link='bundle_verif')
    recon_verify_out = get_link_count(summed, metric='link_frag_consumed_total', link='verify_dedup')

    recon_dedup_in = get_link_count(summed, metric='link_frag_consumed_total', link='verify_dedup') + get_link_count(summed, metric='link_frag_consumed_total', link='gossip_dedup')
    recon_dedup_out = get_link_count(summed, metric='link_frag_consumed_total', link='dedup_resolv')

    recon_resolv_in = get_link_count(summed, metric='link_frag_consumed_total', link='dedup_resolv')
    recon_resolv_out = get_link_count(summed, metric='link_frag_consumed_total', link='resolv_pack')

    recon_pack_in = get_link_count(summed, metric='link_frag_consumed_total', link='resolv_pack') + get_link_count(summed, metric='pack_bundle_crank_attempted_total', link='inserted')
    recon_pack_out = get_link_count(summed, metric='link_frag_consumed_total', link='pack_bank', consumer='gui') # the gui only consumes txn frags on the pack_bank link, so we can use to for reconciling the pack_out count

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
