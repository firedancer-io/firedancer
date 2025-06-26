import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import sys
import warnings

"""
This script generates a report on repair analysis off of one testnet run.
1. Add the following to your testnet config.toml file:
    [tiles.shredcap]
       enabled = true
       folder_path = /my/folder

2. Start up firedancer-dev with the above config. The following files will be generated:
    - /my/folder/request_data.csv
    - /my/folder/shred_data.csv
    - /my/folder/fec_complete.csv

3. Run this script with the following command:
    python3 report.py <testnet.log path> <request_data.csv path> <shred_data.csv path> <fec_complete.csv path (optional, skips some long-running steps)>

    If you are missing dependencies, make sure to install them with:
    python3 -m pip install pandas numpy matplotlib seaborn

    (or manage the installations however you choose)

4. The report will be saved as report.pdf in the current directory.
"""

warnings.filterwarnings('ignore')

def match_repair_requests( requests, responses ):
    rsp = responses[responses['is_turbine'] == False]
    rsp = rsp.groupby('nonce').agg({'timestamp': 'min', 'slot':'first', 'idx':'max'}).reset_index()

    # check which nonces are in requests but not in responses
    matched = requests.merge(rsp, on='nonce', how='left', suffixes=('', '_rsp'))
    matched['is_matched'] = matched['timestamp_rsp'].notnull()

    return matched

def peer_stats( catchup, catchup_rq, live, live_rq, pdf ):
    print('\n\033[1mPeer response statistics\033[0m\n')

    matched = match_repair_requests(catchup_rq, catchup)

    print(f"Requests from {matched['dst_ip'].nunique()} unique peers this run")
    print(f"Recieved responses for {matched['is_matched'].sum()} out of {len(matched)} requests ({matched['is_matched'].mean() * 100:.2f}%)")

    #print missing idxs in slot_stalled
    print( 'Shreds recieved during catchup:', catchup.shape[0], 'and requests sent during catchup:', catchup_rq.shape[0])
    print( 'Shreds recieved during live turbine:', live.shape[0], 'and requests sent during live:', live_rq.shape[0])

    success_rate = matched.groupby('dst_ip').agg({'is_matched': 'mean', 'nonce': 'count'}).reset_index()

    # how many requests were sent to each responder?
    top_req_counts = matched.groupby('dst_ip').size().reset_index(name='count')
    print('Requests per pubkey: \n')
    describe = "\n".join('\t' + line for line in str(top_req_counts['count'].describe()).splitlines()[1:])
    print(describe)

    fig, axs = plt.subplots(2, 2, figsize=(15, 15))

    sns.histplot(data=top_req_counts, x='count', bins=40, ax=axs[0, 0])
    axs[0, 0].set_title('Histogram of requests per responder')
    axs[0, 0].set_xlabel('Number of requests sent')
    axs[0, 0].set_ylabel('Number of responders')

    # show success rate of the ones we spammed the most
    sns.barplot(data=success_rate.sort_values(by='nonce', ascending=False).head(40), x='dst_ip', y='is_matched', ax=axs[0, 1])
    axs[0, 1].set_xticklabels(axs[0, 1].get_xticklabels(), rotation=90)
    axs[0, 1].set_title('Success rate of the highest requested peers')
    axs[0, 1].set_ylabel('Success rate')
    axs[0, 1].set_xlabel('Responder pubkey')

    #histogram the success rates by responder
    sns.histplot(data=success_rate, x='is_matched', bins=50, ax=axs[1, 0])
    axs[1, 0].set_title('Histogram of success rates by responder')
    axs[1, 0].set_xlabel('Success rate')
    axs[1, 0].set_ylabel('Number of responders')

    least_successful = success_rate.sort_values(by='is_matched')
    least_successful = least_successful[least_successful['is_matched'] < 0.9]
    sns.barplot(data=least_successful, x='dst_ip', y='is_matched', ax=axs[1, 1])
    axs[1, 1].set_xticklabels(axs[1, 1].get_xticklabels(),  rotation=90)
    axs[1, 1].set_title('Least successful responders')
    axs[1, 1].set_ylabel('Success rate')

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # count how many never responded
    never_responded = success_rate[success_rate['is_matched'] == 0]
    print(f"\nPeers that never responded: {len(never_responded)} (made {never_responded['nonce'].sum()} requests)")

    ## Latency analysis
    top_latency = matched[matched['is_matched'] == True]
    top_latency['round_trip_latency'] = (top_latency['timestamp_rsp'] - top_latency['timestamp']) / 1000000  # convert to ms

    fig, (ax0, ax1) = plt.subplots(1, 2, figsize=(12, 6))
    # first plot the latencies
    sns.histplot(top_latency['round_trip_latency'], bins=100, ax=ax0)
    ax0.axvline(top_latency['round_trip_latency'].quantile(0.5), color='red', linestyle='--', label='50%')
    ax0.legend()
    ax0.set_title('Round trip latency of successful requests')
    ax0.set_xlabel('Latency (ms)')
    ax0.set_ylabel('Count')

    # zoom in on the first 100 ms
    sns.histplot(top_latency['round_trip_latency'], bins=100, binrange = (0, 100), ax=ax1)
    ax1.axvline(top_latency['round_trip_latency'].quantile(0.5), color='red', linestyle='--', label='50%')
    ax1.set_title('Round trip latency of successful requests (zoomed in)')
    ax1.set_xlabel('Latency (ms)')
    ax1.set_ylabel('Count')

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # plot latency boxplot per pubkey
    fig = plt.figure(figsize=(12, 6))
    top_latency_peers = top_latency.groupby('dst_ip').agg({'round_trip_latency': 'mean', 'nonce': 'count'}).reset_index()
    top_latency_peers = top_latency_peers.sort_values(by='round_trip_latency', ascending=True).reset_index(drop=True).head(1000)  # Limit to top 100 responders by latency
    sns.boxplot(data=top_latency_peers, x='dst_ip', y='round_trip_latency')
    plt.xticks(rotation=90)
    plt.title('Round trip latency per responder')
    plt.xlabel('Responder pubkey')
    plt.ylabel('Round trip latency (ms)')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()

def repair_performance( repair_requests, shreds_data, pdf ):
    print('\n\033[1mRepair performance\033[0m\n')

    # Calculate the time difference between request and response
    matched = match_repair_requests(repair_requests, shreds_data)
    matched['latency'] = (matched['timestamp_rsp'] - matched['timestamp']) / 1_000_000  # Convert to milliseconds

    # Filter out unmatched requests
    matched = matched[matched['is_matched']]

    # Plot the latency distribution
    plt.figure(figsize=(10, 6))
    sns.histplot(matched['latency'], bins=100, kde=True)
    plt.title('Latency Distribution of Repair Requests')
    plt.xlabel('Latency (ms)')
    plt.ylabel('Frequency')
    pdf.savefig(bbox_inches='tight')
    plt.close()

def execution_stats( log_path, pdf ):
    print('\n\033[1mExecution statistics\033[0m\n')
    first_turbine = None
    snapshot_slot = None
    last_executed = None

    snapshot_loaded_ts = None
    first_turbine_exec_ts = None

    # Open the log file and process it line by line
    with open(log_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        if 'First turbine slot' in line:
            first_turbine = int(line.split()[-1])
        elif 'snapshot slot' in line:
            tokens = line.split()
            snapshot_slot = int(tokens[-1])
            snapshot_loaded_ts = f'{tokens[1]} {tokens[2]}'

        if first_turbine and f'finished block - slot: {first_turbine}' in line:
            tokens = line.split()
            first_turbine_exec_ts = f'{tokens[1]} {tokens[2]}'
            break

    for line in lines[::-1]:  # Iterate in reverse to find the last matching line
        if 'finished block - slot:' in line:
            last_executed = int(line.split()[12][:-1])  # 13th word (index 12 in 0-based indexing)
            break

    # Output the extracted values
    print(f'snapshot_slot = {snapshot_slot}')
    print(f'first_turbine = {first_turbine}')
    print(f'last_executed = {last_executed}')

    if( not first_turbine_exec_ts ):
        print('Seems like first turbine was not executed, skipping time calculation.')
        return first_turbine, snapshot_slot, last_executed

    diff = pd.to_datetime(first_turbine_exec_ts, utc=True) - pd.to_datetime(snapshot_loaded_ts, utc=True)
    diff = diff.total_seconds()  # Convert to seconds
    print(f'Time from snapshot loaded to first turbine execution: {diff}s over {first_turbine - snapshot_slot} slots')
    return first_turbine, snapshot_slot, last_executed

def long_slots( slot_completion, shreds_data, first_turbine):
    print('\n\033[1mLong slots\033[0m\n')

    slot_completion = slot_completion.reset_index()
    long_slots = slot_completion[(slot_completion['time_slot_complete(ms)'] > 410) & (slot_completion['time_slot_complete(ms)'] < 500)]
    long_slots = long_slots[long_slots['slot'] >= first_turbine]
    print("\nSlots that took between 420 ms and 450 ms to complete:")

    for idx, row in long_slots.iterrows():
        print(f"Interested in slot {row['slot']} which took {row['time_slot_complete(ms)']} ms to complete")
        # count number of repair requests sent for this slot
        turbine = shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'])]
        print(f"Number of turbine shreds recieved for slot {idx}: {len(turbine)}")

        repairs = shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'] == False)]
        print(f"Number of repair shreds recieved for slot {idx}: {len(repairs)}")

    # find a correlation between repair requests, number of shreds, and time to complete?
    # Let's analyze the correlation between the number of repair requests, number of shreds, and time to complete for the long slots
    long_slots['num_repair_requests'] = long_slots['slot'].map(
        lambda slot: len(shreds_data[(shreds_data['slot'] == slot) & (shreds_data['is_turbine'] == False)])
    )
    long_slots['num_turbine_shreds'] = long_slots['slot'].map(
        lambda slot: len(shreds_data[(shreds_data['slot'] == slot) & (shreds_data['is_turbine'])])
    )


    long_slots['num_shreds_in_slot'] = long_slots['slot'].map(
        lambda slot: shreds_data[shreds_data['slot'] == slot]['idx'].nunique()
    )

    # Calculate the correlation matrix
    correlation_matrix = long_slots[['time_slot_complete(ms)', 'num_repair_requests', 'num_turbine_shreds', 'num_shreds_in_slot']].corr()
    # Plot the correlation matrix
    fig = plt.figure(figsize=(8, 6))
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt='.2f', square=True)
    plt.title('Correlation Matrix for Long Slots')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    #lets graph the shred arrival times for the long slots
    i = 0
    for idx, row in long_slots.iterrows():
        print(f"Interested in slot {row['slot']} which took {row['time_slot_complete(ms)']} ms to complete")
        # get the shreds for this slot
        shreds = shreds_data[shreds_data['slot'] == row['slot']]
        print(f"Number of shreds in slot {row['slot']}: {row['num_shreds_in_slot']}")

        # only take < time_slot_complete(ms) shreds
        shreds = shreds[shreds['timestamp'] <= row['timestamp_fec1']]
        # plot the timestamps of the shreds
        fig = plt.figure(figsize=(12, 6))
        sns.histplot(shreds['timestamp'], bins=50, kde=True)
        plt.title(f"Shred Arrival Times for Slot {row['slot']}")
        plt.xlabel('Timestamp')
        plt.ylabel('Frequency')

        #print what shred idx is  in the last bin
        last_bin = shreds['timestamp'].max()
        last_bin_idx = shreds[shreds['timestamp'] == last_bin]['idx'].values[0]
        print(f"Last shred idx in the last bin: {last_bin_idx}")

        plt.legend()
        pdf.savefig(fig, bbox_inches='tight')
        plt.close(fig)
        i += 1
        if i == 10:  # Limit to first 5 slots for clarity
            break

    offenders = []

    for idx, row in long_slots.iterrows():
        # get the shreds for this slot
        shreds = shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'] == True)]
        # only take shreds that came in after 400ms
        shreds = shreds[shreds['timestamp'] >= row['first_shred_ts_fec0'] + 400_000_000]  # 400ms in nanoseconds
        if len(shreds) > 0:
            offenders.append(shreds[['src_ip', 'timestamp', 'idx']])

    # Combine all offenders into a single DataFrame
    offenders_df = pd.concat(offenders, ignore_index=True)
    print(offenders_df.shape)
    offenders_df = offenders_df.groupby('src_ip').size().reset_index(name='count')
    print("\nOffenders who sent shreds after 400ms:")
    print(offenders_df)

    # bar plot the offenders by count, top 50 offenders first
    fig = plt.figure(figsize=(12, 6))
    sns.barplot(data=offenders_df.sort_values(by='count', ascending=False).head(50), x='src_ip', y='count', palette='viridis')
    plt.title('Top 50 Offenders by Count of Shreds Sent After 400ms')
    plt.xlabel('Hash Source')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()

    #bar plot the least offenders by count, bottom 50 offenders first
    fig = plt.figure(figsize=(12, 6))
    sns.barplot(data=offenders_df.sort_values(by='count', ascending=False).tail(50), x='src_ip', y='count', palette='viridis')
    plt.title('Bottom 50 Offenders by Count of Shreds Sent After 400ms')
    plt.xlabel('Hash Source')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # The top most offender is responsible for
    print(f"\nThe top most offender is responsible for {offenders_df['count'].max()} shreds sent after 400ms")

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # how many of these long slots are due to repair??? like from 400ms to the end of the slot, how many repair shreds are in that window?
    # for each long slot, count the number of repair shreds that came in after 400ms
    long_slots['num_repair_shreds_after_400ms'] = long_slots.apply(
        lambda row: len(shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'] == False) & (shreds_data['timestamp'] >= row['first_shred_ts_fec0'] + 400_000_000) & (shreds_data['timestamp'] <= row['timestamp_fec1'])]),
        axis=1
    )

    print(long_slots[['slot', 'num_repair_shreds_after_400ms']])


def completion_times( fec_stats, shred_data, first_turbine, pdf ):
    print('\n\033[1mFEC/Slot completion times\033[0m\n')

    # need to do some work to estimate when the first shred of the FEC set arrived
    # search through shred data and for each fec_set_idx find the first shred that matches the slot and idx

    sys.stdout.write('Currently matching fec to shred, may take a while...\r')
    sys.stdout.flush()

    fec_stats['first_shred_ts'] = fec_stats.apply(
        lambda row: shred_data[(shred_data['slot'] == row['slot']) & (shred_data['fec_set_idx'] == row['fec_set_idx'])]['timestamp'].min(),
        axis=1
    )
    sys.stdout.write('\033[K')
    sys.stdout.flush()

    fec_stats['time_to_complete'] = fec_stats['timestamp'] - fec_stats['first_shred_ts']
    fec_stats['time_to_complete(ms)'] = fec_stats['time_to_complete'] / 1_000_000  # Convert to milliseconds

    fec_stats_live = fec_stats[fec_stats['slot'] >= first_turbine]
    fec_stats_catchup = fec_stats[fec_stats['slot'] < first_turbine]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Plotting FEC completion times
    sns.histplot(fec_stats_live['time_to_complete(ms)'], bins=50, kde=True, ax=ax1)
    ax1.set_title('FEC Completion Times (Post First Turbine)')
    ax1.set_xlabel('Time to Complete (ms)')
    ax1.set_ylabel('Frequency')

    sns.histplot(fec_stats_catchup['time_to_complete(ms)'], bins=50, kde=True, ax=ax2)
    ax2.set_title('FEC Completion Times (Pre First Turbine)')
    ax2.set_xlabel('Time to Complete (ms)')
    ax2.set_ylabel('Frequency')
    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # Batch completion times (ref_tick)
    # We get this by keeping the first shred of fec0, and the completion time of fec1


    batch_stats = fec_stats.groupby(['slot', 'ref_tick']).agg({'first_shred_ts': 'min', 'timestamp': 'max'}).reset_index()
    batch_stats['time_to_complete'] = batch_stats['timestamp'] - batch_stats['first_shred_ts']
    batch_stats['time_to_complete(ms)'] = batch_stats['time_to_complete'] / 1_000_000  # Convert to milliseconds

    # plot the batch completion times
    fig = plt.figure(figsize=(12, 6))
    sns.histplot(batch_stats['time_to_complete(ms)'], bins=50, kde=True)
    plt.title('Batch Completion Times')
    plt.xlabel('Time to Complete (ms)')
    plt.ylabel('Frequency')
    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    batch_stats_live = batch_stats[batch_stats['slot'] >= first_turbine]
    batch_stats_catchup = batch_stats[batch_stats['slot'] < first_turbine]

    # Slot completion times

    fec_stats_dedup = fec_stats.drop_duplicates(subset=['slot', 'fec_set_idx'], keep='first')

    slot_completion = fec_stats_dedup.groupby('slot').apply( lambda slot: pd.concat( [ slot.iloc[0],
                                                                                    slot.iloc[-1]
                                                                                    ]))
    slot_completion.drop(columns=['slot', 'slot'], inplace=True)
    slot_completion.columns = ['timestamp_fec0', 'ref_tick_fec0', 'fec_set_idx_fec0', 'data_cnt_fec0', 'first_shred_ts_fec0',
        'time_to_complete_fec0', 'time_to_complete(ms)_fec0', 'timestamp_fec1',
        'ref_tick_fec1', 'fec_set_idx_fec1', 'data_cnt_fec1', 'first_shred_ts_fec1', 'time_to_complete_fec1',
        'time_to_complete(ms)_fec1']
    slot_completion['first_shred_in_slot'] = slot_completion.index.map( lambda slot: shred_data[shred_data['slot'] == slot]['timestamp'].min() )
    slot_completion['time_slot_complete(ms)'] = ( slot_completion['timestamp_fec1'] - slot_completion['first_shred_in_slot'] ) / 1_000_000  # Convert to milliseconds

    #plot slots in order
    plt.figure(figsize=(12, 6))
    plt.plot(slot_completion.index, slot_completion['time_slot_complete(ms)'], marker='o', color='b')
    # put a line at the first turbine slot
    plt.axvline(x=first_turbine, color='r', linestyle='--', label='First Turbine Slot')
    plt.legend()
    plt.title('Time to Complete per Slot')
    plt.xlabel('Slot')
    plt.ylabel('Time to Complete (ms)')
    plt.xticks(rotation=45)
    plt.grid()
    plt.tight_layout()
    pdf.savefig(bbox_inches='tight')
    plt.close()

    slot_cmpl_live = slot_completion[slot_completion.index >= first_turbine]
    slot_cmpl_catchup = slot_completion[slot_completion.index < first_turbine]

    print('Below times in milliseconds (ms)')
    print('{:<50} {:<50} {:<50}'.format('Live FEC Stats Summary', 'Live Batch Stats Summary', 'Live Slot Completion Summary'))
    live = zip(fec_stats_live['time_to_complete(ms)'].describe().to_string().splitlines(),
                 batch_stats_live['time_to_complete(ms)'].describe().to_string().splitlines(),
                 slot_cmpl_live['time_slot_complete(ms)'].describe().to_string().splitlines())
    for fec_line, batch_line, slot_line in live:
        print('{:<50} {:<50} {:<50}'.format(fec_line, batch_line, slot_line))

    print('{:<50} {:<50} {:<50}'.format('Catchup FEC Stats Summary', 'Catchup Batch Stats Summary', 'Catchup Slot Completion Summary'))
    catchup = zip(fec_stats_catchup['time_to_complete(ms)'].describe().to_string().splitlines(),
                  batch_stats_catchup['time_to_complete(ms)'].describe().to_string().splitlines(),
                  slot_cmpl_catchup['time_slot_complete(ms)'].describe().to_string().splitlines())
    for fec_line, batch_line, slot_line in catchup:
        print('{:<50} {:<50} {:<50}'.format(fec_line, batch_line, slot_line))

    # plot the batch completion times for a select slot.
    # I want stacked sideways interval charts for each ref_tick
    # the x axis is the time to complete
    # the y axis is the ref_tick
    # using hlines

    slot_interest = 100
    fig = plt.figure(figsize=(12, 6))
    for idx, row in batch_stats[batch_stats['slot'] == slot_interest].iterrows():
        # get the batch stats for this ref_tick
        plt.hlines(y=row['ref_tick'], xmin=row['first_shred_ts'], xmax=row['timestamp'], color='blue')
    plt.title(f'Batch Completion Times for Slot {slot_interest}')
    plt.xlabel('Time to Complete (ms)')
    plt.ylabel('Ref Tick')
    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)



def turbine_stats(catchup, live):
    print('\n\033[1mTurbine Statistics\033[0m\n')

    # how many shreds received during catchup are turbine shreds?
    num_turbine = catchup['is_turbine'].sum()
    print(f'Number of turbine shreds received for catchup slots (expected 0): {num_turbine} out of {len(catchup)} ({num_turbine / len(catchup) * 100:.2f}%)')
    if( num_turbine ):
        print('Turbine shreds recieved < first_turbine:', np.sort(catchup[catchup['is_turbine']]['slot'].unique() ) )
        print('If this is happening, it is likely that the stake weights are not propagating to the shred tile fast enough')

    num_turbine = live['is_turbine'].sum()
    print(f'Percentage of all shreds recieved through turbine for >first_turbine (expected closer to 100%): {num_turbine} out of {len(live)} ({num_turbine / len(live) * 100:.2f}%)')

    # Just because x% of turbine shreds were recieved as repair, doesn't
    # mean they weren't recieved as turbine shreds. Check how many are this case.

    live_turbine_shreds     = live[live['is_turbine']]
    live_turbine_shred_vals = set(live_turbine_shreds['shred'].values)
    true_live_repair_cnt = 0
    fake_live_repair_cnt = 0
    true_live_repair_shreds = []

    for _, repair_shred in live[live['is_turbine'] == False].iterrows():
        if repair_shred['shred'] in live_turbine_shred_vals:
            fake_live_repair_cnt += 1
        else:
            true_live_repair_shreds.append(repair_shred)
            true_live_repair_cnt += 1

    repaired_during_live = live[live['is_turbine'] == False]
    if( len(repaired_during_live) > 0 ):
        print(f'Number of live repair shreds that are duplicates with shreds recieved through turbine: {fake_live_repair_cnt} out of {len(repaired_during_live)} ({fake_live_repair_cnt / len(repaired_during_live) * 100:.2f}%)')
    true_live_repair_shreds = pd.DataFrame(true_live_repair_shreds)

def show_slot_repairs( repair, response, slot, pdf, max_idx=2**15, time_window=400): # in ms
    rq  = repair[repair['slot'] == slot]
    rsp = response[response['slot'] == slot]

    rq['timestamp'] = pd.to_datetime(rq['timestamp'])
    rsp['timestamp'] = pd.to_datetime(rsp['timestamp'])

    rq = rq[rq['idx'] < max_idx]

    time_slot_start = rq['timestamp'].min()
    time_slot_end   = time_slot_start + pd.Timedelta(milliseconds=time_window)

    rq = rq[rq['timestamp'] < time_slot_end]
    print(f'Number of repair requests sent for slot {slot} in {time_window}ms window: {len(rq)}')

    rsp = rsp[rsp['idx'] < max_idx]
    rsp = rsp[rsp['timestamp'] < time_slot_end]
    print(f'Number of shreds received for slot {slot} in {time_window}ms window: {len(rsp)}')

    fig, (ax1, ax2, ax3) = plt.subplots(1,3, figsize=(30,8))
    sns.scatterplot(data=rq, x='idx', y='timestamp', label='Repair Requests', color='orange', s=10, ax=ax1)
    sns.scatterplot(data=rsp, x='idx', y='timestamp', label='Shreds Received', color='blue', s=10, ax=ax1)

    # graph just min response and min request for each idx
    min_rsp = rsp.loc[rsp.groupby('idx')['timestamp'].idxmin()][['idx', 'timestamp', 'src_ip']]
    min_rq  = rq.loc[rq.groupby('idx')['timestamp'].idxmin()][['idx', 'timestamp', 'dst_ip']]
    sns.scatterplot(data=min_rsp, x='idx', y='timestamp', label='Min Shred Response', color='blue', s=20, ax=ax2)
    sns.scatterplot(data=rq, x='idx', y='timestamp', label='All Repair Request', color='orange', s=20, ax=ax2)

    sns.scatterplot(data=min_rsp, x='idx', y='timestamp', hue='src_ip', s=20, ax=ax3)
    sns.scatterplot(data=min_rq, x='idx', y='timestamp', hue='dst_ip', s=20, ax=ax3, marker='x')

    plt.title(f'Repair Requests and Shreds Received for Slot {slot}')
    plt.xlabel('idx')
    plt.ylabel('Timestamp')
    handles, labels = plt.gca().get_legend_handles_labels()
    plt.legend(handles[:3], labels[:3])
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

def print_slots(repair_requests, shreds_data, snapshot_slot, first_turbine, pdf ):
    print('\n\033[1mSpecific Slot Repair Analysis\033[0m\n')

    print(f'First slot after snapshot: {snapshot_slot + 1}')
    show_slot_repairs(repair_requests, shreds_data, snapshot_slot + 1 , pdf, max_idx=1000, time_window=8000)

    print(f'\nFirst slot after snapshot: {snapshot_slot + 1}')
    show_slot_repairs(repair_requests, shreds_data, snapshot_slot + 1 , pdf, max_idx=100, time_window=200)

    print(f'\nLast slot before first turbine: {first_turbine - 1}')
    show_slot_repairs(repair_requests, shreds_data, first_turbine - 1 , pdf, max_idx=1000, time_window=8000)

    print(f'\nFirst turbine slot: {first_turbine}')
    show_slot_repairs(repair_requests, shreds_data, first_turbine     , pdf, max_idx=100,  time_window=8000)

    print(f'\nFirst turbine slot + 50: {first_turbine + 50}')
    show_slot_repairs(repair_requests, shreds_data, first_turbine + 50, pdf, max_idx=100,  time_window=4000)

def generate_report( log_path, request_data_path, shred_data_path, peers_data_path, fec_complete_path=None, pdf=None ):
    """
    Generate a report based on the peer response data.

    Parameters:
    log_path (str): Path to the testnet log file.
    request_data_path (str): Path to the request data CSV file.
    shred_data_path (str): Path to the shred data CSV file.

    Returns:
    None
    """
    first_turbine, snapshot_slot, last_executed = execution_stats(log_path, pdf)

    # Load data sets
    sys.stdout.write('Reading in CSV files...\r')
    sys.stdout.flush()

    shreds_data     = pd.read_csv( shred_data_path,
                                   dtype={'src_ip': str, 'src_port': int, 'timestamp': int, 'slot': int, 'ref_tick': int, 'fec_set_idx':int, 'idx': int, 'is_turbine': bool, 'is_data': bool, 'nonce' :int },
                                   on_bad_lines='skip',
                                   skipfooter=1 ) # because of the buffered writer the last row is probably incomplete

    repair_requests = pd.read_csv( request_data_path,
                                   dtype={'dst_ip': str, 'dst_port': int, 'timestamp': int, 'slot': int, 'idx': int, 'nonce': int },
                                   skipfooter=1 )

    peers_data      = pd.read_csv( peers_data_path,
                                   dtype={'peer_ip4_addr': int, 'peer_port': int, 'pubkey':str, 'turbine': bool },
                                   on_bad_lines='skip',
                                   skipfooter=1 )

    # if we have a fec complete file, read it in
    if fec_complete_path:
        fec_stats   = pd.read_csv(fec_complete_path,
                                  dtype={'timestamp': int, 'slot': int, 'ref_tick': int, 'fec_set_idx': int, 'data_cnt': int },
                                  on_bad_lines='skip',
                                  skipfooter=1 )

    sys.stdout.write('\033[K')
    sys.stdout.flush()

    shreds_data['shred']      = shreds_data['slot'] + ( shreds_data['idx'] / 100 )
    #repair_requests['pubkey'] = repair_requests['pubkey'].str.slice(0, 8)           #shortening pubkey for better readability

    # There is a specific case where replay takes some time to propagate stake ci, and
    # the shred tile rejects many turbine shreds that could have been the 'first turbine'.
    # We first print the stats on these, but for the rest of the analysis we will
    # filter out the turbine shreds that were received before the first turbine slot.

    first_turbine_accept_ts = shreds_data[shreds_data['slot'] == first_turbine]['timestamp'].min()

    catchup = shreds_data[shreds_data['slot'].between(snapshot_slot, first_turbine - 1)]
    live    = shreds_data[shreds_data['slot'].between(first_turbine, last_executed)]

    catchup_rq = repair_requests[repair_requests['slot'].between(snapshot_slot, first_turbine - 1)]
    live_rq    = repair_requests[repair_requests['slot'].between(first_turbine, last_executed)]

    turbine_stats(catchup, live)

    catchup = catchup[catchup['timestamp'] >= first_turbine_accept_ts]  # only keep shreds that were accepted after the first turbine
    shreds_data = shreds_data[shreds_data['timestamp'] >= first_turbine_accept_ts]  # only keep shreds that were accepted after the first turbine
    peer_stats( catchup, catchup_rq, live, live_rq, pdf )

    if fec_complete_path:
        completion_times( fec_stats, shreds_data, first_turbine, pdf )

    print_slots(repair_requests, shreds_data, snapshot_slot, first_turbine, pdf)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print('Add: [tiles.shredcap] \n\t enabled = true \n\t folder_path = /my/folder_for_csv_dump \n to your testnet config.toml file to enable the report generation.')
        print('Usage: python report.py <testnet.log path> <request_data.csv path> <shred_data.csv path> <peers_data.csv> <fec_complete.csv path (optional)>')
        print('Report will automatically be saved as report.pdf in the current directory.')
        sys.exit(1)

    log_path          = sys.argv[1]
    request_data_path = sys.argv[2]
    shred_data_path   = sys.argv[3]
    peers_data_path   = sys.argv[4]
    fec_complete_path = sys.argv[5] if len(sys.argv) > 5 else None

    output_path = 'report.pdf'
    pdf = PdfPages('report.pdf')
    generate_report(log_path, request_data_path, shred_data_path, peers_data_path, fec_complete_path, pdf)
    print(f'Graphs generated at: {output_path}')

    pdf.close()
