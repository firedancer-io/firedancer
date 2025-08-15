import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import sys
import warnings
import os
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
    python3 report.py <testnet.log path> <csv_folder path>

    If you are missing dependencies, make sure to install them with:
    python3 -m pip install pandas numpy matplotlib seaborn

    (or manage the installations however you choose)

4. The report will be saved as report.pdf in the current directory.
"""

warnings.filterwarnings('ignore')

def create_title_page(pdf):
    """
    Creates a title page for the PDF report with explanation and credits
    """
    fig = plt.figure(figsize=(12, 8))
    fig.patch.set_facecolor('white')

    # Title
    plt.text(0.5, 0.92, 'Firedancer Shredcap Analysis Report',
             horizontalalignment='center',
             fontsize=22,
             fontweight='bold')

    # Subtitle
    plt.text(0.5, 0.85, 'This report analyzes repair mechanisms during validator catchup and live operation',
             horizontalalignment='center',
             fontsize=11,
             style='italic')

    # Analysis sections
    sections = [
        ('Slot Repair Time Analysis',
         'Timeline showing repair duration for each slot (use --turbine flag to include post-turbine slots)'),
        ('Peer Statistics Analysis (3 pages)',
         'Round-trip time distributions, hit rates, request patterns, and peer performance correlations'),
        ('Repair Efficiency Heatmap',
         'Visual analysis of repair efficiency: actual vs minimal required requests per shred'),
        ('Turbine Shred Timeline',
         'Normalized per-slot scatter plot showing turbine vs repair shreds timing within each slot'),
        ('FEC/Batch Completion Analysis',
         'Forward Error Correction timing and slot completion statistics'),
        ('Detailed Slot Analysis',
         'Microscopic view of repair patterns for critical transition slots')
    ]

    y_start = 0.72
    y_spacing = 0.08

    for i, (title, desc) in enumerate(sections):
        y_pos = y_start - (i * y_spacing)
        # Section title
        plt.text(0.5, y_pos, f'• {title}',
                 horizontalalignment='center',
                 fontsize=12,
                 fontweight='bold')
        # Section description
        plt.text(0.5, y_pos - 0.025, desc,
                 horizontalalignment='center',
                 fontsize=10,
                 style='italic')

    plt.text(0.5, 0.17, 'Data collected from CSV files generated with shredcap tile enabled during testnet execution.',
             horizontalalignment='center',
             fontsize=9,
             style='italic')
    plt.text(0.5, 0.10, 'Developed by: Emily Wang and Nishk Patel',
             horizontalalignment='center',
             fontsize=10)

    from datetime import datetime
    current_date_time_timezone = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    plt.text(0.5, 0.05, f'Generated on: {current_date_time_timezone}',
             horizontalalignment='center',
             fontsize=10)

    plt.axis('off')

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)



def execution_stats( log_path, pdf ):
    print('\n\033[1mExecution statistics\033[0m\n')

    # Initialize variables to capture key execution timeline markers
    first_turbine = None
    snapshot_slot = None
    last_executed = None
    snapshot_loaded_ts = None
    first_turbine_exec_ts = None

    # Read entire log file into memory for parsing
    with open(log_path, 'r') as file:
        lines = file.readlines()

    # Parse log file forward to extract snapshot and first turbine information
    # Look for specific log patterns that indicate key execution events
    for line in lines:
        if 'First turbine slot' in line:
            first_turbine = int(line.split()[-1])
        elif 'snapshot slot' in line:
            tokens = line.split()
            snapshot_slot = int(tokens[-1])
            snapshot_loaded_ts = f'{tokens[1]} {tokens[2]}'

        # Once we find the first turbine slot, look for its actual execution timestamp
        if first_turbine and f'slot: {first_turbine}' in line:
            tokens = line.split()
            first_turbine_exec_ts = f'{tokens[1]} {tokens[2]}'
            break

    # Parse log file backward to find the last executed slot efficiently
    for line in lines[::-1]:
        if 'slot:' in line:
            import re
            match = re.search(r'slot:\s*(\d+)', line)
            if match:
                last_executed = int(match.group(1))
            break

    # Handle cases where automatic log parsing failed - fallback to user input
    if snapshot_slot is None:
        snapshot_slot = int(input('Couldn\'t find snapshot slot in log, please enter it manually: '))

    if first_turbine is None:
        first_turbine = input('Couldn\'t find first turbine slot in log, please enter it manually: ')

    if last_executed is None:
        last_executed = int(input('Couldn\'t find last executed slot in log, please enter it manually: '))

    # Display extracted execution timeline information
    print(f'snapshot_slot = {snapshot_slot}')
    print(f'first_turbine = {first_turbine}')
    print(f'last_executed = {last_executed}')

    # Calculate timing between snapshot load and first turbine execution if timestamps available
    if( not first_turbine_exec_ts ):
        print('Seems like first turbine was not executed, skipping time calculation.')
        return first_turbine, snapshot_slot, last_executed

    diff = pd.to_datetime(first_turbine_exec_ts, utc=True) - pd.to_datetime(snapshot_loaded_ts, utc=True)
    diff = diff.total_seconds()
    print(f'Time from snapshot loaded to first turbine execution: {diff}s over {first_turbine - snapshot_slot} slots')
    return first_turbine, snapshot_slot, last_executed

def long_slots( slot_completion, shreds_data, first_turbine):
    print('\n\033[1mLong slots\033[0m\n')

    # Filter to identify problematic slots that take between 410-500ms to complete
    # Focus on live slots (after first turbine) where this timing indicates issues
    slot_completion = slot_completion.reset_index()
    long_slots = slot_completion[(slot_completion['time_slot_complete(ms)'] > 410) & (slot_completion['time_slot_complete(ms)'] < 500)]
    long_slots = long_slots[long_slots['slot'] >= first_turbine]
    print("\nSlots that took between 420 ms and 450 ms to complete:")

    # Print basic statistics for each identified long slot
    for idx, row in long_slots.iterrows():
        print(f"Interested in slot {row['slot']} which took {row['time_slot_complete(ms)']} ms to complete")

        turbine = shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'])]
        print(f"Number of turbine shreds received for slot {idx}: {len(turbine)}")

        repairs = shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'] == False)]
        print(f"Number of repair shreds received for slot {idx}: {len(repairs)}")

    # Calculate correlation metrics for long slots analysis
    # Map each long slot to various shred count metrics to understand delay patterns
    long_slots['num_repair_requests'] = long_slots['slot'].map(
        lambda slot: len(shreds_data[(shreds_data['slot'] == slot) & (shreds_data['is_turbine'] == False)])
    )
    long_slots['num_turbine_shreds'] = long_slots['slot'].map(
        lambda slot: len(shreds_data[(shreds_data['slot'] == slot) & (shreds_data['is_turbine'])])
    )
    long_slots['num_shreds_in_slot'] = long_slots['slot'].map(
        lambda slot: shreds_data[shreds_data['slot'] == slot]['idx'].nunique()
    )

    # Generate correlation matrix heatmap to visualize relationships between metrics
    correlation_matrix = long_slots[['time_slot_complete(ms)', 'num_repair_requests', 'num_turbine_shreds', 'num_shreds_in_slot']].corr()

    fig = plt.figure(figsize=(8, 6))
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt='.2f', square=True)
    plt.title('Correlation Matrix for Long Slots')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # Generate detailed shred arrival timing histograms for individual long slots
    # Limited to first 10 slots to keep report manageable
    i = 0
    for idx, row in long_slots.iterrows():
        print(f"Interested in slot {row['slot']} which took {row['time_slot_complete(ms)']} ms to complete")

        shreds = shreds_data[shreds_data['slot'] == row['slot']]
        print(f"Number of shreds in slot {row['slot']}: {row['num_shreds_in_slot']}")

        # Filter to shreds that arrived before slot completion
        shreds = shreds[shreds['timestamp'] <= row['timestamp_fec1']]

        # Create arrival time distribution plot
        fig = plt.figure(figsize=(12, 6))
        sns.histplot(shreds['timestamp'], bins=50, kde=True)
        plt.title(f"Shred Arrival Times for Slot {row['slot']}")
        plt.xlabel('Timestamp')
        plt.ylabel('Frequency')

        # Identify the latest arriving shred for analysis
        last_bin = shreds['timestamp'].max()
        last_bin_idx = shreds[shreds['timestamp'] == last_bin]['idx'].values[0]
        print(f"Last shred idx in the last bin: {last_bin_idx}")

        plt.legend()
        pdf.savefig(fig, bbox_inches='tight')
        plt.close(fig)
        i += 1
        if i == 10:
            break

    # Identify "offender" sources that send shreds very late (after 400ms mark)
    # These late arrivals may contribute to slot completion delays
    offenders = []

    for idx, row in long_slots.iterrows():
        shreds = shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'] == True)]
        # Filter to shreds arriving after 400ms threshold (400ms = 400,000,000 nanoseconds)
        shreds = shreds[shreds['timestamp'] >= row['first_shred_ts_fec0'] + 400_000_000]
        if len(shreds) > 0:
            offenders.append(shreds[['src_ip', 'timestamp', 'idx']])

    # Analyze and visualize offender patterns
    if offenders:
        offenders_df = pd.concat(offenders, ignore_index=True)
        print(offenders_df.shape)
        offenders_df = offenders_df.groupby('src_ip').size().reset_index(name='count')
        print("\nOffenders who sent shreds after 400ms:")
        print(offenders_df)

        # Generate bar plots showing top and bottom offenders by frequency
        fig = plt.figure(figsize=(12, 6))
        sns.barplot(data=offenders_df.sort_values(by='count', ascending=False).head(50), x='src_ip', y='count', palette='viridis')
        plt.title('Top 50 Offenders by Count of Shreds Sent After 400ms')
        plt.xlabel('Hash Source')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()

        fig = plt.figure(figsize=(12, 6))
        sns.barplot(data=offenders_df.sort_values(by='count', ascending=False).tail(50), x='src_ip', y='count', palette='viridis')
        plt.title('Bottom 50 Offenders by Count of Shreds Sent After 400ms')
        plt.xlabel('Hash Source')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()

        print(f"\nThe top most offender is responsible for {offenders_df['count'].max()} shreds sent after 400ms")

        pdf.savefig(fig, bbox_inches='tight')
        plt.close(fig)

    # Calculate repair shred impact on long slots
    # Count repair shreds arriving in the critical 400ms-to-completion window
    long_slots['num_repair_shreds_after_400ms'] = long_slots.apply(
        lambda row: len(shreds_data[(shreds_data['slot'] == row['slot']) & (shreds_data['is_turbine'] == False) & (shreds_data['timestamp'] >= row['first_shred_ts_fec0'] + 400_000_000) & (shreds_data['timestamp'] <= row['timestamp_fec1'])]),
        axis=1
    )

    print(long_slots[['slot', 'num_repair_shreds_after_400ms']])

def completion_times( fec_stats, shred_data, first_turbine, pdf ):
    print('\n\033[1mFEC/Slot completion times\033[0m\n')

    # Calculate first shred timestamps for each FEC set by matching with shred data
    # This computation can be slow for large datasets, so show progress indicator
    sys.stdout.write('Currently matching fec to shred, may take a while...\r')
    sys.stdout.flush()

    fec_stats['first_shred_ts'] = fec_stats.apply(
        lambda row: shred_data[(shred_data['slot'] == row['slot']) & (shred_data['fec_set_idx'] == row['fec_set_idx'])]['timestamp'].min(),
        axis=1
    )
    sys.stdout.write('\033[K')
    sys.stdout.flush()

    # Calculate FEC completion times and convert to milliseconds
    fec_stats['time_to_complete'] = fec_stats['timestamp'] - fec_stats['first_shred_ts']
    fec_stats['time_to_complete(ms)'] = fec_stats['time_to_complete'] / 1_000_000

    # Split FEC statistics by execution phase (live vs catchup period)
    fec_stats_live = fec_stats[fec_stats['slot'] >= first_turbine]
    fec_stats_catchup = fec_stats[fec_stats['slot'] < first_turbine]

    # Generate FEC completion time distribution histograms for both phases
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

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



    # Calculate slot-level completion times from FEC data
    # Combine first and last FEC completion within each slot
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
    slot_completion['time_slot_complete(ms)'] = ( slot_completion['timestamp_fec1'] - slot_completion['first_shred_in_slot'] ) / 1_000_000

    # Split slot completion data by execution phase
    slot_cmpl_live = slot_completion[slot_completion.index >= first_turbine]
    slot_cmpl_catchup = slot_completion[slot_completion.index < first_turbine]

    # Generate comprehensive summary statistics tables
    # Display side-by-side comparison of FEC and slot-level timing statistics
    print('Below times in milliseconds (ms)')
    print('{:<50} {:<50}'.format('Live FEC Stats Summary', 'Live Slot Completion Summary'))
    live = zip(fec_stats_live['time_to_complete(ms)'].describe().to_string().splitlines(),
                 slot_cmpl_live['time_slot_complete(ms)'].describe().to_string().splitlines())
    for fec_line, slot_line in live:
        print('{:<50} {:<50}'.format(fec_line, slot_line))

    print('{:<50} {:<50}'.format('Catchup FEC Stats Summary', 'Catchup Slot Completion Summary'))
    catchup = zip(fec_stats_catchup['time_to_complete(ms)'].describe().to_string().splitlines(),
                  slot_cmpl_catchup['time_slot_complete(ms)'].describe().to_string().splitlines())
    for fec_line, slot_line in catchup:
        print('{:<50} {:<50}'.format(fec_line, slot_line))



def turbine_stats(catchup, live):
    print('\n\033[1mTurbine Statistics\033[0m\n')

    # Analyze turbine shreds during catchup period - should be zero
    # Any turbine shreds during catchup indicate stake weight propagation issues
    num_turbine = catchup['is_turbine'].sum()
    print(f'Number of turbine shreds received for catchup slots (expected 0): {num_turbine} out of {len(catchup)} ({num_turbine / len(catchup) * 100:.2f}%)')
    if( num_turbine ):
        print('Turbine shreds received < first_turbine:', np.sort(catchup[catchup['is_turbine']]['slot'].unique() ) )
        print('If this is happening, it is likely that the stake weights are not propagating to the shred tile fast enough')

    # Analyze turbine shreds during live period - should be close to 100%
    num_turbine = live['is_turbine'].sum()
    print(f'Percentage of all shreds received through turbine for >first_turbine (expected closer to 100%): {num_turbine} out of {len(live)} ({num_turbine / len(live) * 100:.2f}%)')

    # Identify duplicate shreds: those received both through turbine and repair
    # This analysis distinguishes true repairs from redundant repair requests
    live_turbine_shreds     = live[live['is_turbine']]
    live_turbine_shred_vals = set(live_turbine_shreds['shred'].values)
    true_live_repair_cnt = 0
    fake_live_repair_cnt = 0
    true_live_repair_shreds = []

    # Classify each repair shred as true repair or duplicate of turbine shred
    for _, repair_shred in live[live['is_turbine'] == False].iterrows():
        if repair_shred['shred'] in live_turbine_shred_vals:
            fake_live_repair_cnt += 1
        else:
            true_live_repair_shreds.append(repair_shred)
            true_live_repair_cnt += 1

    # Report duplicate analysis results
    repaired_during_live = live[live['is_turbine'] == False]
    if( len(repaired_during_live) > 0 ):
        print(f'Number of live repair shreds that are duplicates with shreds received through turbine: {fake_live_repair_cnt} out of {len(repaired_during_live)} ({fake_live_repair_cnt / len(repaired_during_live) * 100:.2f}%)')
    true_live_repair_shreds = pd.DataFrame(true_live_repair_shreds)

def turbine_shred_timeline(shreds_data, first_turbine, pdf):
    """
    Track turbine vs repair shreds over time with scatter plot
    Blue dots = turbine shreds, Green dots = repair shreds
    """
    print('\n\033[1mTurbine Shred Timeline Analysis\033[0m\n')

    # live slots (>= first_turbine) where turbine should be active
    live_data = shreds_data[shreds_data['slot'] >= first_turbine].copy()

    if live_data.empty:
        print("No live data found for turbine analysis")
        return

    turbine_shreds = live_data[live_data['is_turbine'] == True]
    repair_shreds = live_data[live_data['is_turbine'] == False]

    print(f"Analyzing {len(turbine_shreds):,} turbine shreds and {len(repair_shreds):,} repair shreds")
    print(f"Slot range: {live_data['slot'].min()} to {live_data['slot'].max()}")

    print("Creating normalized per-slot timeline...")

    live_data_normalized = live_data.copy()

    slot_start_times = live_data.groupby('slot')['timestamp'].min()
    live_data_normalized['slot_relative_time_ms'] = live_data_normalized.apply(
        lambda row: (row['timestamp'] - slot_start_times[row['slot']]) / 1_000_000,
        axis=1
    )

    # Separate turbine and repair shreds for normalized view
    turbine_norm = live_data_normalized[live_data_normalized['is_turbine'] == True]
    repair_norm = live_data_normalized[live_data_normalized['is_turbine'] == False]

    # Create the normalized scatter plot
    fig, ax = plt.subplots(figsize=(20, 12))

    # Plot turbine shreds (blue)
    if not turbine_norm.empty:
        ax.scatter(turbine_norm['slot'], turbine_norm['slot_relative_time_ms'],
                  c='blue', s=1, alpha=0.6, label=f'Turbine Shreds ({len(turbine_norm):,})')

    # Plot repair shreds (green)
    if not repair_norm.empty:
        ax.scatter(repair_norm['slot'], repair_norm['slot_relative_time_ms'],
                  c='red', s=1, alpha=0.8, label=f'Repair Shreds ({len(repair_norm):,})')

    # Formatting
    ax.set_xlabel('Slot Number', fontsize=16)
    ax.set_ylabel('Time from Slot Start (ms)', fontsize=16)
    ax.set_title('Turbine vs Repair Shreds - Normalized per Slot\n(Blue = Turbine, Green = Repair, Each Slot Starts at 0ms)', fontsize=20)
    ax.legend(fontsize=12)
    ax.grid(True, alpha=0.3)

    slot_range = live_data['slot'].max() - live_data['slot'].min()
    if slot_range > 1000:
        # For large slot ranges, show first and last 500 slots
        first_500_start = first_turbine
        last_500_end = live_data['slot'].max()
        ax.set_xlim(first_500_start, last_500_end)

    max_slot_time = live_data_normalized['slot_relative_time_ms'].quantile(0.95)
    if max_slot_time > 0:
        ax.set_ylim(0, min(max_slot_time * 1.1, 2000))

    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    if not live_data_normalized.empty:
        print(f"\nSlot Timing Statistics (normalized):")
        print(f"  Average slot duration: {live_data_normalized.groupby('slot')['slot_relative_time_ms'].max().mean():.1f} ms")
        print(f"  Median slot duration: {live_data_normalized.groupby('slot')['slot_relative_time_ms'].max().median():.1f} ms")
        print(f"  95th percentile slot duration: {live_data_normalized.groupby('slot')['slot_relative_time_ms'].max().quantile(0.95):.1f} ms")

    if not turbine_shreds.empty and not repair_shreds.empty:
        print(f"\nTurbine Shred Statistics:")
        print(f"  Total turbine shreds: {len(turbine_shreds):,}")
        print(f"  Slots with turbine shreds: {turbine_shreds['slot'].nunique():,}")
        print(f"  Average turbine shreds per slot: {len(turbine_shreds) / turbine_shreds['slot'].nunique():.1f}")

        print(f"\nRepair Shred Statistics:")
        print(f"  Total repair shreds: {len(repair_shreds):,}")
        print(f"  Slots with repair shreds: {repair_shreds['slot'].nunique():,}")
        print(f"  Average repair shreds per slot: {len(repair_shreds) / repair_shreds['slot'].nunique():.1f}")

        total_shreds = len(turbine_shreds) + len(repair_shreds)
        repair_rate = len(repair_shreds) / total_shreds * 100
        print(f"\nOverall repair rate: {repair_rate:.2f}% ({len(repair_shreds):,} repairs out of {total_shreds:,} total shreds)")

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

def slot_request_rate_analysis(shreds_data, first_turbine, pdf, include_after_turbine=False):
    """
    Analyze slot request rates and processing times, showing first non-orphan response markers.
    Adapted from slot_request_rate.py to work with report.py structures.
    """
    print('\n\033[1mSlot Request Rate Analysis\033[0m\n')

    # data vis similar to slot_request_rate.py
    turbine_slot_start_time = shreds_data[shreds_data['slot'] == first_turbine]['timestamp'].min()
    if pd.isna(turbine_slot_start_time):
        print(f"Warning: No data found for turbine slot {first_turbine}")
        return

    print(f"First occurrence of turbine slot {first_turbine} at timestamp {turbine_slot_start_time}")

    df_filtered = shreds_data[(shreds_data['slot'] != 0) &
                             (shreds_data['timestamp'] >= turbine_slot_start_time)]

    if 'is_turbine' in df_filtered.columns:
        df_filtered = df_filtered[~((df_filtered['is_turbine'] == True) & (df_filtered['slot'] < first_turbine))]

    slot_timestamps = {}

    for slot, group in df_filtered.groupby('slot'):
        first_timestamp = group['timestamp'].min()

        group_sorted = group.sort_values('timestamp')

        # last unique shred timestamp
        is_first_occurrence = ~group_sorted.duplicated(subset=['idx'], keep='first')
        unique_shred_timestamps = group_sorted.loc[is_first_occurrence, 'timestamp']
        last_unique_timestamp = unique_shred_timestamps.max() if not unique_shred_timestamps.empty else first_timestamp

        first_non_orphan_timestamp = None
        if not group_sorted.empty:
            first_idx = group_sorted.iloc[0]['idx']
            non_orphan_mask = group_sorted['idx'] != first_idx
            if non_orphan_mask.any():
                first_non_orphan_timestamp = group_sorted.loc[non_orphan_mask, 'timestamp'].iloc[0]

        slot_timestamps[slot] = {
            'first_shred': first_timestamp,
            'slot_complete': last_unique_timestamp,
            'first_non_orphan': first_non_orphan_timestamp
        }

    if not slot_timestamps:
        print("No valid timestamps found in shred data.")
        return

        print(f"Smallest slot number: {min(slot_timestamps.keys())}")
    print(f"Largest slot number: {max(slot_timestamps.keys())}")

    # turbine filtering
    if not include_after_turbine:
        # default: exclude slots >= turbine_slot
        print(f"Default mode: excluding slots >= {first_turbine}")
        slot_timestamps = {
            slot_num: timestamps for slot_num, timestamps in slot_timestamps.items()
            if slot_num < first_turbine
        }
    else:
        # With --turbine flag: include all slots (no additional filtering needed)
        print(f"Turbine mode: including all slots from turbine slot {first_turbine} onwards")

    if not slot_timestamps:
        print(f"No slots found with the current filtering criteria")
        return

    time_differences = []
    for slot_num, timestamps in slot_timestamps.items():
        first_shred_time = timestamps['first_shred']
        slot_complete_time = timestamps['slot_complete']
        if first_shred_time is not None and slot_complete_time is not None:
            time_diff = slot_complete_time - first_shred_time
            time_differences.append((slot_num, time_diff))

    if not time_differences:
        print("No matching slot timestamps found to compute differences.")
        return

    time_differences.sort(key=lambda x: x[0])
    # create valid slots data for calculations and plotting
    valid_slots = []
    for slot_num, timestamps in slot_timestamps.items():
        if timestamps['first_shred'] is not None and timestamps['slot_complete'] is not None:
            valid_slots.append({
                'shred_num': slot_num,
                'start': timestamps['first_shred'],
                'end': timestamps['slot_complete'],
                'first_non_orphan': timestamps['first_non_orphan']
            })
    valid_slots.sort(key=lambda x: x['shred_num'])

    avg_time_per_slot_ns = sum(diff for _, diff in time_differences) / len(time_differences)
    print(f"Average processing time between slots: {avg_time_per_slot_ns / 1e6:.2f} milliseconds")

    # average time between slots
    if len(valid_slots) >= 2:
        completion_diffs = []
        for i in range(1, len(valid_slots)):
            diff = valid_slots[i]['end'] - valid_slots[i-1]['end']
            completion_diffs.append(diff)
        avg_time_between_slots_ns = sum(completion_diffs) / len(completion_diffs) if completion_diffs else 0
    else:
        avg_time_between_slots_ns = 0

    print(f"Time to repair between slots: {avg_time_between_slots_ns / 1e6:.2f} milliseconds")

    if not valid_slots:
        print("No time intervals to plot.")
        return

    shred_nums = [s['shred_num'] for s in valid_slots]
    start_times_ns = [s['start'] for s in valid_slots]
    end_times_ns = [s['end'] for s in valid_slots]

    # Extract first non-orphan timestamps (only for slots before turbine)
    first_non_orphan_times_ns = []
    first_non_orphan_slot_nums = []
    for s in valid_slots:
        if s['first_non_orphan'] is not None and s['shred_num'] < first_turbine:
            first_non_orphan_times_ns.append(s['first_non_orphan'])
            first_non_orphan_slot_nums.append(s['shred_num'])

    # convert/normalize timestamps
    min_start_time_ns = min(start_times_ns) if start_times_ns else 0
    start_times_ms = [(t - min_start_time_ns) / 1e6 for t in start_times_ns]
    end_times_ms = [(t - min_start_time_ns) / 1e6 for t in end_times_ns]
    first_non_orphan_times_ms = [(t - min_start_time_ns) / 1e6 for t in first_non_orphan_times_ns]

    # Create the plot - MUCH LARGER than other pages
    fig, ax = plt.subplots(figsize=(28, 18))

    first_non_orphan_lookup = dict(zip(first_non_orphan_slot_nums, first_non_orphan_times_ms))

    for slot_num, start_ms, end_ms in zip(shred_nums, start_times_ms, end_times_ms):
        if slot_num in first_non_orphan_lookup:
            first_non_orphan_ms = first_non_orphan_lookup[slot_num]

            # slot has first non-orphan response - draw two segments, dark for actual repair, light for time after first orphan
            ax.vlines(slot_num, start_ms, first_non_orphan_ms, color='b', alpha=0.3, linewidth=3)

            ax.vlines(slot_num, first_non_orphan_ms, end_ms, color='b', alpha=0.8, linewidth=3)
        else:
            ax.vlines(slot_num, start_ms, end_ms, color='b', alpha=0.8, linewidth=3)

    ax.plot([], [], color='b', alpha=0.8, linewidth=3, label='Slot Processing Time')

    ax.scatter(shred_nums, start_times_ms, color='green', s=20, zorder=5, label='Slot Start Times')
    ax.scatter(shred_nums, end_times_ms, color='red', s=20, zorder=5, label='Slot End Times')

    if first_non_orphan_slot_nums:
        ax.scatter(first_non_orphan_slot_nums, first_non_orphan_times_ms, color='darkorange', s=20, zorder=6,
                  marker='D', edgecolors='black', linewidths=2, label='First Non-Orphan Response')

    ax.set_xlabel('Slot Number', fontsize=28)
    ax.set_ylabel('Time (milliseconds from first slot start)', fontsize=28)
    ax.set_title('Slot Processing Time Intervals', fontsize=36)
    ax.legend(fontsize=24)

    x_min, x_max = ax.get_xlim()
    y_min, y_max = ax.get_ylim()

    from matplotlib.ticker import MultipleLocator, AutoMinorLocator

    ax.xaxis.set_major_locator(MultipleLocator(5))
    ax.xaxis.set_minor_locator(MultipleLocator(1))

    y_range = y_max - y_min
    y_major_spacing = y_range / 100
    ax.yaxis.set_major_locator(MultipleLocator(y_major_spacing))
    ax.yaxis.set_minor_locator(AutoMinorLocator(5))

    ax.grid(True, which='major', alpha=0.5, linewidth=0.5)
    ax.grid(True, which='minor', alpha=0.2, linewidth=0.25)

    ax.tick_params(axis='both', which='major', labelsize=10)
    ax.tick_params(axis='both', which='minor', labelsize=8)

    # stats text
    avg_text = (f"Average processing time between slots: {avg_time_per_slot_ns / 1e6:.2f} ms\n"
                f"Time to repair between slots: {avg_time_between_slots_ns / 1e6:.2f} ms")
    ax.text(0.05, 0.95, avg_text, transform=ax.transAxes, fontsize=20,
             verticalalignment='top', bbox=dict(boxstyle='round', facecolor='gray', alpha=0.5))

    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

def int_to_ip(ip_int):
    """Convert integer IP address to dotted decimal notation."""
    try:
        if isinstance(ip_int, str):
            if '.' in ip_int:
                return ip_int
            ip_int = int(ip_int)

        return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"
    except (ValueError, TypeError):
        # if conversion fails, return the original value
        return str(ip_int)

def peer_stats_analysis(repair_requests, shreds_data, pdf):
    """
    Comprehensive peer statistics analysis across 3 pages.
    Optimized with vectorized operations for performance.
    """
    print('\n\033[1mPeer Statistics Analysis\033[0m\n')

    # Validate input data availability before proceeding with analysis
    if repair_requests is None or repair_requests.empty:
        print("No repair request data available for peer analysis")
        return

    if shreds_data is None or shreds_data.empty:
        print("No shred data available for peer analysis")
        return

    print("Preparing peer statistics data...")

        # Data cleaning: filter out invalid slots and standardize timestamp format
    # Pre-filter both datasets for slot != 0 using vectorized operations for performance
    if 'slot' in repair_requests.columns:
        repair_requests = repair_requests.query('slot != 0').copy()
    else:
        repair_requests = repair_requests.copy()

    if 'slot' in shreds_data.columns:
        shreds_data = shreds_data.query('slot != 0').copy()
    else:
        shreds_data = shreds_data.copy()

    # Timestamp normalization: convert nanoseconds to milliseconds if needed
    ts_scale = 1e6 if repair_requests['timestamp'].iloc[0] > 1e12 else 1
    if ts_scale > 1:
        repair_requests['timestamp'] /= ts_scale
        shreds_data['timestamp'] /= ts_scale

    # Core RTT calculation: merge request and response data by nonce
    # Single comprehensive merge optimizes performance over multiple smaller merges
    comprehensive_merge = pd.merge(
        repair_requests[['nonce', 'timestamp', 'dst_ip']],
        shreds_data[['nonce', 'timestamp']],
        on='nonce',
        suffixes=('_req', '_shred'),
        how='inner'
    )

    # Calculate round-trip times and filter out invalid negative values
    comprehensive_merge['round_trip_time_ms'] = comprehensive_merge['timestamp_shred'] - comprehensive_merge['timestamp_req']
    valid_rtt_data = comprehensive_merge.query('round_trip_time_ms >= 0')

    # Peer performance metrics calculation using vectorized aggregations
    peer_metrics = valid_rtt_data.groupby('dst_ip').agg({
        'round_trip_time_ms': ['mean', 'median', 'count'],
        'nonce': 'count'
    }).round(3)

    # Flatten column hierarchy for easier access
    peer_metrics.columns = ['avg_rtt', 'median_rtt', 'rtt_count', 'total_responses']

    # Calculate hit rates: successful responses vs total requests per peer
    total_requests = repair_requests['dst_ip'].value_counts()
    unique_successful_requests = valid_rtt_data.drop_duplicates(subset=['nonce', 'dst_ip'])
    successful_responses = unique_successful_requests['dst_ip'].value_counts()
    hit_rates = (successful_responses / total_requests).fillna(0)

    # Prepare data series for visualization
    round_trip_times = valid_rtt_data['round_trip_time_ms']
    avg_rtt_per_peer = peer_metrics['avg_rtt']
    median_rtt_per_peer = peer_metrics['median_rtt']
    reqs_per_ip = total_requests

    # PAGE 1: RTT Analysis
    # 1. RTT Distribution with outliers

    # Create figure with gridspec for 2,2,1 layout
    fig = plt.figure(figsize=(24, 16))
    gs = fig.add_gridspec(3, 2, height_ratios=[1, 1, 0.8], hspace=0.5)
    fig.suptitle('Round-Trip Time Analysis', fontsize=32)

    # Create axes for the 2x2 grid
    ax1 = fig.add_subplot(gs[0, 0])  # Top left
    ax2 = fig.add_subplot(gs[0, 1])  # Top right
    ax3 = fig.add_subplot(gs[1, 0])  # Bottom left
    ax4 = fig.add_subplot(gs[1, 1])  # Bottom right
    ax5 = fig.add_subplot(gs[2, :])  # Full width bottom

    if not round_trip_times.empty:
        ax1.hist(round_trip_times, bins=100, color='blue', alpha=0.7, edgecolor='black')

        p25 = round_trip_times.quantile(0.25)
        p50 = round_trip_times.quantile(0.50)
        p75 = round_trip_times.quantile(0.75)
        mean_val = round_trip_times.mean()

        ax1.axvline(p25, color='lightgray', linestyle='--', linewidth=2, label=f'25th %ile: {p25:.1f}ms')
        ax1.axvline(p50, color='gray', linestyle='--', linewidth=2, label=f'50th %ile: {p50:.1f}ms')
        ax1.axvline(p75, color='darkgray', linestyle='--', linewidth=2, label=f'75th %ile: {p75:.1f}ms')
        ax1.axvline(mean_val, color='black', linestyle='-', linewidth=2, label=f'Mean: {mean_val:.1f}ms')

        ax1.set_title('RTT Distribution', fontsize=20)
        ax1.set_xlabel('Round-trip Time (ms)', fontsize=16)
        ax1.set_ylabel('Frequency', fontsize=16)
        ax1.grid(True)
        ax1.tick_params(axis='both', labelsize=14)
        ax1.legend(fontsize=10)

    # 2. RTT Distribution without outliers (<200ms) - zoomed view with same stats as full dataset
    rtt_filtered = round_trip_times[round_trip_times < 200]
    if not rtt_filtered.empty:
        ax2.hist(rtt_filtered, bins=75, color='lightblue', alpha=0.7, edgecolor='black')

        # Use the same percentile and mean lines from the full dataset (not recalculated from filtered data)
        if p25 < 200:
            ax2.axvline(p25, color='lightgray', linestyle='--', linewidth=2, label=f'25th %ile: {p25:.1f}ms')
        if p50 < 200:
            ax2.axvline(p50, color='gray', linestyle='--', linewidth=2, label=f'50th %ile: {p50:.1f}ms')
        if p75 < 200:
            ax2.axvline(p75, color='darkgray', linestyle='--', linewidth=2, label=f'75th %ile: {p75:.1f}ms')
        if mean_val < 200:
            ax2.axvline(mean_val, color='black', linestyle='-', linewidth=2, label=f'Mean: {mean_val:.1f}ms')

        ax2.set_title('RTT Distribution (< 200ms)', fontsize=20)
        ax2.set_xlabel('Round-trip Time (ms)', fontsize=16)
        ax2.set_ylabel('Frequency', fontsize=16)
        ax2.grid(True)
        ax2.tick_params(axis='both', labelsize=14)
        ax2.legend(fontsize=10)

    # 3. top 16 peers with best median RTT (Box Plot)
    if not median_rtt_per_peer.empty and not valid_rtt_data.empty:
        top_16_peers = median_rtt_per_peer.nsmallest(16).index
        top_16_rtt_data = []
        top_16_labels = []

        for peer_ip in top_16_peers:
            peer_rtt_values = valid_rtt_data[valid_rtt_data['dst_ip'] == peer_ip]['round_trip_time_ms']
            if not peer_rtt_values.empty:
                top_16_rtt_data.append(peer_rtt_values.values)
                top_16_labels.append(int_to_ip(peer_ip))

        if top_16_rtt_data:
            bp1 = ax3.boxplot(top_16_rtt_data, patch_artist=True, labels=top_16_labels, showfliers=False)
            for patch in bp1['boxes']:
                patch.set_facecolor('green')
                patch.set_alpha(0.7)

            ax3.set_title('Top 16 Peers (Best Median RTT)', fontsize=20)
            ax3.set_xlabel('Peer IP Address', fontsize=16)
            ax3.set_ylabel('RTT Distribution (ms)', fontsize=16)
            ax3.grid(True, alpha=0.3)
            ax3.tick_params(axis='x', rotation=45, labelsize=10)
            ax3.tick_params(axis='y', labelsize=14)

    # 4. bottom 16 peers with worst median RTT (Box Plot)
    if not median_rtt_per_peer.empty and not valid_rtt_data.empty:
        bottom_16_peers = median_rtt_per_peer.nlargest(16).index
        bottom_16_rtt_data = []
        bottom_16_labels = []

        for peer_ip in bottom_16_peers:
            peer_rtt_values = valid_rtt_data[valid_rtt_data['dst_ip'] == peer_ip]['round_trip_time_ms']
            if not peer_rtt_values.empty:
                bottom_16_rtt_data.append(peer_rtt_values.values)
                bottom_16_labels.append(int_to_ip(peer_ip))

        if bottom_16_rtt_data:
            bp2 = ax4.boxplot(bottom_16_rtt_data, patch_artist=True, labels=bottom_16_labels, showfliers=False)
            for patch in bp2['boxes']:
                patch.set_facecolor('red')
                patch.set_alpha(0.7)

            ax4.set_title('Bottom 16 Peers (Worst Median RTT)', fontsize=20)
            ax4.set_xlabel('Peer IP Address', fontsize=16)
            ax4.set_ylabel('RTT Distribution (ms)', fontsize=16)
            ax4.grid(True, alpha=0.3)
            ax4.tick_params(axis='x', rotation=45, labelsize=10)
            ax4.tick_params(axis='y', labelsize=14)

    # 5. Full-width request distribution per peer (sorted)
    if not reqs_per_ip.empty:
        # Sort peers by request count (ascending)
        sorted_requests = reqs_per_ip.sort_values()

        # Create x-axis positions
        x_positions = range(len(sorted_requests))

        # Create the bar plot with uniform coloring
        bars = ax5.bar(x_positions, sorted_requests.values, color='black', alpha=0.7, width=0.8)

        ax5.set_title('Request Distribution per Peer (Sorted by Request Count)', fontsize=20)
        ax5.set_xlabel('Peers (Sorted by Request Count)', fontsize=16)
        ax5.set_ylabel('Number of Requests', fontsize=16)
        ax5.grid(True, alpha=0.3, axis='y')
        ax5.tick_params(axis='both', labelsize=14)

        # Add statistics text
        total_peers = len(sorted_requests)
        total_requests = sorted_requests.sum()
        median_requests = sorted_requests.median()
        mean_requests = sorted_requests.mean()
        min_requests = sorted_requests.min()
        max_requests = sorted_requests.max()

        stats_text = (
            f"Total Peers: {total_peers:,}\n"
            f"Total Requests: {total_requests:,}\n"
            f"Min: {min_requests}, Max: {max_requests}\n"
            f"Mean: {mean_requests:.1f}, Median: {median_requests:.1f}"
        )

        ax5.text(0.02, 0.98, stats_text, transform=ax5.transAxes, fontsize=12,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

        # Set x-axis to show only some tick marks for readability
        if total_peers > 50:
            # Show ticks at regular intervals
            tick_interval = max(1, total_peers // 20)
            tick_positions = range(0, total_peers, tick_interval)
            ax5.set_xticks(tick_positions)
            # Create labels with number: ip_address format
            tick_labels = [f'{i+1}: {int_to_ip(sorted_requests.index[i])}' for i in tick_positions]
            ax5.set_xticklabels(tick_labels, rotation=45)
        else:
            # For smaller datasets, show more detail
            tick_positions = range(0, total_peers, max(1, total_peers // 10))
            ax5.set_xticks(tick_positions)
            # Create labels with number: ip_address format
            tick_labels = [f'{i+1}: {int_to_ip(sorted_requests.index[i])}' for i in tick_positions]
            ax5.set_xticklabels(tick_labels, rotation=45)

    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # PAGE 2: Hit Rates and Request Counts
    fig, axes = plt.subplots(1, 2, figsize=(24, 12))
    fig.suptitle('Hit Rates and Request Distribution', fontsize=32)

    if not hit_rates.empty:
        axes[0].hist(hit_rates, bins=50, color='yellow', alpha=0.7, edgecolor='black')

        p25_hr = hit_rates.quantile(0.25)
        p50_hr = hit_rates.quantile(0.50)
        p75_hr = hit_rates.quantile(0.75)
        mean_hr = hit_rates.mean()

        axes[0].axvline(p25_hr, color='lightgray', linestyle='--', linewidth=2, label=f'25th %ile: {p25_hr:.3f}')
        axes[0].axvline(p50_hr, color='gray', linestyle='--', linewidth=2, label=f'50th %ile: {p50_hr:.3f}')
        axes[0].axvline(p75_hr, color='darkgray', linestyle='--', linewidth=2, label=f'75th %ile: {p75_hr:.3f}')
        axes[0].axvline(mean_hr, color='black', linestyle='-', linewidth=2, label=f'Mean: {mean_hr:.3f}')

        axes[0].set_title('Hit Rate Distribution', fontsize=24)
        axes[0].set_xlabel('Hit Rate', fontsize=20)
        axes[0].set_ylabel('Frequency', fontsize=20)
        axes[0].grid(True)
        axes[0].tick_params(axis='both', labelsize=16)
        axes[0].legend(fontsize=14)

    # 2. request count distribution
    if not reqs_per_ip.empty:
        axes[1].hist(reqs_per_ip, bins=75, color='purple', alpha=0.7, edgecolor='black')

        p25_req = reqs_per_ip.quantile(0.25)
        p50_req = reqs_per_ip.quantile(0.50)
        p75_req = reqs_per_ip.quantile(0.75)
        mean_req = reqs_per_ip.mean()

        axes[1].axvline(p25_req, color='lightgray', linestyle='--', linewidth=2, label=f'25th %ile: {p25_req:.0f}')
        axes[1].axvline(p50_req, color='gray', linestyle='--', linewidth=2, label=f'50th %ile: {p50_req:.0f}')
        axes[1].axvline(p75_req, color='darkgray', linestyle='--', linewidth=2, label=f'75th %ile: {p75_req:.0f}')
        axes[1].axvline(mean_req, color='black', linestyle='-', linewidth=2, label=f'Mean: {mean_req:.0f}')

        axes[1].set_title('Request Count Distribution', fontsize=24)
        axes[1].set_xlabel('Number of Requests', fontsize=20)
        axes[1].set_ylabel('Frequency', fontsize=20)
        axes[1].grid(True)
        axes[1].tick_params(axis='both', labelsize=16)
        axes[1].legend(fontsize=14)

    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # Page 3: Combined Analysis
    fig, axes = plt.subplots(1, 2, figsize=(24, 12))
    fig.suptitle('Combined Peer Analysis', fontsize=32)

    peer_stats_combined = pd.concat([
        reqs_per_ip.rename('requests'),
        hit_rates.rename('hit_rate'),
        avg_rtt_per_peer.rename('avg_rtt')
    ], axis=1, join='outer').fillna(0)

    # 1. scatter plot: request frequency vs hit rate
    if not peer_stats_combined.empty and not peer_stats_combined['requests'].empty:
        axes[0].scatter(peer_stats_combined['requests'], peer_stats_combined['hit_rate'],
                       alpha=0.3, s=40, color='gold', edgecolors='black', linewidth=0.5)
        axes[0].set_title('Request Frequency vs Hit Rate', fontsize=24)
        axes[0].set_xlabel('Number of Requests', fontsize=20)
        axes[0].set_ylabel('Hit Rate', fontsize=20)
        axes[0].grid(True, alpha=0.3)
        axes[0].tick_params(axis='both', labelsize=16)

    # 2. scatter plot: request frequency vs RTT (vectorized filtering)
    if not peer_stats_combined.empty:
        rtt_mask = peer_stats_combined['avg_rtt'] > 0
        if rtt_mask.any():
            valid_requests = peer_stats_combined.loc[rtt_mask, 'requests']
            valid_rtt = peer_stats_combined.loc[rtt_mask, 'avg_rtt']
            axes[1].scatter(valid_requests, valid_rtt, alpha=0.3, s=40, color='darkblue',
                           edgecolors='black', linewidth=0.5)
            axes[1].set_title('Request Frequency vs Average RTT', fontsize=24)
            axes[1].set_xlabel('Number of Requests', fontsize=20)
            axes[1].set_ylabel('Average RTT (ms)', fontsize=20)
            axes[1].set_ylim(0, 500)
            axes[1].grid(True, alpha=0.3)
            axes[1].tick_params(axis='both', labelsize=16)

        plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # Print summary statistics
    print(f"\nPeer Statistics Summary:")
    print(f"Total unique peers contacted: {len(reqs_per_ip)}")
    print(f"Total repair requests sent: {reqs_per_ip.sum()}")
    print(f"Average hit rate: {hit_rates.mean():.3f}")
    print(f"Average RTT: {round_trip_times.mean():.2f} ms")
    print(f"Median RTT: {round_trip_times.median():.2f} ms")

def repair_efficiency_heatmap(repair_requests, shreds_data, snapshot_slot, first_turbine, pdf):
    """
    Create a tiered heatmap showing repair efficiency (minimal required vs actual requests)

    Shows:
    - Total requests: ALL requests made between snapshot slot and first turbine
    - Heatmap analysis: Only fully buffered slots (continuous shreds 0 to max with no gaps)
    - Efficiency ratio: (actual_requests - minimal_needed) / minimal_needed per shred
    - X-axis organized like slot request rate graph showing actual slot numbers
    """
    print('\n\033[1mRepair Efficiency Heatmap Analysis\033[0m\n')
    print(f"Analyzing repair period: slot {snapshot_slot} to {first_turbine - 1}")

    # Validate input data availability
    if repair_requests is None or repair_requests.empty:
        print("No repair request data available for efficiency analysis")
        return

    if shreds_data is None or shreds_data.empty:
        print("No shred data available for efficiency analysis")
        return

    # Filter datasets to repair period (snapshot to first turbine) for focused analysis
    repair_period_requests = repair_requests[repair_requests['slot'].between(snapshot_slot, first_turbine - 1)].copy()
    repair_period_responses = shreds_data[
        (shreds_data['slot'].between(snapshot_slot, first_turbine - 1)) &
        (shreds_data['is_turbine'] == False)
    ].copy()

    if repair_period_requests.empty or repair_period_responses.empty:
        print("No repair data found for the specified period")
        return

    print(f"Analyzing {len(repair_period_requests)} requests and {len(repair_period_responses)} responses")

    total_requests_all_repair_period = len(repair_period_requests)
    print(f"Total requests in repair period (snapshot to first turbine): {total_requests_all_repair_period:,}")

    # Handle UINTMAX values that represent invalid/placeholder shred indices
    # Auto-detect UINTMAX threshold based on data characteristics (2^32 or 2^64)
    max_idx_in_data = max(repair_period_requests['idx'].max(), repair_period_responses['idx'].max())
    if max_idx_in_data > 1000000:
        possible_uintmax = [2**32 - 1, 2**32, 2**64 - 1]
        UINTMAX_THRESHOLD = min([val for val in possible_uintmax if val >= max_idx_in_data], default=max_idx_in_data)
    else:
        UINTMAX_THRESHOLD = float('inf')

    # Calculate legitimate maximum shred indices per slot (excluding UINTMAX)
    responses_filtered = repair_period_responses[repair_period_responses['idx'] < UINTMAX_THRESHOLD]
    max_shred_per_slot = responses_filtered.groupby('slot')['idx'].max().to_dict()

    # Replace UINTMAX values with slot-specific maximum legitimate indices
    uintmax_mask_req = repair_period_requests['idx'] >= UINTMAX_THRESHOLD
    if uintmax_mask_req.any():
        print(f"Replacing {uintmax_mask_req.sum()} UINTMAX values in requests")
        for idx in repair_period_requests[uintmax_mask_req].index:
            slot = repair_period_requests.loc[idx, 'slot']
            if slot in max_shred_per_slot:
                repair_period_requests.loc[idx, 'idx'] = max_shred_per_slot[slot]
            else:
                repair_period_requests.loc[idx, 'idx'] = 0

    # Calculate efficiency metrics by aggregating requests and responses per (slot, shred_idx)
    requests_count = repair_period_requests.groupby(['slot', 'idx']).size().reset_index(name='request_count')
    responses_count = repair_period_responses.groupby(['slot', 'idx']).size().reset_index(name='response_count')
    efficiency_data = pd.merge(requests_count, responses_count, on=['slot', 'idx'], how='outer').fillna(0)

    # Calculate efficiency ratio: excess requests beyond minimal needed per shred
    # Logic: minimal_needed = 1 for successfully repaired shreds, 0 for failed repairs
    # Efficiency ratio = (actual_requests - minimal_needed) / minimal_needed
    # Higher ratios indicate more redundant requests relative to success
    efficiency_data['minimal_needed'] = (efficiency_data['response_count'] > 0).astype(int)
    efficiency_data['efficiency_ratio'] = np.where(
        efficiency_data['minimal_needed'] > 0,
        (efficiency_data['request_count'] - efficiency_data['minimal_needed']) / efficiency_data['minimal_needed'],
        efficiency_data['request_count']  # For shreds with no response, efficiency = request_count
    )

    # Filter to only shreds that had either requests or responses
    efficiency_data = efficiency_data[
        (efficiency_data['request_count'] > 0) | (efficiency_data['response_count'] > 0)
    ]

    if efficiency_data.empty:
        print("No efficiency data to plot")
        return

    # Identify "fully buffered" slots with continuous shred coverage for accurate analysis
    # Only analyze slots with complete shred sequences to avoid gaps skewing efficiency metrics
    valid_slots = []

    for slot in efficiency_data['slot'].unique():
        slot_data = efficiency_data[efficiency_data['slot'] == slot].copy()
        slot_indices = sorted(slot_data['idx'].unique())

        if len(slot_indices) == 0:
            continue

        min_idx = min(slot_indices)
        max_idx = max(slot_indices)

        expected_indices = set(range(min_idx, max_idx + 1))
        actual_indices = set(slot_indices)

        if expected_indices == actual_indices:
            valid_slots.append(slot)

    # create a complete slot range (like slot request rate analysis)
    all_slots_in_range = list(range(efficiency_data['slot'].min(), efficiency_data['slot'].max() + 1))
    non_buffered_slots = [slot for slot in all_slots_in_range if slot not in valid_slots]

    # Keep only fully buffered slots for efficiency calculation, but we'll show all slots in heatmap
    efficiency_data_buffered = efficiency_data[efficiency_data['slot'].isin(valid_slots)].copy()

    if efficiency_data_buffered.empty:
        print("No fully buffered slots found")
        return

    # prepare data for heatmap
    slots = all_slots_in_range
    max_shred_idx = int(efficiency_data_buffered['idx'].max())

    # verify max_shred_idx is reasonable after UINTMAX replacement
    if max_shred_idx > 100000:
        print(f"Warning: max_shred_idx still very large ({max_shred_idx}), capping at 10000 for visualization")
        efficiency_data_buffered = efficiency_data_buffered[efficiency_data_buffered['idx'] <= 10000]
        max_shred_idx = 10000

    heatmap_matrix = np.full((max_shred_idx + 1, len(slots)), np.nan)

    for _, row in efficiency_data_buffered.iterrows():
        if row['slot'] in slots:
            slot_idx = slots.index(row['slot'])
            shred_idx = int(row['idx'])
            if shred_idx <= max_shred_idx:
                heatmap_matrix[shred_idx, slot_idx] = row['efficiency_ratio']

    fig, ax = plt.subplots(figsize=(28, 16))

    q1 = efficiency_data_buffered['efficiency_ratio'].quantile(0.25)
    q3 = efficiency_data_buffered['efficiency_ratio'].quantile(0.75)
    iqr = q3 - q1

    # outlier thresholds, not sure if its better to use quantiles or IQR
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr
    p95 = efficiency_data_buffered['efficiency_ratio'].quantile(0.95)
    p99 = efficiency_data_buffered['efficiency_ratio'].quantile(0.99)
    # use the more conservative approach between IQR and 99th percentile
    outlier_threshold = min(upper_bound, p99)

    # identify outliers (only from buffered slots)
    outliers = efficiency_data_buffered[efficiency_data_buffered['efficiency_ratio'] > outlier_threshold]
    non_outliers = efficiency_data_buffered[efficiency_data_buffered['efficiency_ratio'] <= outlier_threshold]

    min_efficiency_ratio = non_outliers['efficiency_ratio'].min()
    max_efficiency_ratio = non_outliers['efficiency_ratio'].max()

    # Use a colormap where green=good (low efficiency ratio), red=bad (high efficiency ratio)
    # Set explicit scale to non-outlier data range, but outliers will be capped at max color
    im = ax.imshow(heatmap_matrix, cmap='RdYlGn_r', aspect='auto', interpolation='nearest',
                   vmin=min_efficiency_ratio, vmax=max_efficiency_ratio)

    ax.set_xlabel('Slot Number', fontsize=24)
    ax.set_ylabel('Shred Index', fontsize=24)
    ax.set_title('Repair Efficiency Heatmap - All Repair Period Slots', fontsize=28)

    slot_range = max(slots) - min(slots)
    if slot_range <= 50:
        major_tick_spacing = 5
    elif slot_range <= 200:
        major_tick_spacing = 10
    elif slot_range <= 500:
        major_tick_spacing = 20
    else:
        major_tick_spacing = 50

    ax.set_xticks(range(0, len(slots), max(1, len(slots) // 20)))
    ax.set_xticklabels([slots[i] for i in range(0, len(slots), max(1, len(slots) // 20))], rotation=45, fontsize=12)

    ax.grid(True, which='major', alpha=0.3, linewidth=0.5)
    ax.grid(True, which='minor', alpha=0.1, linewidth=0.25)

    ax.tick_params(axis='both', which='major', labelsize=14)
    ax.tick_params(axis='both', which='minor', labelsize=12)

    if max_shred_idx > 50:
        step = max(1, max_shred_idx // 20)
        ax.set_yticks(range(0, max_shred_idx + 1, step))

    cbar = plt.colorbar(im, ax=ax, shrink=0.6)
    cbar.set_label(f'Efficiency Ratio\n(Excess Requests / Minimal Required)', fontsize=18)

    avg_efficiency = efficiency_data_buffered['efficiency_ratio'].mean()
    total_requests_buffered_slots = efficiency_data_buffered['request_count'].sum()
    total_minimal = efficiency_data_buffered['minimal_needed'].sum()

    stats_text = (f"Total Slots: {len(slots)} ({len(valid_slots)} buffered, {len(non_buffered_slots)} empty)\n"
                 f"Shred Requests: {total_requests_buffered_slots:,}\n"
                 f"Outliers (>{outlier_threshold:.2f}): {len(outliers)} shreds\n"
                 f"Average Efficiency: {avg_efficiency:.2f}\n"
                 f"Minimal Required: {total_minimal:,}\n"
                 f"Excess Requests: {total_requests_buffered_slots - total_minimal:,}")

    ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=16,
            verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    plt.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # outlier details
    if len(outliers) > 0:
        print(f"\nOUTLIER SHREDS (Efficiency Ratio > {outlier_threshold:.2f}):")
        outlier_summary = outliers.groupby('slot').agg({
            'idx': lambda x: f"{min(x)}-{max(x)}" if len(x) > 1 else str(list(x)[0]),
            'efficiency_ratio': ['min', 'max', 'mean', 'count'],
            'request_count': 'sum'
        }).round(2)

        outlier_summary.columns = ['shred_range', 'min_ratio', 'max_ratio', 'avg_ratio', 'num_shreds', 'total_requests']
        outlier_summary = outlier_summary.sort_values('max_ratio', ascending=False)

        print("Slot | Shred Range | Min Ratio | Max Ratio | Avg Ratio | # Shreds | Total Requests")
        print("-" * 85)
        for slot, row in outlier_summary.head(10).iterrows():  # Show top 10 worst slots
            print(f"{slot:<4} | {row['shred_range']:<11} | {row['min_ratio']:<9.2f} | {row['max_ratio']:<9.2f} | {row['avg_ratio']:<9.2f} | {row['num_shreds']:<8} | {row['total_requests']:<14}")

        if len(outlier_summary) > 10:
            print(f"... and {len(outlier_summary) - 10} more slots with outliers\n")
    else:
        print("\nNo outlier shreds found.")

    # summary stats
    print(f"Repair Efficiency Summary:")
    print(f"  TOTAL repair period requests (snapshot to first turbine): {total_requests_all_repair_period:,}")
    print(f"  Fully buffered slots analyzed: {len(slots)}")
    print(f"  Buffered slot requests: {total_requests_buffered_slots:,}")
    print(f"  Max shred index: {max_shred_idx}")
    print(f"  Minimal requests needed (buffered slots): {total_minimal:,}")
    print(f"  Excess requests (buffered slots): {total_requests_buffered_slots - total_minimal:,}")
    print(f"  Average efficiency ratio: {avg_efficiency:.2f}")
    print(f"  Normal efficiency range: {min_efficiency_ratio:.2f} to {max_efficiency_ratio:.2f}")
    print(f"  Outlier threshold: {outlier_threshold:.2f}")
    print(f"  Outlier shreds: {len(outliers)} ({len(outliers)/len(efficiency_data_buffered)*100:.1f}% of total)")
    print(f"  Perfect efficiency (ratio=0): {(efficiency_data_buffered['efficiency_ratio'] == 0).sum()} shreds")

def generate_report( log_path, request_data_path, shred_data_path, peers_data_path, fec_complete_path=None, pdf=None, include_after_turbine=False ):
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

    if request_data_path:
        repair_requests = pd.read_csv( request_data_path,
                                    dtype={'dst_ip': str, 'dst_port': int, 'timestamp': int, 'slot': int, 'idx': int, 'nonce': int },
                                    skipfooter=1 )

    if peers_data_path:
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


    create_title_page(pdf)

    slot_request_rate_analysis(shreds_data, first_turbine, pdf, include_after_turbine)

    # Add peer statistics analysis (3 pages) - after slot analysis
    if request_data_path:
        peer_stats_analysis(repair_requests, shreds_data, pdf)

    # Add repair efficiency heatmap analysis
    if request_data_path:
        repair_efficiency_heatmap(repair_requests, shreds_data, snapshot_slot, first_turbine, pdf)

    if request_data_path:
        catchup_rq = repair_requests[repair_requests['slot'].between(snapshot_slot, first_turbine - 1)]
        live_rq    = repair_requests[repair_requests['slot'].between(first_turbine, last_executed)]

        turbine_stats(catchup, live)

        # Add turbine shred timeline analysis
        turbine_shred_timeline(shreds_data, first_turbine, pdf)

        catchup = catchup[catchup['timestamp'] >= first_turbine_accept_ts]  # only keep shreds that were accepted after the first turbine
        shreds_data = shreds_data[shreds_data['timestamp'] >= first_turbine_accept_ts]  # only keep shreds that were accepted after the first turbine

    if fec_complete_path:
        completion_times( fec_stats, shreds_data, first_turbine, pdf )

    if request_data_path:
        print_slots(repair_requests, shreds_data, snapshot_slot, first_turbine, pdf)

def find_most_recent_log():
    """Find the most recently created log file in current directory and common locations"""
    import glob

    search_paths = [
        './*.log',
        './logs/*.log',
        '../*.log',
        '../logs/*.log',
    ]

    log_files = []
    for pattern in search_paths:
        log_files.extend(glob.glob(pattern))

    if not log_files:
        return None

    # Sort by creation time (most recent first)
    log_files.sort(key=lambda x: os.path.getctime(x), reverse=True)
    return log_files[0]

def find_most_recent_csv_folder():
    """Find the most recently created folder containing CSV files"""
    import glob

    potential_folders = []

    for root, dirs, files in os.walk('.'):
        if 'shred_data.csv' in files:
            potential_folders.append(root)

    for root, dirs, files in os.walk('..'):
        if 'shred_data.csv' in files:
            potential_folders.append(root)

    if not potential_folders:
        return None

    potential_folders.sort(key=lambda x: os.path.getctime(x), reverse=True)
    return potential_folders[0]

if __name__ == "__main__":
    # Check for --turbine flag (controls whether to include slots after turbine in slot analysis)
    include_after_turbine = '--turbine' in sys.argv
    if include_after_turbine:
        sys.argv.remove('--turbine')

    # Handle different argument scenarios
    if len(sys.argv) == 1:
        # No arguments provided - auto-detect most recent files, simplicity of use for users
        print("No arguments provided. Searching for most recent log file and CSV folder...")
        log_path = find_most_recent_log()
        csv_path = find_most_recent_csv_folder()

        if log_path is None:
            print("Error: Could not find any log files automatically.")
            print("Please provide log file path as argument.")
            sys.exit(1)

        if csv_path is None:
            print("Error: Could not find any CSV folder with shred_data.csv automatically.")
            print("Please provide CSV folder path as argument.")
            sys.exit(1)

        print(f"Auto-detected log file: {log_path}")
        print(f"Auto-detected CSV folder: {csv_path}")

    elif len(sys.argv) == 3:
        # Both arguments provided
        log_path = sys.argv[1]
        csv_path = sys.argv[2]

    else:
        print('Add: [tiles.shredcap] \n\t enabled = true \n\t folder_path = /my/folder_for_csv_dump \n to your testnet config.toml file to enable the report generation.')
        print('Usage: python report.py [--turbine] [<testnet.log path> <csv_folder_path>]')
        # TODO: Add the --turbine flag to all functions such that we can filter by turbine slot in all functions
        print('  Note: The --turbine flag only affects the slot_request_rate graph and related calculations; it does not impact other report sections.')
        print('  --turbine: Include slots >= turbine slot in slot processing analysis (default: exclude them)')
        print('  If no arguments provided, will auto-detect most recently created log and CSV folder')
        print('Report will automatically be saved as report.pdf in the current directory.')
        sys.exit(1)
    # check if the csvs live in path
    if not os.path.exists(csv_path):
        print(f'Error: {csv_path} does not exist')
        sys.exit(1)

    csv_paths = { 'shred_data.csv'   : os.path.join(csv_path, 'shred_data.csv'),
                  'request_data.csv' : os.path.join(csv_path, 'request_data.csv'),
                  'peers_data.csv'   : os.path.join(csv_path, 'peers.csv'),
                  'fec_complete.csv' : os.path.join(csv_path, 'fec_complete.csv') }

    for csv_name, csv_path in csv_paths.items():
        if not os.path.exists(csv_path):
            csv_paths[csv_name] = None

    for csv_name, csv_path in csv_paths.items():
        print(f'Found {csv_name}: {csv_path}')

    output_path = 'report.pdf'
    pdf = PdfPages('report.pdf')

    generate_report(log_path,
                    csv_paths['request_data.csv'],
                    csv_paths['shred_data.csv'],
                    csv_paths['peers_data.csv'],
                    csv_paths['fec_complete.csv'],
                    pdf,
                    include_after_turbine)
    print(f'Graphs generated at: {output_path}')

    pdf.close()
