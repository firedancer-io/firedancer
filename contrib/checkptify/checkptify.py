import os
import subprocess
import argparse
import glob

FIREDANCER_DIR="/home/svc-firedancer/firedancer/"
OUTPUT_DIR="/data/snapshot_converter/snapshots/"

MAINNET_SOLANA_ENDPOINT="http://entrypoint2.mainnet-beta.solana.com:8899"
TESTNET_SOLANA_ENDPOINT="http://entrypoint3.testnet.solana.com:8899"
INCREMENTAL_ENDPOINT="/incremental-snapshot.tar.bz2"
FULL_ENDPOINT="/snapshot.tar.bz2"
NUM_PAGES=200
INDEX_MAX=75000000

# Example Command: python3 checkptify.py --firedancer-dir /home/svc-firedancer/firedancer/ 
#                  --output-dir /data/snapshot_converter/snapshots/ 
#                  --solana-url http://entrypoint2.mainnet-beta.solana.com:8899 
#                  --num-pages 200 --index-max 75000000 --pull-clean True --keep-checkpts 2

parser = argparse.ArgumentParser( description="Ingest snapshots, convert to checkpoints, and upload to gcloud" )
parser.add_argument( "--firedancer-dir", help="location for firedancer directory", default=FIREDANCER_DIR )
parser.add_argument( "--output-dir",     help="location for output directory",     default=OUTPUT_DIR )
parser.add_argument( "--solana-url",     help="solana snapshot endpoint",          default=MAINNET_SOLANA_ENDPOINT )
parser.add_argument( "--num-pages",      help="number of pages for firedancer",    default=NUM_PAGES )
parser.add_argument( "--index-max",      help="max index for funk",                default=INDEX_MAX )
parser.add_argument( "--pull-clean",     help="git pull and clean firedancer",     default=True )
parser.add_argument( "--keep-checkpts",  help="number of old checkpoints to keep", default=2 )
args = parser.parse_args()

firedancer_dir  = args.firedancer_dir
output_dir      = args.output_dir
solana_url      = args.solana_url
num_pages       = args.num_pages
index_max       = args.index_max
pull_clean      = args.pull_clean
keep_checkpts   = args.keep_checkpts

# Clean build and pull down latest main
os.chdir( firedancer_dir )
if not pull_clean:
    subprocess.run( "git pull", shell = True )
    subprocess.run( "make distclean; make -j", shell = True ) 

# Go to snapshot directory remove all incremental snapshots and checkpoints
os.chdir( output_dir )
print( "current directory: {}".format( os.getcwd() ) )
full_snapshot_slot = 0
full_snapshot_file = ""
checkpt_files = []
for file in os.listdir( output_dir ):
    if "incremental" in file:
        os.remove( output_dir + file )
    if "snapshot" in file and "incremental" not in file:
        full_snapshot_slot = int( file.split( "-" )[1] )
        full_snapshot_file = file
    if "checkpt" in file:
        checkpt_files.append( file )

# Remove all but the newest N checkpoints
checkpt_files.sort( key=os.path.getmtime, reverse=True)
[ os.remove( output_dir + file ) for file in checkpt_files[2:] ]

# Download an incremental snapshot
full_command = [ "wget", "--trust-server-names", solana_url + INCREMENTAL_ENDPOINT ]
print( " ".join(  full_command ) )
subprocess.run( " ".join(  full_command ), shell = True )

# If the incremental snapshot matches the full snapshot, don't do anything. However,
# it it doesn't remove and redownload the main snapshot
incremental_start_slot    = 0
incremental_end_slot      = 0
incremental_snapshot_file = ""
for file in os.listdir( output_dir ):
    if "incremental" in file:
        incremental_start_slot = int( file.split( "-" )[2] )
        incremental_end_slot   = int( file.split( "-" )[3] )
        print( output_dir + file + " with start slot " + str(incremental_start_slot) + " and end slot " + str(incremental_end_slot) )
        incremental_snapshot_file = file
    
if full_snapshot_slot != incremental_start_slot:
    if full_snapshot_file != "":
        os.remove( output_dir + full_snapshot_file )
    full_command = [ "wget", "--trust-server-names", solana_url + FULL_ENDPOINT ]
    #full_command = "wget --trust-server-names " + solana_url + FULL_ENDPOINT
    subprocess.run( " ".join(  full_command ), shell = True )

for file in os.listdir( OUTPUT_DIR ):
    if "snapshot" in file and "incremental" not in file:
        full_snapshot_file = file
    
print( "full snapshot file: {}".format( full_snapshot_file ) )
print( "incremental snapshot file: {}".format( incremental_snapshot_file ) )

os.chdir( firedancer_dir )
full_snapshot_path        = output_dir + full_snapshot_file
incremental_snapshot_path = output_dir + incremental_snapshot_file
checkpt_path              = output_dir + str(incremental_end_slot) + "-checkpt"
obj_dir = os.environ["OBJDIR"]
# ingest_command = "./" + obj_dir + "/bin/fd_ledger --cmd ingest --snapshot " + full_snapshot_path + \
#                  " --incremental " + incremental_snapshot_path + " --funk-only 1 " + \
#                  " --checkpt-funk " + checkpt_path + " --funk-page-cnt " + str(num_pages) + \
#                  " --index-max " + str(index_max)
executable = "./" + obj_dir + "/bin/fd_ledger"
ingest_command = [executable, "--cmd", "ingest", "--snapshot", full_snapshot_path, "--incremental", incremental_snapshot_path, "--funk-only", "1", "--checkpt-funk", checkpt_path, "--funk-page-cnt", str(num_pages), "--index-max", str(index_max)]
print( " ".join(  ingest_command ) )
subprocess.run( " ".join(  ingest_command ), shell = True )
