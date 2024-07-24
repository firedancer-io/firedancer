import os
import subprocess
import argparse
import glob
import time

DEFAULT_SOLANA_ENDPOINT="http://entrypoint3.testnet.solana.com:8899"
parser = argparse.ArgumentParser( description="Automatically download the latest snapshots" )
parser.add_argument( "--solana-url",     help="solana snapshot endpoint",          default=DEFAULT_SOLANA_ENDPOINT )
parser.add_argument( "--output-dir",     help="location for output directory",     default=None )
args = parser.parse_args()

solana_url = args.solana_url
output_dir = args.output_dir
if output_dir is None:
    output_dir = 'snaps/' + solana_url.split('//')[1].replace(':','_')

subprocess.run( f'mkdir -p {output_dir}', shell=True )
os.chdir( output_dir )
print( f"output directory: {os.getcwd()}" )
print( f"solana endpoint: {solana_url}" )

def download(url):
    while True:
        print( f'trying {url}' )
        cmd = f'curl --max-redirs 0 --silent {url}'
        proc = subprocess.Popen( cmd, shell=True, stdout=subprocess.PIPE )
        newname = proc.stdout.read().decode("utf-8").split('/')[-1]
        if os.path.exists(newname) and os.stat(newname).st_size > 0:
            return (newname,False)
        if len(newname) == 0:
            # We are temporarily banned
            print( f'"{cmd}" failed' )
            time.sleep( 10 )
            continue

        print( f'downloading {newname} ...' )
        subprocess.run( 'rm -f tmp', shell=True )
        cmd = f'wget --output-document=tmp --quiet {url}'
        subprocess.run( cmd, shell=True )
        if not (os.path.exists('tmp') and os.stat('tmp').st_size > 0):
            print( f'"{cmd}" failed' )
            time.sleep( 10 )
            continue

        subprocess.run( f'mv -f tmp {newname}', shell=True )
        print( f'downloaded {newname}' )
        return (newname,True)

def relink(snap, link):
    subprocess.run( f'rm -f tmp-link', shell=True )
    subprocess.run( f'ln -s {snap} tmp-link', shell=True )
    subprocess.run( f'mv -f tmp-link {link}', shell=True )
    print( f'linked {link} to {snap}' )

def rmold(files, keep):
    files.sort( key=os.path.getmtime, reverse=True)
    for i in range(keep, len(files)):
        os.remove( files[i] )
        print( f'removed {files[i]}' )

while True:
    (fullsnap,fullsnapnew) = download( f'{solana_url}/snapshot.tar.bz2' )
    (incsnap,incsnapnew) = download( f'{solana_url}/incremental-snapshot.tar.bz2' )

    if (fullsnapnew or incsnapnew) and (fullsnap.split('-')[1] == incsnap.split('-')[2]):
        relink( fullsnap, 'snapshot.tar.bz2' )
        relink( incsnap, 'incremental-snapshot.tar.bz2' )

    fullfiles = []
    incfiles = []
    for file in os.listdir( "." ):
        if "incremental" in file:
            if file != 'incremental-snapshot.tar.bz2':
                incfiles.append(file)
        elif "snapshot" in file:
            if file != 'snapshot.tar.bz2':
                fullfiles.append(file)
    rmold(fullfiles, 2)
    rmold(incfiles, 3)

    time.sleep(30)
