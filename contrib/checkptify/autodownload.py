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
    cmd = f'wget --no-clobber --trust-server-names {url}'
    subprocess.run( cmd, shell=True )

def relink(snap, link):
    subprocess.run( f'rm -f tmp-link', shell=True )
    subprocess.run( f'ln -s {snap} tmp-link', shell=True )
    subprocess.run( f'mv -f tmp-link {link}', shell=True )
    print( f'linked {link} to {snap}' )

def rmold(files, keep):
    for i in range(keep, len(files)):
        os.remove( files[i] )
        print( f'removed {files[i]}' )

while True:
    download( f'{solana_url}/snapshot.tar.bz2' )
    download( f'{solana_url}/incremental-snapshot.tar.bz2' )

    fullfiles = []
    incfiles = []
    for file in os.listdir( "." ):
        if "incremental" in file:
            if file != 'incremental-snapshot.tar.bz2':
                incfiles.append(file)
        elif "snapshot" in file:
            if file != 'snapshot.tar.bz2':
                fullfiles.append(file)

    fullfiles.sort( key=(lambda n: int(n.split('-')[1])), reverse=True );
    incfiles.sort( key=(lambda n: int(n.split('-')[3])), reverse=True );

    rmold(fullfiles, 2)
    rmold(incfiles, 3)

    if fullfiles[0].split('-')[1] == incfiles[0].split('-')[2]:
        fullname = os.path.realpath(fullfiles[0])
        incname = os.path.realpath(incfiles[0])
        print(f'FULLSNAP={fullname}')
        print(f'INCSNAP={incname}')
        with open('latest', 'w') as fd:
            fd.write(f'FULLSNAP={fullname}\n')
            fd.write(f'INCSNAP={incname}\n')

    time.sleep(30)
