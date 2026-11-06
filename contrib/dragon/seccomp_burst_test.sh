#!/bin/bash
# Runs the dragon tile's server under its real seccomp policy with a
# small connection pool, keeps one subscriber streaming, and offers
# more connections than the pool holds.  Passes when every extra
# connection is refused with a GOAWAY, the subscriber is untouched and
# the tile exits 0 ("pass").  A syscall outside the policy on the
# accept, refuse or close path shows up here as a dead tile.
#
#   contrib/dragon/seccomp_burst_test.sh [objdir] [port]
set -u
OBJDIR=${1:-$(make --silent objdir 2>/dev/null || echo build/native/gcc)}
PORT=${2:-10999}
T=$OBJDIR/unit-test/test_dragon_tile
L=$OBJDIR/unit-test/bench_grpc_load
POOL=16; BURST=40; VICTIM_SECS=14; TILE_SECS=22
D=$(mktemp -d /tmp/dragon-burst.XXXXXX)
PAGE="--page-sz normal --page-cnt 1572864"

[ -x "$T" ] && [ -x "$L" ] || { echo "FAIL: build test_dragon_tile and bench_grpc_load first ($OBJDIR)"; exit 1; }

( $T $PAGE --log-path "" --listen-port $PORT --max-conns $POOL --seccomp 1 --slot 1000 --duration-seconds $TILE_SECS > $D/tile.log 2>&1; echo $? > $D/tile.rc ) &
sleep 5
( $L --log-path "" --host 127.0.0.1 --port $PORT --conns 1 --ramp 1 --sub slots --commitment processed --seconds $VICTIM_SECS > $D/victim.log 2>&1 & )
sleep 3
$L --log-path "" --host 127.0.0.1 --port $PORT --conns $BURST --ramp $BURST --sub slots --commitment processed --seconds 8 > $D/burst.log 2>&1
wait

rc=$(cat $D/tile.rc 2>/dev/null || echo none)
passed=$(grep -c 'test_dragon_tile.c([0-9]*): pass' $D/tile.log)
j(){ grep '^{' $1 | grep -oE "\"$2\":[0-9]+" | cut -d: -f2; }
b_open=$(j $D/burst.log open); b_goaway=$(j $D/burst.log closed_goaway); b_eof=$(j $D/burst.log closed_eof); b_err=$(j $D/burst.log closed_err)
v_open=$(j $D/victim.log open); v_closed=$(j $D/victim.log closed); v_msgs=$(j $D/victim.log msgs)
echo "tile rc=$rc pass=$passed | burst open=$b_open goaway=$b_goaway eof=$b_eof err=$b_err | victim open=$v_open closed=$v_closed msgs=$v_msgs | logs $D"

ok=1
[ "$rc" = "0" ] && [ "$passed" = "1" ]                  || { echo "FAIL: tile did not survive the burst"; ok=0; }
[ "${b_eof:-1}" = "0" ] && [ "${b_err:-1}" = "0" ]       || { echo "FAIL: connections closed without a GOAWAY"; ok=0; }
[ "${b_goaway:-0}" -ge $(( BURST-POOL )) ]               || { echo "FAIL: too few refusals"; ok=0; }
[ "${v_closed:-1}" = "0" ] && [ "${v_msgs:-0}" -gt 0 ]   || { echo "FAIL: the existing subscriber was disturbed"; ok=0; }
[ $ok = 1 ] || exit 1

# Phase 2: the per-address limit.  A pool of 16 with 4 per address:
# 10 connections from 127.0.0.1 leave 6 refused, and one from 127.0.0.2
# still gets in.
PORT2=$(( PORT+1 ))
( $T $PAGE --log-path "" --listen-port $PORT2 --max-conns $POOL --max-conns-per-addr 4 --seccomp 1 --slot 1000 --duration-seconds 16 > $D/tile2.log 2>&1; echo $? > $D/tile2.rc ) &
sleep 5
$L --log-path "" --host 127.0.0.1 --port $PORT2 --conns 10 --ramp 10 --sub slots --commitment processed --seconds 6 > $D/same.log 2>&1 &
sleep 2
$L --log-path "" --host 127.0.0.1 --bind 127.0.0.2 --port $PORT2 --conns 1 --ramp 1 --sub slots --commitment processed --seconds 4 > $D/other.log 2>&1
wait
s_open=$(j $D/same.log open); s_goaway=$(j $D/same.log closed_goaway); o_open=$(j $D/other.log open); o_msgs=$(j $D/other.log msgs)
echo "per-address: same-address open=$s_open goaway=$s_goaway | other-address open=$o_open msgs=$o_msgs | tile rc=$(cat $D/tile2.rc)"
[ "$(cat $D/tile2.rc)" = "0" ]                                 || { echo "FAIL: tile did not survive phase 2"; ok=0; }
[ "${s_open:-0}" = "4" ] && [ "${s_goaway:-0}" = "6" ]         || { echo "FAIL: per-address limit not enforced"; ok=0; }
[ "${o_open:-0}" = "1" ] && [ "${o_msgs:-0}" -gt 0 ]           || { echo "FAIL: another address was refused"; ok=0; }

# Phase 3: a connection that completes the handshake and opens no
# stream is closed after the idle timeout even if it keeps pinging.
PORT3=$(( PORT+2 ))
( $T $PAGE --log-path "" --listen-port $PORT3 --max-conns $POOL --idle-timeout-seconds 4 --seccomp 1 --slot 1000 --duration-seconds 16 > $D/tile3.log 2>&1; echo $? > $D/tile3.rc ) &
sleep 5
python3 - $PORT3 > $D/holder.log 2>&1 <<'PY'
import socket, struct, sys, time
port = int(sys.argv[1]); s = socket.create_connection(("127.0.0.1", port)); s.settimeout(0.5)
def frame(t, fl, sid, p=b""): return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))   # preface + empty SETTINGS, no stream ever
t0 = time.time(); last = None
while time.time() - t0 < 10:
    try: s.sendall(frame(6, 0, 0, b"holdslot"))                          # PING every 0.5 s
    except OSError: break
    try:
        d = s.recv(4096)
        if not d: break
    except socket.timeout: pass
    except OSError: break
    last = time.time() - t0
print("held %.1f s" % (time.time() - t0))
PY
wait
held=$(grep -oE 'held [0-9.]+' $D/holder.log | awk '{print $2}')
echo "no-stream hold: closed after ${held:-?} s with idle timeout 4 s | tile rc=$(cat $D/tile3.rc)"
[ "$(cat $D/tile3.rc)" = "0" ]                                   || { echo "FAIL: tile did not survive phase 3"; ok=0; }
awk -v h="${held:-99}" 'BEGIN{ exit !(h>=3.5 && h<=7.0) }'       || { echo "FAIL: a stream-less pinging connection was not closed by the idle timeout"; ok=0; }

# Phase 4: a connection whose only streams are refused (unknown method,
# which is also what a wrong token looks like) is closed by the idle
# timeout too: a refused stream does not count as use.
PORT4=$(( PORT+3 ))
( $T $PAGE --log-path "" --listen-port $PORT4 --max-conns $POOL --idle-timeout-seconds 4 --seccomp 1 --slot 1000 --duration-seconds 16 > $D/tile4.log 2>&1; echo $? > $D/tile4.rc ) &
sleep 5
python3 - $PORT4 > $D/holder4.log 2>&1 <<'PY'
import socket, struct, sys, time
port = int(sys.argv[1]); s = socket.create_connection(("127.0.0.1", port)); s.settimeout(0.5)
def frame(t, fl, sid, p=b""): return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p
def lit(name, value):
    return bytes([0x00, len(name)]) + name + bytes([len(value)]) + value
hdrs = lit(b":method", b"POST") + lit(b":scheme", b"http") + lit(b":path", b"/no.such/Method") + lit(b":authority", b"x") + lit(b"content-type", b"application/grpc")
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
t0 = time.time(); sid = 1
while time.time() - t0 < 10:
    try: s.sendall(frame(1, 0x5, sid, hdrs)); sid += 2                     # HEADERS, END_STREAM|END_HEADERS, every second
    except OSError: break
    try:
        d = s.recv(65536)
        if not d: break
    except socket.timeout: pass
    except OSError: break
    time.sleep(1.0)
print("held %.1f s" % (time.time() - t0))
PY
wait
held4=$(grep -oE 'held [0-9.]+' $D/holder4.log | awk '{print $2}')
echo "refused-stream hold: closed after ${held4:-?} s with idle timeout 4 s | tile rc=$(cat $D/tile4.rc)"
[ "$(cat $D/tile4.rc)" = "0" ]                                   || { echo "FAIL: tile did not survive phase 4"; ok=0; }
awk -v h="${held4:-99}" 'BEGIN{ exit !(h>=3.5 && h<=8.0) }'      || { echo "FAIL: a connection opening only refused streams was not closed by the idle timeout"; ok=0; }

[ $ok = 1 ] && { echo "PASS"; rm -rf $D; exit 0; } || exit 1
