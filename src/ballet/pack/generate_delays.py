# FIXME: This file belongs with the tile code.  Rather than clutter
# fdctl/run/tiles with these two files, I'm putting this in ballet/pack.
# Really, all of this belongs in disco.
from sage.all import *
import struct
var('x,v,t,a,b,r')

MAX_TXN_PER_MICROBLOCK = Integer(31)

# I have no idea why, but without this line here, sage gives an error
ex_expr =  sum( (x+v)/(t+a+b*(x+v)) * (r*t)**v * exp(-r*t)/factorial(v), v, 0, MAX_TXN_PER_MICROBLOCK-1-x) + sum(MAX_TXN_PER_MICROBLOCK/(t+a+b*MAX_TXN_PER_MICROBLOCK) * (r*t)**v * exp(-r*t)/factorial(v), v, MAX_TXN_PER_MICROBLOCK-x, oo)

# We model microblock execution times as a linear function of the number
# of transactions in the microblock, up to the limit.  a is the
# per-microblock overhead, and b is the marginal per-transaction cost,
# both in microseconds.  (Microseconds probably makes the numerics
# easier.)
a=900; b=5;

# We model transaction arrival as a Poisson process with an expected
# rate of r, measured in transactions per microsecond.
r=1;

# The rest of firedancer uses nanoseconds, so store it as nanos.
ns_delay = [0]*(MAX_TXN_PER_MICROBLOCK+1)
ns_delay[0] = 1<<64 - 1; # ULONG_MAX

for x in range(1,MAX_TXN_PER_MICROBLOCK):
    # Suppose we start with x transactions and wait an additional t
    # microseconds before we schedule a microblock.  The number of
    # additional transactions we receive in that wait period is
    # distributed with a Poisson distribution.  Then we can compute the
    # expected value of (transactions executed)/(wait time+execution
    # time) and find the value of t that maximizes the expected value.
	ex_expr =  sum( (x+v)/(t+a+b*(x+v)) * (r*t)**v * exp(-r*t)/factorial(v), v, 0, MAX_TXN_PER_MICROBLOCK-1-x) + sum(MAX_TXN_PER_MICROBLOCK/(t+a+b*MAX_TXN_PER_MICROBLOCK) * (r*t)**v * exp(-r*t)/factorial(v), v, MAX_TXN_PER_MICROBLOCK-x, oo)

    # Maximize by solving d E[throughput] / dt == 0.  This seems to work
    # better than Sage's maximization functions.  Based on the shape of
    # the function, I'm pretty sure this is always a maximum.
	ex_deriv = derivative(ex_expr, t)
	ns_delay[x] = int(1000*find_root( ex_deriv, 0, 1000)+0.5)

with open('pack_delay.bin', 'wb') as f:
    f.write(struct.pack('<'+str(MAX_TXN_PER_MICROBLOCK+1)+'Q', *ns_delay))
print(ns_delay)
