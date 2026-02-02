#!/usr/bin/env python3
"""
Generate pack_delay.bin.

Tries to use Sage for symbolic computation if available, otherwise falls
back to scipy for numerical computation.
"""

import struct

MAX_TXN_PER_MICROBLOCK = 10

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
ns_delay[0] = (1<<64) - 1; # ULONG_MAX

try:
    from sage.all import var, sum, exp, factorial, derivative, find_root, oo, Integer

    MAX_TXN_PER_MICROBLOCK = Integer(MAX_TXN_PER_MICROBLOCK)
    var('x,v,t')

    # I have no idea why, but without this line here, sage gives an error
    ex_expr =  sum( (x+v)/(t+a+b*(x+v)) * (r*t)**v * exp(-r*t)/factorial(v), v, 0, MAX_TXN_PER_MICROBLOCK-1-x) + sum(MAX_TXN_PER_MICROBLOCK/(t+a+b*MAX_TXN_PER_MICROBLOCK) * (r*t)**v * exp(-r*t)/factorial(v), v, MAX_TXN_PER_MICROBLOCK-x, oo)

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

except ImportError:
    from scipy.optimize import brentq
    from math import exp, factorial

    for x in range(1,MAX_TXN_PER_MICROBLOCK):
        # Suppose we start with x transactions and wait an additional t
        # microseconds before we schedule a microblock.  The number of
        # additional transactions we receive in that wait period is
        # distributed with a Poisson distribution.  Then we can compute the
        # expected value of (transactions executed)/(wait time+execution
        # time) and find the value of t that maximizes the expected value.
        def ex_expr(t):
            # sum( (x+v)/(t+a+b*(x+v)) * (r*t)**v * exp(-r*t)/factorial(v), v, 0, MAX_TXN_PER_MICROBLOCK-1-x)
            s1 = sum( (x+v)/(t+a+b*(x+v)) * (r*t)**v * exp(-r*t)/factorial(v) for v in range(0, MAX_TXN_PER_MICROBLOCK-x) )
            # sum(MAX_TXN_PER_MICROBLOCK/(t+a+b*MAX_TXN_PER_MICROBLOCK) * (r*t)**v * exp(-r*t)/factorial(v), v, MAX_TXN_PER_MICROBLOCK-x, oo)
            # The infinite sum from v=MAX-x to infinity is the tail of Poisson CDF
            s2_terms = sum( (r*t)**v * exp(-r*t)/factorial(v) for v in range(0, MAX_TXN_PER_MICROBLOCK-x) )
            s2 = MAX_TXN_PER_MICROBLOCK/(t+a+b*MAX_TXN_PER_MICROBLOCK) * (1 - s2_terms)
            return s1 + s2

        # Maximize by solving d E[throughput] / dt == 0. Based on the shape of
        # the function, I'm pretty sure this is always a maximum.
        def ex_deriv(t, dx=1e-6):
            return (ex_expr(t+dx) - ex_expr(t-dx)) / (2*dx)

        ns_delay[x] = int(1000*brentq( ex_deriv, 0.1, 1000)+0.5)

with open('pack_delay.bin', 'wb') as f:
    f.write(struct.pack('<'+str(MAX_TXN_PER_MICROBLOCK+1)+'Q', *ns_delay))
print(ns_delay)
