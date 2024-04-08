
import random
import numbers

import ref_ed25519

class Expr:
    '''
        Expr class is used to generate the sequence of machine instructions
        needed to compute the ed25519 verify procedure using the processor
        implemented inside hw-sigverify.

        Expr class tracks the sequence of python expressions executed as an
        arbitrary piece of python code is evaluated.  Optimizations include
        constant propagation, deadcode elimination, and minimum register
        allocation.

        If statements are not supported as the entire datapath of the code
        is meant to be executed regardless of the input data.  Instead, 
        ternary operator is introduced which allows for Expr class to track
        both branches of the datapath.  In hardware terminology, all paths are
        executed and the correct data is multiplexed using ternary operators.

        To start an expression tracker:
            - Expr.reset()
            - Simply invoke the target python code with all input variables
            initialized as Expr(var=True):
                - ab = add_a_and_b(Expr(var=True), Expr(var=true))
            - Provide all the outputs of the executed code to Expr.outputs().
            This step is necessary as Expr has no other means of tracking what
            constitutes the intended output list.
                - Expr.outputs(ab)
        
    '''
    trace_q = None
    op_hist = None
    op_args = None
    func_const_prop = True
    def reset():
        Expr.func_const_prop = False
        Expr.maddr = 0
        Expr.caddr = 0
        Expr.trace_q = list()
        Expr.op_hist = dict()
        Expr.op_args = dict()
        Expr.outs = list()

    def outputs(outs):
        if isinstance(outs, Expr):
            outs = [outs]
        Expr.outputs = outs
        for t in Expr.outputs:
            t.out = True
            Expr.outs.append(t)
        Expr.opt_trace()

    def __init__(
            self,
            left    = None,
            op      = None,
            right   = None,
            cond    = None,
            func    = None,
            args    = None,
            var     = False,
            out     = False,
        ):
        self.v = None
        self.t = None
        self.c = False
        self.func = None
        self.op = None
        self.args = None
        self.addr = None
        self.out = False

        if func != None:
            self.func = func
            self.args = args
            self.c = Expr.func_const_prop
            e_args = list()
            for a in args:
                e_a = a if isinstance(a, Expr) else Expr(a)
                e_args.append(e_a)
                if not e_a.c:
                    self.c = False
            self.args = e_args
            if self.c:
                self.c = False
                left = self.eval()
                self.c = True
                self.func = None
                self.args = [left]
        elif op == None:
            if var == True:
                e_left = left if isinstance(left, Expr) else Expr(left)
                self.func = 'input'
                self.args = []
            else:
                if isinstance(left, numbers.Integral):
                # if type(left) in [int, long]:
                    self.c = True
                    self.args = [left]
                else:
                    print (type(left))
                    WTF
        elif op == 'if':
            e_left = left if isinstance(left, Expr) else Expr(left)
            e_right = right if isinstance(right, Expr) else Expr(right)
            e_cond = cond if isinstance(cond, Expr) else Expr(cond)
            if e_cond.c:
                if e_cond.eval() != 0:
                    self.copy(e_left)
                else:
                    self.copy(e_right)
            else:
                self.func = 'ternary'
                self.args = [e_left, e_right, e_cond]
        else:
            e_left = left if isinstance(left, Expr) else Expr(left)
            e_right = right if isinstance(right, Expr) else Expr(right)
            self.func = 'op'
            self.op = op
            self.args = (e_left, e_right)
            # constant propagation
            if e_left.c and e_right.c:
                left = self.eval()
                self.func = None
                self.op = None
                self.c = True
                self.args = [left]

        if not self.c:
            Expr.trace_q.append(self)
        self.eval()

    def copy(self, r):
        self.v = r.v
        self.t = r.t
        self.c = r.c
        self.op = r.op
        self.func = r.func
        self.args = r.args
        self.addr = r.addr

    def eval(self):
        if self.v == None:
            if False:
                pass
            elif self.c == True:
                self.v = self.args[0]
            elif self.func == 'input':
                self.v = 0
            elif self.func == 'if':
                left = self.args[0].eval()
                right = self.args[1].eval()
                cond = self.args[2].eval()
                self.v = eval('{} if {} else {}'.format(left, cond, right))
            elif self.func == 'op':
                left = self.args[0].eval()
                right = self.args[1].eval()
                self.v = eval('{} {} {}'.format(left, self.op, right))
            elif self.func != None:
                self.v = eval('{}({})'.format(self.func, ','.join([str(e.eval()) for e in self.args])))
            else:
                WTF

            self.v = int(self.v)
        return self.v

    def __add__(self, v):
        return Expr(self, '+', v)

    def __sub__(self, v):
        return Expr(self, '-', v)

    def __rshift__(self, v):
        return Expr(self, '>>', v)

    def __lshift__(self, v):
        return Expr(self, '<<', v)

    def __and__(self, v):
        return Expr(self, '&', v)

    def __eq__(self, v):
        return Expr(self, '==', v)

    def __ne__(self, v):
        return Expr(self, '!=', v)

    def __ge__(self, v):
        return Expr(self, '>=', v)

    def __int__(self):
        return self.eval()

    def __repr__(self):
        return '[{} {} {} {} {}]'.format(
            self.func,
            self.op,
            [a.addr for a in self.args],
            self.c,
            self.addr,
        )
    
    def __hash__(self):
        return id(self)

    def mem(self):
        if self.addr == None:
            WTF
            return '0x{:x}'.format(self.expr[0])
        elif self.c:
            return 'c{}'.format(self.caddr)
        else:
            return 'm{}'.format(self.addr)

    # def eval_trace(inputs):
    #     inputs = inputs[::]
    #     mem = dict()
    #     con = dict()

    #     # store inputs in the first spots
    #     for i in range(len(inputs)):
    #         mem[str(i)] = inputs[i]

    #     def get_v(t):
    #         if t.addr[0] == 'c':
    #             return t.v#con[t.addr[1:]]
    #         return mem[Expr.mmap[t.addr[1:]]]
    #     def put_v(t, r):
    #         mem[Expr.mmap[t.addr[1:]]] = r

    #     for t in Expr.trace_q:
    #         if t.c:
    #             r = None
    #         elif t.func == 'input':
    #             r = None
    #         elif t.func == 'op' and t.op == '+':
    #             r = get_v(t.args[0]) + get_v(t.args[1])
    #         elif t.func == 'op' and t.op == '-':
    #             r = get_v(t.args[0]) - get_v(t.args[1])
    #         elif t.func == 'op' and t.op == '&':
    #             r = get_v(t.args[0]) & get_v(t.args[1])
    #         elif t.func == 'op' and t.op == '<<':
    #             r = get_v(t.args[0]) << get_v(t.args[1])
    #         elif t.func == 'op' and t.op == '>>':
    #             r = get_v(t.args[0]) >> get_v(t.args[1])
    #         elif t.func == 'op' and t.op == '==':
    #             r = int(get_v(t.args[0]) == get_v(t.args[1]))
    #         elif t.func == 'op' and t.op == '!=':
    #             r = int(get_v(t.args[0]) != get_v(t.args[1]))
    #         elif t.func == 'op' and t.op == '>=':
    #             r = int(get_v(t.args[0]) >= get_v(t.args[1]))
    #         elif t.func == 'mul_modp':
    #             r = (get_v(t.args[0]) * get_v(t.args[1])) % ref_ed25519.p
    #         elif t.func == 'add_modp':
    #             r = add_modp(get_v(t.args[0]), get_v(t.args[1]), ref_ed25519.p)
    #         elif t.func == 'sub_modp':
    #             r = sub_modp(get_v(t.args[0]), get_v(t.args[1]), ref_ed25519.p)
    #         elif t.func == 'ternary':
    #             # we only check the first bit
    #             r = get_v(t.args[0]) if (get_v(t.args[2]) & 1) else get_v(t.args[1])
    #         elif t.func == 'dsdp_sel':
    #             # we only check the first bit
    #             r = dsdp_sel(get_v(t.args[0]), get_v(t.args[1]))
    #         elif t.func == 'ternary_dsdp_x':
    #             r = ternary_dsdp_x(get_v(t.args[0]), get_v(t.args[1]), get_v(t.args[2]))
    #         elif t.func == 'ternary_dsdp_y':
    #             r = ternary_dsdp_y(get_v(t.args[0]), get_v(t.args[1]), get_v(t.args[2]))
    #         elif t.func == 'ternary_dsdp_z':
    #             r = ternary_dsdp_z(get_v(t.args[0]), get_v(t.args[1]), get_v(t.args[2]))
    #         elif t.func == 'ternary_dsdp_t':
    #             r = ternary_dsdp_t(get_v(t.args[0]), get_v(t.args[1]), get_v(t.args[2]))
    #         else:
    #             WTF

    #         # dead code
    #         if t.addr == None:
    #             r = None
    #         if r != None:
    #             # print ('mem[{}] = {:x}'.format(t.addr, r))
    #             put_v(t, r)
    #             t.r = r
    #     rs = list()
    #     for o in Expr.outs:
    #         rs.append(o.r)
    #     return tuple(rs)

    def opt_trace():
        mfree = list()
        mmap = dict()
        cmap = dict()
        Expr.consts = list()
        Expr.mmap = dict()
        Expr.max_i = 0
        Expr.max_c = 0
        Expr.max_m = 0
        Expr.n_dead = 0

        def tmap(t):
            if t.c:
                if t.args[0] not in cmap:
                    cmap[t.args[0]] = Expr.max_c
                    Expr.consts.append(t.args[0])
                    Expr.max_c += 1
                t.addr = 'c{}'.format(cmap[t.args[0]])
            else:
                if t not in mmap:
                    if len(mfree) == 0:
                        mfree.append(Expr.max_m)
                        Expr.max_m += 1
                    mmap[t] = mfree.pop(0)
                t.addr = 'm{}'.format(mmap[t])
        def tfree(t):
            if t.c:
                WTF
            else:
                if t in mmap:
                    mfree.append(mmap[t])
                    del mmap[t]
                else:
                    t.dead = True
                    Expr.n_dead += 1

        # allocate inputs, outputs, and consts
        for t in Expr.trace_q:
            if t.func == 'input':
                # t.addr_i = 'i{}'.format(Expr.max_i)
                tmap(t)
                Expr.max_i += 1
            elif t.c:
                tmap(t)
        for t in Expr.outputs:
            tmap(t)

        for ti in range(len(Expr.trace_q)-1, -1, -1):
            t = Expr.trace_q[ti]
            op = t.func

            targs = []
            if t.c:
                WTF
            elif t.func == 'input':
                pass
            elif t.func.startswith('ternary'):
                targs = t.args
            elif t.func == 'op':
                op = t.op
                targs = t.args
            elif t.func != None:
                targs = t.args
            else:
                WTF

            # free dest
            if t.func != 'input':
                tfree(t)

            # allocate args
            for targ in targs:
                tmap(targ)

            # opcode and arg historgram
            Expr.op_hist.setdefault(op, 0)
            Expr.op_hist[op] += 1
            Expr.op_args.setdefault(op, dict())
            args = [_.v if _.c else 'var' for _ in targs]
            args = tuple(args)
            Expr.op_args[op].setdefault(args, 0)
            Expr.op_args[op][args] += 1

            Expr.trace_q[ti] = t

        for op in Expr.op_hist:
            print ('{}: {}'.format(op, Expr.op_hist[op]))
            if op in Expr.op_args:
                for a in Expr.op_args[op]:
                    print ('    {}: {}'.format(Expr.op_args[op][a], a))

        Expr.max_mem = Expr.max_i + Expr.max_m + Expr.max_c
        print ('{} = {} + {} + {}'.format(
            Expr.max_mem,
            Expr.max_i,
            Expr.max_m,
            Expr.max_c,
        ))
        print ('n_dead: {}'.format(Expr.n_dead))

        # Expr.mmap = dict()
        # for i in range(Expr.max_mem):
        #     Expr.mmap[str(i)] = None
        # for t in Expr.trace_q:
        #     if t.func == 'input':
        #         Expr.mmap[t.addr[1:]] = t.addr_i[1:]
        # _i = Expr.max_i
        # for i in range(Expr.max_mem):
        #     if Expr.mmap[str(i)] == None:
        #         Expr.mmap[str(i)] = str(_i)
        #         _i += 1

    # n = number of copies
    # r = number of rows per copy
    def dump_const_hex(n, r, format='hex'):
        hex_st = ''
        h_i = 0
        for i in range(n):
            if format == 'hex':
                # hex_st = '@{:08x}\n'.format(Expr.max_m)
                hex_st = '@{:08x}\n'.format(4)
            if format == 'coe':
                hex_st = 'memory_initialization_radix=16;\n'
                hex_st += 'memory_initialization_vector=\n'
            # hex_st += '@{:08x}\n'.format(i*r)
            for ci in range(len(Expr.consts)):
                if format == 'hex':
                    hex_st += '{:064x}\n'.format(Expr.consts[ci])
                if format == 'coe':
                    if h_i > 0:
                        hex_st += ',\n'
                    h_i += 1
                    hex_st += '{:064x}'.format(Expr.consts[ci])
        if format == 'coe':
            hex_st += ';'
        return hex_st

    #   // Instruction ROM
    #   // { 5 [op], 6 [INA], 6[INB], 6[INC], 6[OUT] }
    def dump_instr_hex(format='hex'):
        if format == 'hex':
            hex_st = '@{:08x}\n'.format(0)
        if format == 'coe':
            hex_st = 'memory_initialization_radix=16;\n'
            hex_st += 'memory_initialization_vector=\n'
        if format == 'mif':
            hex_st = ''

        mmap = dict()
        for i in range(4):
            mmap['m{}'.format(i)] = i
        for i in range(Expr.max_c):
            mmap['c{}'.format(i)] = 4+i
        for i in range(Expr.max_m):
            mmap['m{}'.format(4+i)] = 0x24+i

        h_i = 0
        for t in Expr.trace_q:

            a = 'm0'
            b = 'm0'
            c = 'm0'
            if t.c:
                WTF
            elif t.func == 'input':
                continue
            elif t.func.startswith('ternary'):
                a = t.args[0].addr
                b = t.args[1].addr
                c = t.args[2].addr
            elif t.func == 'op':
                a = t.args[0].addr
                b = t.args[1].addr
            elif t.func != None:
                a = t.args[0].addr
                b = t.args[1].addr
            else:
                WTF
            a = mmap[a]
            b = mmap[b]
            c = mmap[c]
            d = mmap[t.addr]

            if t.func == 'op' and t.op == '&':
                op = 0
            elif t.func == 'op' and t.op == '==':
                op = 1
            elif t.func == 'op' and t.op == '!=':
                op = 2
            elif t.func == 'op' and t.op == '>=':
                op = 3
            elif t.func == 'op' and t.op == '<<':
                op = 4
            elif t.func == 'op' and t.op == '>>':
                op = 5
            elif t.func == 'op' and t.op == '+':
                op = 6
            elif t.func == 'op' and t.op == '-':
                op = 7
            elif t.func == 'add_modp':
                op = 8
            elif t.func == 'sub_modp':
                op = 9
            elif t.func == 'mul_modp':
                op = 10
            elif t.func == 'ternary':
                op = 0x1B
            else:
                WTF

            h = (op << (4*6)) | (a << (3*6)) | (b << (2*6)) | (c << (1*6)) | (d << (0*6))
            if format == 'mif':
                hex_st += '{:029b}\n'.format(h)
            if format == 'hex':
                hex_st += '{:08x}\n'.format(h)
            if format == 'coe':
                if h_i > 0:
                    hex_st += ',\n'
                h_i += 1
                hex_st += '{:08x}'.format(h)

        for ti in range(len(Expr.outputs)):
            t = Expr.outputs[ti]
            op = 0xC
            a = mmap[t.addr]
            b = mmap[t.addr]
            c = mmap[t.addr]
            d = ti
            
            h = (op << (4*6)) | (a << (3*6)) | (b << (2*6)) | (c << (1*6)) | (d << (0*6))
            if format == 'mif':
                hex_st += '{:029b}\n'.format(h)
            if format == 'hex':
                hex_st += '{:08x}\n'.format(h)
            if format == 'coe':
                if h_i > 0:
                    hex_st += ',\n'
                h_i += 1
                hex_st += '{:08x}'.format(h)

        if format == 'coe':
            hex_st += ';'
        return hex_st

    def eval_hex(const_hex, instr_hex, inputs):
        mem = dict()
        rs = list()

        for i in range(len(inputs)):
            mem[i] = inputs[i]

        off_c = None
        for l in const_hex.split("\n"):
            if l == '':
                continue
            if off_c == None:
                if l == 'memory_initialization_radix=16;':
                    continue
                elif l == 'memory_initialization_vector=':
                    off_c = 4
                else:
                    off_c = int(l[1:], 16)
            else:
                l = l.rstrip(',;')
                mem[off_c] = int(l, 16)
                off_c += 1

        for l in instr_hex.split("\n")[1:]:
            if l == '':
                continue
            if l == 'memory_initialization_radix=16;':
                continue
            if l == 'memory_initialization_vector=':
                continue
            l = l.rstrip(',;')
            instr = int(l, 16)

            d = bits(instr, 6, 0*6)
            c = bits(instr, 6, 1*6)
            b = bits(instr, 6, 2*6)
            a = bits(instr, 6, 3*6)
            o = bits(instr, 5, 4*6)

            c = mem[c]
            b = mem[b]
            a = mem[a]

            if o == 0:
                r = a & b
            elif o == 1:
                r = int(a == b)
            elif o == 2:
                r = int(a != b)
            elif o == 3:
                r = int(a >= b)
            elif o == 4:
                r = bits(a << b, 256, 0)
            elif o == 5:
                r = bits(a >> b, 256, 0)
            elif o == 6:
                r = a + b
            elif o == 7:
                r = a - b
            elif o == 8:
                r = add_modp(a, b, ref_ed25519.p)
            elif o == 9:
                r = sub_modp(a, b, ref_ed25519.p)
            elif o == 10:
                r = mul_modp3(a, b, ref_ed25519.p)
            elif o == 0x1B:
                r = a if c!=0 else b
            elif o == 0xC:
                rs.append(a)
            else:
                WTF

            mem[d] = r

        return tuple(rs)





def bits(n, b, s):
    return (n >> s) & ((1<<b)-1)

def rand_int(w=256):
    n = 0
    for i in range(w):
        n |= random.randint(0, 1) << i
    return n

def ternary(c, x, y):
    r = x if c else y
    return Expr(x, 'if', y, c)

def ternary_p(c, x, y):
    r = x if c else y
    return r

def mul_modp(x, y, p):

    # math:
    # p = b-c
    # x*b % (b-c) = x*c % (b-c)

    p2 = p*2
    xy = x * y

    l = bits(xy, 256,   0)
    h = bits(xy, 256, 256)

    m = l
    for i in range(0, -1, -1):
        m = ternary_p(m >= (p2<<i), m - (p2<<i), m)

    # *38
    mm = (h << 1) + (h << 2) + (h << 5)
    for i in range(5, -1, -1):
        mm = ternary_p(mm >= (p2<<i), mm - (p2<<i), mm)

    m = m + mm
    for i in range(1, -1, -1):
        m = ternary_p(m >= (p<<i), m - (p<<i), m)

    return m

def mul_modp2(x, y, p):

    x0 = bits(x, 128,   0)
    x1 = bits(x, 127, 128)

    y0 = bits(y, 128,   0)
    y1 = bits(y, 127, 128)

    x0y0 = x0 * y0
    x1y1 = x1 * y1

    # print ('Z: {:x}'.format(x0y0))
    # print ('Y: {:x}'.format(x1y1))

    x0x1 = x0 + x1
    y0y1 = y0 + y1

    # print ('T: {:x}'.format(x0x1))
    # print ('S: {:x}'.format(y0y1))

    xy = bits(x0x1, 129, 0) * bits(y0y1, 129, 0)

    # print ('X: {:x}'.format(xy))

    C0 = bits(x0y0, 256, 0)
    C1 = bits(xy  , 258, 0)
    C2 = bits(x1y1, 256, 0)

    C0C2 = C0 + C2

    # print ('W: {:x}'.format(C0C2))

    C = C0
    C += (C2 << 1) + (C2 << 2) + (C2 << 5)
    # print ('U: {:x}'.format(C))
    C += (C1 - bits(C0C2, 258, 0)) << 128
    # print ('R: {:x}'.format(C))

    Cl = bits(C, 255,   0)
    Ch = bits(C, 132, 255)

    Ch19 = (Ch << 0) + (Ch << 1) + (Ch << 4)
    Cp = Cl + Ch19

    if Cp >= p:
        Cp -= p

    return Cp

def mul_modp3(x, y, p):

    x0 = bits(x, 128,   0)
    x1 = bits(x, 127, 128)

    y0 = bits(y, 128,   0)
    y1 = bits(y, 127, 128)

    A = bits(x0 * y0, 256, 0)
    B = bits(x0 * y1, 255, 0)
    C = bits(x1 * y0, 255, 0)
    D = bits(x1 * y1, 254, 0)

    E = A + (B << 128) + (C << 128) + (D << 1) + (D << 2) + (D << 5)

    El = bits(E, 255, 0)
    Eh = bits(E, 132, 255)

    F = El + (Eh << 0) + (Eh << 1) + (Eh << 4)

    G = F - (p if F >= p else 0)

    # print ('A = {:x}'.format(A))
    # print ('B = {:x}'.format(B))
    # print ('C = {:x}'.format(C))
    # print ('D = {:x}'.format(D))
    # print ('E = {:x}'.format(E))
    # print ('F = {:x}'.format(F))
    # print ('G = {:x}'.format(G))

    return G

def flip(n, b):
    nn = 0
    for i in range(b):
        _ = 0 if (n & 1) else 1
        nn |= _ << i
        n >>= 1
    return nn

def mul_modp4(x, y, p):

    x0 = bits(x, 128,   0)
    x1 = bits(x, 127, 128)

    y0 = bits(y, 128,   0)
    y1 = bits(y, 127, 128)

    A = bits(x0 + x1, 129, 0)
    B = bits(y0 + y1, 129, 0)

    C = bits(x0 * y0, 256, 0)
    D = bits(x1 * y1, 254, 0)

    M = bits(A * B, 258, 0)
    N = bits((D << 1) + (D << 2) + (D << 5), 260, 0)

    print ('A: {:x}'.format(A))
    print ('B: {:x}'.format(B))

    print ('C: {:x}'.format(C))
    print ('D: {:x}'.format(D))

    print ('M: {:x}'.format(M))
    print ('N: {:x}'.format(N))

    E = C + N + (M << 128) - (C << 128) - (D << 128)

    print ('E: {:x}'.format(E))

    El = bits(E, 255, 0)
    Eh = bits(E, 132, 255)

    F = El + (Eh << 0) + (Eh << 1) + (Eh << 4)

    G = F - (p if F >= p else 0)

    # print ('A = {:x}'.format(A))
    # print ('B = {:x}'.format(B))
    # print ('C = {:x}'.format(C))
    # print ('D = {:x}'.format(D))
    # print ('E = {:x}'.format(E))
    # print ('F = {:x}'.format(F))
    # print ('G = {:x}'.format(G))

    return G

def kpow_2k(x, y, p):
    for i in range(y):
        x = Expr(func='mul_modp', args=(x, x, p))
    return x

def kpow_ed250(x, p):
    t0  = Expr(func='mul_modp', args=(x, x, p))                 # 1
    t00 = Expr(func='mul_modp', args=(t0, t0, p))               # 2
    t1  = Expr(func='mul_modp', args=(t00, t00, p))             # 3
    t2  = Expr(func='mul_modp', args=(x, t1, p))                # x^(2^(1001))
    t3  = Expr(func='mul_modp', args=(t0, t2, p))               # 3,1,0
    t4  = Expr(func='mul_modp', args=(t3, t3, p))               # 4,2,1
    t5  = Expr(func='mul_modp', args=(t2, t4, p))               # 4,3,2,1,0
    t6  = kpow_2k(t5, 5, p)                                     # 9,8,7,6,5
    t7  = Expr(func='mul_modp', args=(t6, t5, p))               # 9,8,7,6,5,4,3,2,1,0
    t8  = kpow_2k(t7, 10, p)                                    # 19..10
    t9  = Expr(func='mul_modp', args=(t8, t7, p))               # 19..0
    t10 = kpow_2k(t9, 20, p)                                    # 39..20
    t11 = Expr(func='mul_modp', args=(t10, t9, p))              # 39..0
    t12 = kpow_2k(t11, 10, p)                                   # 49..10
    t13 = Expr(func='mul_modp', args=(t12, t7, p))              # 49..0
    t14 = kpow_2k(t13, 50, p)                                   # 99..50
    t15 = Expr(func='mul_modp', args=(t14, t13, p))             # 99..0
    t16 = kpow_2k(t15, 100, p)                                  # 199..100
    t17 = Expr(func='mul_modp', args=(t16, t15, p))             # 199..0
    t18 = kpow_2k(t17, 50, p)                                   # 249..50
    t19 = Expr(func='mul_modp', args=(t18, t13, p))             # 249..0

    return t0, t3, t19

def kpow_ed255192(x, p):
    t0, t3, t19 = kpow_ed250(x, p)
    t20 = kpow_2k(t19, 5, p)                                    # 254..5
    t21 = Expr(func='mul_modp', args=(t20, t3, p))              # 254..5,3,1,0
    return t21

def kpow_ed2551938(x, p):
    t0, t3, t19 = kpow_ed250(x, p)
    t20 = kpow_2k(t19, 2, p)                                    # 251..2
    t21 = Expr(func='mul_modp', args=(t20, t0, p))              # 251..2,1

    return t21

def kpow(x, y, p):
    a = Expr(1)
    y = Expr(y)
    wy = y.eval().bit_length()
    for i in range(wy):
        xx = ternary(y & 1, x, 1)
        a = Expr(func='mul_modp', args=(a, xx, p))
        x = Expr(func='mul_modp', args=(x, x, p))
        y = y >> 1
    return a

def add_modp(a, b, p):
    return (a + b) % p


def sub_modp(a, b, p):
    if a >= b:
        return a - b
    else:
        return a - b + p

def dsdp_sel(sh2, h):
    b0 = bits(sh2, 1, 255)
    b1 = bits(h, 1, 255)
    b0b1 = b0 & b1
    if b0b1:
        return 3
    if b1:
        return 2
    if b0:
        return 1
    return 0

def ternary_dsdp_x(sel, A, T):
    if sel == 0:
        return 0
    if sel == 1:
        return ref_ed25519.G[0]
    if sel == 2:
        return A
    return T

def ternary_dsdp_y(sel, A, T):
    if sel == 0:
        return 1
    if sel == 1:
        return ref_ed25519.G[1]
    if sel == 2:
        return A
    return T

def ternary_dsdp_z(sel, A, T):
    if sel == 0:
        return 1
    if sel == 1:
        return ref_ed25519.G[2]
    if sel == 2:
        return A
    return T

def ternary_dsdp_t(sel, A, T):
    if sel == 0:
        return 0
    if sel == 1:
        return ref_ed25519.G[3]
    if sel == 2:
        return A
    return T






def ed25519_dsdp_mul(A, As, Gs, W_S=256):

    Z = (0, 1, 1, 0)
    Z = ref_ed25519.point_add(Z, Z)
    G = ref_ed25519.G
    T = ref_ed25519.point_add(A, G)

    for i in range(W_S):

        # taking advantage of the fact
        # ternary only checks LSB
        b0 = (Gs >> 255) & 0x1
        b1 = (As >> 255) & 0x1
        b0b1 = b0 & b1

        As = As << 1
        Gs = Gs << 1

        qx = G[0] if (b0 == 1)      else 0
        qx = A[0] if (b1 == 1)      else qx
        qx = T[0] if (b0b1 == 1)    else qx

        qy = G[1] if (b0 == 1)      else 1
        qy = A[1] if (b1 == 1)      else qy
        qy = T[1] if (b0b1 == 1)    else qy

        qz = G[2] if (b0 == 1)      else 1
        qz = A[2] if (b1 == 1)      else qz
        qz = T[2] if (b0b1 == 1)    else qz

        qt = G[3] if (b0 == 1)      else 0
        qt = A[3] if (b1 == 1)      else qt
        qt = T[3] if (b0b1 == 1)    else qt

        Q = (qx, qy, qz, qt)

        # if i > 0:
        # print ('{:b} {:b}'.format(b1, b0))
        # print ("{}_0: {:x} {:x}".format(i, Z[0]&0xFFFFFFFF, Z[0]&0xFFFFFFFF))
        # if i > 0:
        Z = ref_ed25519.point_add(Z, Z)
        # print ("{}_1: {:x} {:x}".format(i, Z[0]&0xFFFFFFFF, Q[0]&0xFFFFFFFF))
        Z = ref_ed25519.point_add(Z, Q)

    return Z


















if __name__ == '__main__':

    from ref_ed25519 import p

    while True:
        x = random.choice([
            0,
            1,
            p-random.randint(1, 5),
            rand_int(256) % p,
            (rand_int(255-128) << 128) | ((1<<128)-1)
        ])
        y = random.choice([
            0,
            1,
            p-random.randint(1, 5),
            rand_int(256) % p,
            (rand_int(255-128) << 128) | ((1<<128)-1)
        ])
        xy = x * y

        m_0 = xy % p
        m_1 = mul_modp4(x, y, p)

        print ('{:x} =?= \n{:x}'.format(m_0, m_1))
        if m_0 != m_1:
            WTF
