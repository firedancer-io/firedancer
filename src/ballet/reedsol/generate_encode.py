indent = 0
def cprint(string):
    global indent
    if "}" in string:
        indent -= 1
    print(" "*(2*indent) + string, file=outf)
    if "{" in string:
        indent += 1

def make_encode(min_data_shreds, max_data_shreds, max_parity_shreds):
    n = 2**(max_data_shreds - 1).bit_length()
    global outf
    with open(f'fd_reedsol_encode_{n}.c', 'wt') as outf:
        cprint('#include "fd_reedsol_ppt.h"')

        cprint('')
        cprint('void')
        fn_name = f'fd_reedsol_private_encode_{n}('
        cprint(fn_name + " ulong                 shred_sz,")
        cprint(" "*len(fn_name) + " uchar const * const * data_shred,")
        cprint(" "*len(fn_name) + " ulong                 data_shred_cnt,")
        cprint(" "*len(fn_name) + " uchar       * const * parity_shred,")
        cprint(" "*len(fn_name) + " ulong                 parity_shred_cnt ) {")

        cprint("for( ulong shred_pos=0UL; shred_pos<shred_sz; /* advanced manually at end of loop */ ) {")

        for k in range(0,min_data_shreds-1,2):
            cprint(f"gf_t in{k+0:02} = gf_ldu( data_shred[ {k+0:2} ] + shred_pos );  gf_t in{k+1:02} = gf_ldu( data_shred[ {k+1:2} ] + shred_pos );")
        for k in range(min_data_shreds-1, n, 4):
            cprint(f"gf_t in{k+0:02} = gf_zero();  gf_t in{k+1:02} = gf_zero();  gf_t in{k+2:02} = gf_zero();  gf_t in{k+3:02} = gf_zero();")

        cprint("switch( data_shred_cnt ) {")
        for k in range(max_data_shreds, min_data_shreds-1, -1):
            fallthru = ""
            if k>min_data_shreds:
                fallthru = " FALLTHRU"
            cprint(f"case {k:2}UL: in{k-1:02} = gf_ldu( data_shred[ {k-1:2} ] + shred_pos );"+ fallthru)
        cprint("}")
        all_vars = [ f'in{k:02}' for k in range(n) ]
        cprint(f"#define ALL_VARS " + ", ".join(all_vars))
        if n>=64:
            cprint(f"#define ALL_VARS_REF &" + ", &".join(all_vars))
        cprint("switch( data_shred_cnt ) {")
        if n <= max_data_shreds:
            cprint(f"case {n:2}UL: FD_REEDSOL_GENERATE_IFFT( {n:2}, {0:2}, ALL_VARS ); break;")
        for k in range(max_data_shreds-1, min_data_shreds-1, -1):
            if n<64:
                cprint(f"case {k:2}UL: FD_REEDSOL_GENERATE_PPT(  {n:2}, {k:2}, ALL_VARS ); break;")
            else:
                cprint(f"case {k:2}UL: fd_reedsol_ppt_{n}_{k}( ALL_VARS_REF ); break;")
        cprint("}")
        cprint(f"/* That generated the first {n}-data_shred_cnt parity shreds in the")
        cprint(f"   last {n}-data_shred_cnt variables. We might only need")
        cprint(f"   parity_shred_cnt of them though. */")

        cprint("ulong total_shreds = data_shred_cnt+parity_shred_cnt;")
        cprint("switch( data_shred_cnt ) {")
        for k in range(min_data_shreds, n):
            fallthru = ""
            if k<n-1:
                fallthru = " FALLTHRU"
            cprint(f"case {k:2}UL: if( total_shreds <= {k:2}UL ) break; gf_stu( parity_shred[ {k:2}UL-data_shred_cnt ] + shred_pos, in{k:02} ); in{k:02} = gf_zero();"+fallthru)
        cprint("}")
        cprint(f"ulong parity_produced  = fd_ulong_min( {n:2}UL - data_shred_cnt, parity_shred_cnt );")
        cprint(f"ulong parity_remaining = parity_shred_cnt - parity_produced;")

        potential_parity_remaining = max_parity_shreds
        rep = 0
        while potential_parity_remaining>0:
            cprint( "if( FD_UNLIKELY( parity_remaining>0UL ) ) {")
            cprint(f"/* Produce another {n} parity shreds */")
            if rep>0:
                cprint(f"FD_REEDSOL_GENERATE_IFFT( {n}, {n*rep}, ALL_VARS );")
            cprint(f"FD_REEDSOL_GENERATE_FFT(  {n}, {n*rep+n}, ALL_VARS );")
            cprint("switch( parity_remaining ) {")
            cprint("default:")
            for k in range(min(n, potential_parity_remaining), 0, -1):
                fallthru = ""
                if k>1:
                    fallthru = " FALLTHRU"
                cprint(f"case {k:2}UL: gf_stu( parity_shred[ {k-1:2}UL+parity_produced ] + shred_pos, in{k-1:02} );" + fallthru)
            cprint("}")
            cprint(f"parity_produced += fd_ulong_min( {min(n, potential_parity_remaining)}UL, parity_remaining );")
            cprint(f"parity_remaining = parity_shred_cnt - parity_produced;")
            cprint("}")

            rep += 1
            potential_parity_remaining -= n

        cprint("#undef ALL_VARS")
        cprint("/* In order to handle shred sizes that are not divisible by 32, we clamp")
        cprint("   shred_pos to shred_sz-32 when shred_sz-32<shred_pos<shred_sz")
        cprint("   (after the increment). */")
        cprint("shred_pos += GF_WIDTH;")
        cprint("shred_pos = fd_ulong_if( ((shred_sz-GF_WIDTH)<shred_pos) & (shred_pos<shred_sz), shred_sz-GF_WIDTH, shred_pos );")
        cprint("}")
        cprint("}")

make_encode( 1, 16, 68)
make_encode(17, 32, 68)
make_encode(33, 64, 68)
make_encode(65, 68, 68)
