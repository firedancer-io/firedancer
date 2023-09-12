indent = 0
def cprint(string):
    global indent
    if (not string) or string.isspace():
        print(file=outf)
        return

    if "}" in string:
        indent -= 1
    print(" "*(2*indent) + string, file=outf)
    if "{" in string:
        indent += 1

def make_recover_var(n, max_shreds):
    global outf
    with open(f'fd_reedsol_recover_{n}.c', 'wt') as outf:
        cprint('#include "fd_reedsol_ppt.h"')
        cprint('#include "fd_reedsol_fderiv.h"')
        cprint('')

        cprint('int')
        fn_name = f'fd_reedsol_private_recover_var_{n}('
        cprint(fn_name +          " ulong           shred_sz,")
        cprint(" "*len(fn_name) + " uchar * const * shred,")
        cprint(" "*len(fn_name) + " ulong           data_shred_cnt,")
        cprint(" "*len(fn_name) + " ulong           parity_shred_cnt,")
        cprint(" "*len(fn_name) + " uchar const *   erased ) {")

        cprint(f"uchar _erased[ {n} ] W_ATTR;")
        cprint(f"uchar pi[      {n} ] W_ATTR;")
        cprint(f"ulong shred_cnt = data_shred_cnt + parity_shred_cnt;")

        cprint(f'ulong loaded_cnt = 0UL;')
        cprint(f'for( ulong i=0UL; i<{n}UL; i++) ' + '{')
        cprint(f'int load_shred = ((i<shred_cnt)&(loaded_cnt<data_shred_cnt))&&( erased[ i ]==0 );')
        cprint(f'_erased[ i ] = !load_shred;')
        cprint(f'loaded_cnt += (ulong)load_shred;')
        cprint('}')

        cprint(f'if( FD_UNLIKELY( loaded_cnt<data_shred_cnt ) ) return FD_REEDSOL_ERR_PARTIAL;')

        cprint('')
        cprint(f'fd_reedsol_private_gen_pi_{n}( _erased, pi );')
        cprint('')

        cprint("/* Store the difference for each shred that was regenerated.  This")
        cprint("   must be 0.  Otherwise there's a corrupt shred. */")
        cprint("gf_t diff = gf_zero();")

        cprint('')
        cprint("for( ulong shred_pos=0UL; shred_pos<shred_sz; /* advanced manually at end of loop */ ) {")

        cprint('/* Load exactly data_shred_cnt un-erased input shreds into')
        cprint('   their respective vector.  Fill the erased vectors with 0. */')
        for k in range(min(n, max_shreds)):
            cprint(f"gf_t in{k:02} = _erased[ {k:2} ] ? gf_zero() : gf_ldu( shred[ {k:2} ] + shred_pos );")
        for k in range(min(n, max_shreds),n):
            cprint(f"gf_t in{k:02} = gf_zero();")

        cprint('/* Technically, we only need to multiply the non-erased ones, since')
        cprint('   the erased ones are 0, but we know at least half of them are')
        cprint('   non-erased, and the branch is going to be just as costly as the')
        cprint('   multiply. */')

        for k in range(min(n, max_shreds)):
            cprint(f'in{k:02} = GF_MUL_VAR( in{k:02}, pi[ {k:2} ] );')

        all_vars = [ f'in{k:02}' for k in range(n) ]
        cprint(f"#define ALL_VARS " + ", ".join(all_vars))
        if n>64:
            cprint(f"#define ALL_VARS_REF &" + ", &".join(all_vars))
        cprint('')
        if n>64:
            cprint(f'fd_reedsol_ifft_{n}_0( ALL_VARS_REF );')
        else:
            cprint(f'FD_REEDSOL_GENERATE_IFFT( {n}, 0, ALL_VARS );')
        cprint('')
        cprint(f'FD_REEDSOL_GENERATE_FDERIV( {n}, ALL_VARS );')
        cprint('')
        if n>64:
            cprint(f'fd_reedsol_fft_{n}_0( ALL_VARS_REF );')
        else:
            cprint(f'FD_REEDSOL_GENERATE_FFT( {n}, 0, ALL_VARS );')
        cprint('')

        cprint("/* Again, we only need to multiply the erased ones, since we don't")
        cprint("   use the value of the non-erased ones anymore, but I'll take")
        cprint("   multiplies over branches most days. */")
        for k in range(min(n, max_shreds)):
            cprint(f'in{k:02} = GF_MUL_VAR( in{k:02}, pi[ {k:2} ] );')

        cprint("/* There are a couple of cases we have to handle:")
        cprint("    - If i<shred_cnt and erased[ i ], it's an actual erasure, so we")
        cprint("        need to store the generated value.")
        cprint("    - If i<shred_cnt and _erased[ i ] but not erased[ i ], it was a")
        cprint("        value that we ignored to ensure the data lies on a")
        cprint("        polynomial of the right order, so we need to compare the")
        cprint("        value we generated to the one that was there.")
        cprint("    - If i<shred_cnt and !_erased[ i ], then this is a value we")
        cprint("        actually used in the computation, but we destroyed it, so we")
        cprint("        need to reload the actual value of the shred in order to use the")
        cprint("        IFFT in the next step.")
        cprint("    - If i>=shred_cnt, do nothing, which will keep the value of the")
        cprint("        shred if it existed in the variable. */")

        cprint("""#define STORE_COMPARE_RELOAD( n, var ) do{                                                        \\
            if(       erased[ n ] )        gf_stu( shred[ n ] + shred_pos, var );                            \\
            else if( _erased[ n ] ) diff = GF_OR( diff, GF_ADD( var, gf_ldu( shred[ n ] + shred_pos ) ) );       \\
            else                    var  = gf_ldu( shred[ n ] + shred_pos );                                     \\
          } while( 0 )""")
        cprint("""#define STORE_COMPARE( n, var ) do{                                                         \\
        if(       erased[ n ] )        gf_stu( shred[ n ] + shred_pos, var );                          \\
        else                    diff = GF_OR( diff, GF_ADD( var, gf_ldu( shred[ n ] + shred_pos ) ) ); \\
      } while( 0 )""")
        cprint(f"switch( fd_ulong_min( shred_cnt, {n}UL ) ) " + "{")
        for k in range(min(n, max_shreds)-1, -1, -1):
            fallthru = ""
            if k>0:
                fallthru = " FALLTHRU"
            cprint(f"case {k+1:2}UL: STORE_COMPARE_RELOAD( {k:2}, in{k:02} );{fallthru}")
        cprint("}")
        cprint("")

        if max_shreds > n:
            cprint(f"ulong shreds_remaining = shred_cnt-fd_ulong_min( shred_cnt, {n}UL );")

        potential_shreds_remaining = max_shreds - n
        chunk_cnt = 0
        while potential_shreds_remaining>0:
            cprint("if( shreds_remaining>0UL ) {")
            cprint(f"FD_REEDSOL_GENERATE_IFFT( {n}, {n*chunk_cnt:2}, ALL_VARS );")
            cprint(f"FD_REEDSOL_GENERATE_FFT(  {n}, {n*(chunk_cnt+1):2}, ALL_VARS );")
            cprint("")
            cprint(f"switch( fd_ulong_min( shreds_remaining, {n}UL ) ) " + "{")
            for k in range(min(n-1, potential_shreds_remaining), -1, -1):
                fallthru = ""
                if k>0:
                    fallthru = " FALLTHRU"
                cprint(f"case {k+1:2}UL: STORE_COMPARE( {k+n*(chunk_cnt+1):2}, in{k:02} );{fallthru}")
            cprint("}")
            cprint(f'shreds_remaining -= fd_ulong_min( shreds_remaining, {n}UL );')
            cprint("}")

            potential_shreds_remaining -= n
            chunk_cnt += 1

        cprint("if( FD_UNLIKELY( GF_ANY( diff ) ) ) return FD_REEDSOL_ERR_CORRUPT;")

        cprint('shred_pos += GF_WIDTH;')
        cprint('shred_pos = fd_ulong_if( ((shred_sz-GF_WIDTH)<shred_pos) & (shred_pos<shred_sz), shred_sz-GF_WIDTH, shred_pos );')
        cprint('}')
        cprint('return FD_REEDSOL_SUCCESS;')
        cprint('}')

make_recover_var( 16, 67*2)
make_recover_var( 32, 67*2)
make_recover_var( 64, 67*2)
make_recover_var(128, 67*2)
make_recover_var(256, 67*2)
