#include "../../flamenco/runtime/tests/fd_exec_sol_compat.h"
#include <stdio.h>

int main(int argc, char ** argv) {
    printf("Executing!\n");
    for (int i = 1; i < argc; i++) {
        // Open the Protobuf file
        char * file_name = argv[i];
        FILE * file = fopen(file_name, "rb");
        assert(file);

        // Get the file size
        fseek(file, 0, SEEK_END);
        ulong in_sz = (ulong) ftell(file);
        fseek(file, 0, SEEK_SET);

        // Allocate memory to read in the file
        uchar * in = malloc(in_sz);
        assert(in);

        // Read in the file
        ulong bytes_read = fread(in, 1, in_sz, file);
        if (bytes_read != in_sz) {
            printf("Failed to read file.\n");
            return 1;
        }
        fclose(file);

        uchar out[32 * 1024];
        ulong out_sz = sizeof(out);

        sol_compat_init();

        int result = sol_compat_instr_execute_v1(out, &out_sz, in, in_sz);
        if (result) {
            printf("Execution successful.\n");
        } else {
            printf("Execution failed.\n");
        }

        sol_compat_fini();
    }

    printf("Done!\n");

    return 0;
}
