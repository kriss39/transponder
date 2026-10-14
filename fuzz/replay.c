/*
 * Run a fuzz target over files, without libFuzzer: for compilers that lack
 * it, and to replay the corpus under the sanitizers in CI.
 *
 *   make fuzz-replay
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    static uint8_t buf[1 << 16];
    int i;

    for (i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        size_t n;
        if (!f) {
            fprintf(stderr, "cannot open %s\n", argv[i]);
            return 1;
        }
        n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, n);
    }
    printf("replayed %d inputs\n", argc - 1);
    return 0;
}
