/*
 * Run a fuzz target over files, without libFuzzer: for compilers that lack
 * it, and to replay the corpus under the sanitizers in CI.
 *
 *   make fuzz-replay
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    static uint8_t buf[1 << 16];
    int i;

    for (i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        uint8_t *exact;
        size_t n;
        if (!f) {
            fprintf(stderr, "cannot open %s\n", argv[i]);
            return 1;
        }
        n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        /* An exact-size heap copy, as libFuzzer passes, so ASan sees a read past the end. */
        exact = (uint8_t *)malloc(n ? n : 1);
        if (!exact) return 1;
        memcpy(exact, buf, n);
        LLVMFuzzerTestOneInput(exact, n);
        free(exact);
    }
    printf("replayed %d inputs\n", argc - 1);
    return 0;
}
