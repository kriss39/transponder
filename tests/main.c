#include "test.h"

int trp_test_failures = 0;
int trp_test_checks = 0;

static void run(const char *name, void (*fn)(void))
{
    int before = trp_test_failures;
    fn();
    printf("%s %s\n", trp_test_failures == before ? "ok  " : "FAIL", name);
}

int main(void)
{
    run("hex", test_hex);
    run("keccak", test_keccak);
    run("rlp", test_rlp);
    run("base64url", test_base64url);
    run("json", test_json);
    run("challenge", test_challenge);
    run("tempo", test_tempo);

    printf("\n%d checks, %d failed\n", trp_test_checks, trp_test_failures);
    return trp_test_failures == 0 ? 0 : 1;
}
