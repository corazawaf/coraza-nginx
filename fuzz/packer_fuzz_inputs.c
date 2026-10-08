/* Fixed inputs exercise the fuzz adapter without starting a fuzz campaign. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
main(void)
{
    const uint8_t zero[] = {0};
    const uint8_t ordinary[] = {2, 0, 1, 0, 2, 'N', 0, 'v', 0, 0, 0, 0};
    const uint8_t truncated[] = {1, 0xff, 0xff, 0xff, 0xff, 'n'};
    const uint8_t short_value[] = {1, 0, 0, 0xff, 0xff, 'v'};
    uint8_t maximum[1 + 4 + 2 * 65535];
    uint8_t many[1 + 4 * 32] = {255};

    LLVMFuzzerTestOneInput(NULL, 0);
    LLVMFuzzerTestOneInput(zero, sizeof(zero));
    LLVMFuzzerTestOneInput(ordinary, sizeof(ordinary));
    LLVMFuzzerTestOneInput(ordinary, 4);
    LLVMFuzzerTestOneInput(truncated, sizeof(truncated));
    LLVMFuzzerTestOneInput(short_value, sizeof(short_value));
    LLVMFuzzerTestOneInput(many, sizeof(many));
    memset(maximum, 0xff, sizeof(maximum));
    maximum[0] = 1;
    LLVMFuzzerTestOneInput(maximum, sizeof(maximum));
    puts("PASS: 8 fixed fuzz-adapter inputs");
    return 0;
}
