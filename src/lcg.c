#include "crypto/lcg.h"
#include <stdlib.h>

enum crypto_status lcg_crypt(
    const unsigned char* input,
    size_t len,
    uint64_t x0,
    uint64_t a,
    uint64_t d,
    uint64_t m,
    unsigned char** output)
{
    if (!input || !output)
        return CRYPTO_ERROR_NULL_POINTER;

    if (m == 0)
        return CRYPTO_ERROR_INVALID_KEY;

    unsigned char* result = (unsigned char*)malloc(len);
    if (!result)
        return CRYPTO_ERROR_MEMORY;

    uint64_t x = x0;
    for (size_t i = 0; i < len; i++)
    {
        result[i] = input[i] ^ (unsigned char)(x & 0xFF);
        x = (a * x + d) % m;
    }

    *output = result;
    return CRYPTO_SUCCESS;
}