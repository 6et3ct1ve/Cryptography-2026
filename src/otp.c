#include "crypto/otp.h"
#include <stdlib.h>

enum crypto_status otp_crypt(
    const unsigned char* input,
    size_t len,
    const unsigned char* key,
    size_t key_len,
    unsigned char** output)
{
    if (!input || !key || !output)
        return CRYPTO_ERROR_NULL_POINTER;

    if (key_len < len)
        return CRYPTO_ERROR_INVALID_KEY;

    unsigned char* result = (unsigned char*)malloc(len);
    if (!result)
        return CRYPTO_ERROR_MEMORY;

    for (size_t i = 0; i < len; i++)
        result[i] = input[i] ^ key[i];

    *output = result;
    return CRYPTO_SUCCESS;
}