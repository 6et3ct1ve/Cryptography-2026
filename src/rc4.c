#include "crypto/rc4.h"
#include <stdlib.h>
#include <string.h>

#define RC4_SIZE 8

enum crypto_status rc4_crypt(
    const unsigned char* input,
    size_t len,
    const unsigned char key[2],
    unsigned char** output)
{
    if (!input || !key || !output)
        return CRYPTO_ERROR_NULL_POINTER;

    unsigned char* result = (unsigned char*)malloc(len);
    if (!result)
        return CRYPTO_ERROR_MEMORY;

    /* KSA */
    unsigned char S[RC4_SIZE];
    for (int i = 0; i < RC4_SIZE; i++)
        S[i] = i;

    int j = 0;
    for (int i = 0; i < RC4_SIZE; i++)
    {
        j = (j + S[i] + key[i % 2]) % RC4_SIZE;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    /* PRGA */
    int pi = 0;
    int pj = 0;
    for (size_t n = 0; n < len; n++)
    {
        pi = (pi + 1) % RC4_SIZE;
        pj = (pj + S[pi]) % RC4_SIZE;

        unsigned char tmp = S[pi];
        S[pi] = S[pj];
        S[pj] = tmp;

        int t = (S[pi] + S[pj]) % RC4_SIZE;
        result[n] = input[n] ^ S[t];
    }

    *output = result;
    return CRYPTO_SUCCESS;
}