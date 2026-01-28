#include "crypto/vernam.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Encrypt using Vernam cipher
 * 
 * Formula: S[i] = C[i] ⊕ K[i]
 */
enum crypto_status encrypt_vernam(
    const unsigned char* data, 
    size_t data_len,
    const unsigned char* key, 
    size_t key_len,
    unsigned char** result
)
{
    if (!data || !key || !result)
        return CRYPTO_ERROR_NULL_POINTER;
    
    if (key_len < data_len)
        return CRYPTO_ERROR_INVALID_KEY;
    
    unsigned char* output = (unsigned char*)malloc(data_len);
    if (!output)
        return CRYPTO_ERROR_MEMORY;
    
    for (size_t i = 0; i < data_len; i++)
    {
        output[i] = data[i] ^ key[i];
    }
    
    *result = output;
    return CRYPTO_SUCCESS;
}

/**
 * @brief Decrypt using Vernam cipher
 * 
 * Formula: C[i] = S[i] ⊕ K[i]
 */
enum crypto_status decrypt_vernam(
    const unsigned char* data, 
    size_t data_len,
    const unsigned char* key, 
    size_t key_len,
    unsigned char** result
)
{
    if (!data || !key || !result)
        return CRYPTO_ERROR_NULL_POINTER;
    
    if (key_len < data_len)
        return CRYPTO_ERROR_INVALID_KEY;
    
    unsigned char* output = (unsigned char*)malloc(data_len);
    if (!output)
        return CRYPTO_ERROR_MEMORY;
    
    for (size_t i = 0; i < data_len; i++)
    {
        output[i] = data[i] ^ key[i];
    }
    
    *result = output;
    return CRYPTO_SUCCESS;
}