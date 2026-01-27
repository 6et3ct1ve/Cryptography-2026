#include "crypto/core.h"

const char* crypto_status_output(enum crypto_status status) 
{
    switch (status) 
    {
        case CRYPTO_SUCCESS:
            return "Success";
        case CRYPTO_ERROR_INVALID_INPUT:
            return "Invalid input data";
        case CRYPTO_ERROR_INVALID_KEY:
            return "Invalid key value";
        case CRYPTO_ERROR_EXECUTION:
            return "Execution error";
        case CRYPTO_ERROR_MEMORY:
            return "Memory allocation failed";
        case CRYPTO_ERROR_NULL_POINTER:
            return "Unexpected NULL pointer";
        default:
            return "Unknown error";
    }
}