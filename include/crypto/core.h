#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

/**
 * @file core.h
 * @brief Core definitions and utilities for cryptography library.
 *
 * Contains common status codes and error handling functions
 * used across all cipher implementations.
 */

/**
 * @brief Status codes for cryptographic operations.
 *
 * All cipher functions return these status codes to indicate
 * success or specific failure reasons.
 */
enum crypto_status {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_INPUT = -1,
    CRYPTO_ERROR_INVALID_KEY = -2,
    CRYPTO_ERROR_EXECUTION = -3,
    CRYPTO_ERROR_MEMORY = -4,
    CRYPTO_ERROR_NULL_POINTER = -5
};

/**
 * @brief Converts crypto_status to human-readable string.
 *
 * Returns a descriptive error message for the given status code.
 *
 * @param status Status code to convert.
 * @return Constant string describing the status.
 */
const char* crypto_status_output(enum crypto_status status);

#endif