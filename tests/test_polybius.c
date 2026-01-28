/**
 * @file test_polybius.c
 * @brief Unit tests for Polybius cipher implementation
 * 
 * Tests encryption, decryption, J=I handling, and error cases
 * using the Check framework.
 */

#include <check.h>
#include <stdlib.h>
#include "crypto/polybius.h"
#include "crypto/core.h"

/**
 * @brief Test basic encryption
 */
START_TEST(test_encrypt_basic)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_polybius("HELLO", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "2315313134");
    
    free(result);
} 
END_TEST

/**
 * @brief Test basic decryption
 */
START_TEST(test_decrypt_basic)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = decrypt_polybius("2315313134", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "HELLO");
    
    free(result);
} 
END_TEST

/**
 * @brief Test J→I conversion
 */
START_TEST(test_j_to_i)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_polybius("JOB", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "243412");
    
    free(result);
    
    status = decrypt_polybius("243412", &result);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_str_eq(result, "IOB");
    
    free(result);
} 
END_TEST

/**
 * @brief Test case insensitive encryption
 */
START_TEST(test_case_insensitive)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_polybius("HeLLo", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "2315313134");
    
    free(result);
} 
END_TEST

/**
 * @brief Test non-letters are ignored
 */
START_TEST(test_non_letters)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_polybius("A B! 123", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "1112");
    
    free(result);
} 
END_TEST

/**
 * @brief Test odd-length ciphertext error
 */
START_TEST(test_odd_length)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = decrypt_polybius("123", &result);
    
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_INPUT);
} 
END_TEST

/**
 * @brief Test invalid digits (not 1-5)
 */
START_TEST(test_invalid_digits)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = decrypt_polybius("1267", &result);
    
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_INPUT);
    
    status = decrypt_polybius("0012", &result);
    
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_INPUT);
} 
END_TEST

/**
 * @brief Test NULL input handling
 */
START_TEST(test_null_input)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_polybius(NULL, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_polybius("ABC", NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
} 
END_TEST

/**
 * @brief Create test suite
 */
Suite* polybius_suite(void)
{
    Suite* s;
    TCase* tc_core;
    
    s = suite_create("Polybius Cipher");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_encrypt_basic);
    tcase_add_test(tc_core, test_decrypt_basic);
    tcase_add_test(tc_core, test_j_to_i);
    tcase_add_test(tc_core, test_case_insensitive);
    tcase_add_test(tc_core, test_non_letters);
    tcase_add_test(tc_core, test_odd_length);
    tcase_add_test(tc_core, test_invalid_digits);
    tcase_add_test(tc_core, test_null_input);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}

/**
 * @brief Main test runner
 */
int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;
    
    s = polybius_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}