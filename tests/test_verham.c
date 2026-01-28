#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/vernam.h"
#include "crypto/core.h"

/**
 * @brief Test basic encryption and decryption
 */
START_TEST(test_encrypt_decrypt_basic)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "HELLO";
    unsigned char key[] = "WORLD";
    size_t len = 5;
    
    status = encrypt_vernam(data, len, key, len, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(encrypted);
    
    status = decrypt_vernam(encrypted, len, key, len, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(decrypted);
    
    ck_assert_mem_eq(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

/**
 * @brief Test XOR symmetry (encrypt = decrypt)
 */
START_TEST(test_xor_symmetry)
{
    unsigned char* result1 = NULL;
    unsigned char* result2 = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "TEST";
    unsigned char key[] = "KEYS";
    size_t len = 4;
    
    status = encrypt_vernam(data, len, key, len, &result1);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_vernam(data, len, key, len, &result2);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(result1, result2, len);
    
    free(result1);
    free(result2);
} 
END_TEST

/**
 * @brief Test with binary data (including null bytes)
 */
START_TEST(test_binary_data)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = {0x00, 0x01, 0xFF, 0x80, 0x7F};
    unsigned char key[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    size_t len = 5;
    
    status = encrypt_vernam(data, len, key, len, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_vernam(encrypted, len, key, len, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

/**
 * @brief Test XOR result correctness
 */
START_TEST(test_xor_result)
{
    unsigned char* result = NULL;
    enum crypto_status status;
    
    unsigned char data[] = {0x0F, 0xF0};
    unsigned char key[] = {0xFF, 0xFF};
    size_t len = 2;
    
    status = encrypt_vernam(data, len, key, len, &result);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_int_eq(result[0], 0xF0);
    ck_assert_int_eq(result[1], 0x0F);
    
    free(result);
} 
END_TEST

/**
 * @brief Test key shorter than data (error)
 */
START_TEST(test_key_too_short)
{
    unsigned char* result = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "HELLO";
    unsigned char key[] = "KEY";
    
    status = encrypt_vernam(data, 5, key, 3, &result);
    
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_KEY);
} 
END_TEST

/**
 * @brief Test key longer than data (OK)
 */
START_TEST(test_key_longer)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "HI";
    unsigned char key[] = "VERYLONGKEY";
    size_t data_len = 2;
    size_t key_len = 11;
    
    status = encrypt_vernam(data, data_len, key, key_len, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_vernam(encrypted, data_len, key, key_len, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(decrypted, data, data_len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

/**
 * @brief Test NULL input handling
 */
START_TEST(test_null_input)
{
    unsigned char* result = NULL;
    unsigned char data[] = "TEST";
    unsigned char key[] = "KEYS";
    enum crypto_status status;
    
    status = encrypt_vernam(NULL, 4, key, 4, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_vernam(data, 4, NULL, 4, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_vernam(data, 4, key, 4, NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
} 
END_TEST

/**
 * @brief Test zero XOR (data XOR 0 = data)
 */
START_TEST(test_zero_key)
{
    unsigned char* result = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "HELLO";
    unsigned char key[] = {0x00, 0x00, 0x00, 0x00, 0x00};
    size_t len = 5;
    
    status = encrypt_vernam(data, len, key, len, &result);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(result, data, len);
    
    free(result);
} 
END_TEST

/**
 * @brief Create test suite
 */
Suite* vernam_suite(void)
{
    Suite* s;
    TCase* tc_core;
    
    s = suite_create("Vernam Cipher");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_encrypt_decrypt_basic);
    tcase_add_test(tc_core, test_xor_symmetry);
    tcase_add_test(tc_core, test_binary_data);
    tcase_add_test(tc_core, test_xor_result);
    tcase_add_test(tc_core, test_key_too_short);
    tcase_add_test(tc_core, test_key_longer);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_zero_key);
    
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
    
    s = vernam_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}