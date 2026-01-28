#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/gamma.h"
#include "crypto/core.h"

START_TEST(test_encrypt_decrypt_basic)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "HELLO";
    size_t len = 5;
    uint32_t seed = 12345;
    
    status = encrypt_gamma(data, len, seed, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(encrypted);
    
    status = decrypt_gamma(encrypted, len, seed, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(decrypted);
    
    ck_assert_mem_eq(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

START_TEST(test_different_seeds)
{
    unsigned char* encrypted1 = NULL;
    unsigned char* encrypted2 = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "TEST";
    size_t len = 4;
    
    status = encrypt_gamma(data, len, 111, &encrypted1);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = encrypt_gamma(data, len, 222, &encrypted2);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_ne(encrypted1, encrypted2, len);
    
    free(encrypted1);
    free(encrypted2);
} 
END_TEST

START_TEST(test_single_byte)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "A";
    size_t len = 1;
    uint32_t seed = 5997;
    
    status = encrypt_gamma(data, len, seed, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_gamma(encrypted, len, seed, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

START_TEST(test_long_text)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen((char*)data);
    uint32_t seed = 98765;
    
    status = encrypt_gamma(data, len, seed, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_gamma(encrypted, len, seed, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

START_TEST(test_binary_data)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = {0x00, 0xFF, 0x80, 0x7F, 0x42};
    size_t len = 5;
    uint32_t seed = 54321;
    
    status = encrypt_gamma(data, len, seed, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_gamma(encrypted, len, seed, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_eq(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

START_TEST(test_wrong_seed)
{
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;
    enum crypto_status status;
    
    unsigned char data[] = "SECRET";
    size_t len = 6;
    
    status = encrypt_gamma(data, len, 1111, &encrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    status = decrypt_gamma(encrypted, len, 2222, &decrypted);
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    
    ck_assert_mem_ne(decrypted, data, len);
    
    free(encrypted);
    free(decrypted);
} 
END_TEST

START_TEST(test_null_input)
{
    unsigned char* result = NULL;
    unsigned char data[] = "TEST";
    enum crypto_status status;
    
    status = encrypt_gamma(NULL, 4, 12345, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_gamma(data, 4, 12345, NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = decrypt_gamma(NULL, 4, 12345, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = decrypt_gamma(data, 4, 12345, NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
} 
END_TEST

START_TEST(test_zero_length)
{
    unsigned char* result = NULL;
    unsigned char data[] = "TEST";
    enum crypto_status status;
    
    status = encrypt_gamma(data, 0, 12345, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_INPUT);
    
    status = decrypt_gamma(data, 0, 12345, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_INPUT);
} 
END_TEST

Suite* gamma_suite(void)
{
    Suite* s;
    TCase* tc_core;
    
    s = suite_create("Gamma Cipher");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_encrypt_decrypt_basic);
    tcase_add_test(tc_core, test_different_seeds);
    tcase_add_test(tc_core, test_single_byte);
    tcase_add_test(tc_core, test_long_text);
    tcase_add_test(tc_core, test_binary_data);
    tcase_add_test(tc_core, test_wrong_seed);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_zero_length);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}

int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;
    
    s = gamma_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}