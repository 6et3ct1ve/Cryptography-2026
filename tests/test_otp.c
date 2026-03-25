#include <check.h>
#include <stdlib.h>
#include "crypto/otp.h"
#include "crypto/core.h"

/**
 * @brief Test basic encryption
 */
START_TEST(test_encrypt_basic)
{
    unsigned char input[] = {0x41, 0x42, 0x43};
    unsigned char key[]   = {0x01, 0x02, 0x03};
    unsigned char* result = NULL;

    enum crypto_status status = otp_crypt(input, 3, key, 3, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_int_eq(result[0], 0x40);
    ck_assert_int_eq(result[1], 0x40);
    ck_assert_int_eq(result[2], 0x40);

    free(result);
}
END_TEST

/**
 * @brief Test symmetry: encrypt(encrypt(x)) == x
 */
START_TEST(test_symmetry)
{
    unsigned char input[] = {0xDE, 0xAD, 0xBE};
    unsigned char key[]   = {0xFF, 0xFF, 0xFF};
    unsigned char* first  = NULL;
    unsigned char* second = NULL;

    otp_crypt(input, 3, key, 3, &first);
    otp_crypt(first, 3, key, 3, &second);

    ck_assert_int_eq(second[0], input[0]);
    ck_assert_int_eq(second[1], input[1]);
    ck_assert_int_eq(second[2], input[2]);

    free(first);
    free(second);
}
END_TEST

/**
 * @brief Test key longer than input (valid)
 */
START_TEST(test_key_longer)
{
    unsigned char input[] = {0x01};
    unsigned char key[]   = {0xFF, 0xFF, 0xFF};
    unsigned char* result = NULL;

    enum crypto_status status = otp_crypt(input, 1, key, 3, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_int_eq(result[0], 0xFE);

    free(result);
}
END_TEST

/**
 * @brief Test key shorter than input (invalid)
 */
START_TEST(test_key_too_short)
{
    unsigned char input[] = {0x01, 0x02, 0x03};
    unsigned char key[]   = {0xFF};
    unsigned char* result = NULL;

    enum crypto_status status = otp_crypt(input, 3, key, 1, &result);

    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_KEY);
}
END_TEST

/**
 * @brief Test NULL pointer handling
 */
START_TEST(test_null_input)
{
    unsigned char input[] = {0x01};
    unsigned char key[]   = {0xFF};
    unsigned char* result = NULL;

    ck_assert_int_eq(otp_crypt(NULL, 1, key, 1, &result), CRYPTO_ERROR_NULL_POINTER);
    ck_assert_int_eq(otp_crypt(input, 1, NULL, 1, &result), CRYPTO_ERROR_NULL_POINTER);
    ck_assert_int_eq(otp_crypt(input, 1, key, 1, NULL), CRYPTO_ERROR_NULL_POINTER);
}
END_TEST

/**
 * @brief Test single byte
 */
START_TEST(test_single_byte)
{
    unsigned char input[] = {0xAA};
    unsigned char key[]   = {0x55};
    unsigned char* result = NULL;

    enum crypto_status status = otp_crypt(input, 1, key, 1, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_int_eq(result[0], 0xFF);

    free(result);
}
END_TEST

/**
 * @brief Create test suite
 */
Suite* otp_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("OTP Cipher");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_encrypt_basic);
    tcase_add_test(tc_core, test_symmetry);
    tcase_add_test(tc_core, test_key_longer);
    tcase_add_test(tc_core, test_key_too_short);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_single_byte);

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

    s = otp_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}