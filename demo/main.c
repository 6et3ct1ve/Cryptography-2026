#include <cryptography.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 1024

/**
 * @brief Clears input buffer after scanf.
 */
void clear_input_buffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void clear_screen()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

/**
 * @brief Prints main menu
 */
void print_menu()
{
    printf("\n=== Cryptography Library Demo ===\n");
    printf("1. Caesar cipher\n");
    printf("2. Trithemius cipher\n");
    printf("3. Polybius cipher\n");
    printf("4. Vigenere cipher\n");
    printf("5. Verham ciphere\n");
    printf("6. Gamma ciphere\n");
    printf("0. Exit\n");
    printf("Select cipher>");
}

void caesar_menu()
{
    int action, key;
    char input[MAX_INPUT];
    char* result = NULL;
    enum crypto_status status;

    printf("\n--- Caesar Cipher ---\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    printf("Select action>");

    if (scanf("%d", &action) != 1)
    {
        printf("Invalid input!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    if (action != 1 && action != 2)
    {
        printf("Invalid action!\n");
        return;
    }

    printf("Enter key>");
    if (scanf("%d", &key) != 1)
    {
        printf("Invalid key!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    printf("Enter text>");
    if (!fgets(input, MAX_INPUT, stdin))
    {
        printf("Failed to read input!\n");
        return;
    }

    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n')
        input[len-1] = '\0';

    if (action == 1)
        status = encrypt_caesar(input, key, &result);
    else
        status = decrypt_caesar(input, key, &result);

    if (status == CRYPTO_SUCCESS)
    {
        printf("\nResult: %s\n", result);
        free(result);
    }
    else 
        printf("\nError: %s\n", crypto_status_output(status));
}

void trithemius_menu()
{
    int action, key;
    char input[MAX_INPUT];
    char* result = NULL;
    enum crypto_status status;

    printf("\n--- Trithemius Cipher ---\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    printf("Select action>");

    if (scanf("%d", &action) != 1)
    {
        printf("Invalid input!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    if (action != 1 && action != 2)
    {
        printf("Invalid action!\n");
        return;
    }

    printf("Enter key>");
    if (scanf("%d", &key) != 1)
    {
        printf("Invalid key!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    printf("Enter text>");
    if (!fgets(input, MAX_INPUT, stdin))
    {
        printf("Failed to read input!\n");
        return;
    }

    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n')
        input[len-1] = '\0';

    if (action == 1)
        status = encrypt_trithemius(input, key, &result);
    else
        status = decrypt_trithemius(input, key, &result);

    if (status == CRYPTO_SUCCESS)
    {
        printf("\nResult: %s\n", result);
        free(result);
    }
    else 
        printf("\nError: %s\n", crypto_status_output(status));
}

void polybius_menu()
{
    int action;
    char input[MAX_INPUT];
    char* result = NULL;
    enum crypto_status status;

    printf("\n--- Polybius Cipher ---\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    printf("Select action>");

    if (scanf("%d", &action) != 1)
    {
        printf("Invalid input!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    if (action != 1 && action != 2)
    {
        printf("Invalid action!\n");
        return;
    }

    printf("Enter text>");
    if (!fgets(input, MAX_INPUT, stdin))
    {
        printf("Failed to read input!\n");
        return;
    }

    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n')
        input[len-1] = '\0';

    if (action == 1)
        status = encrypt_polybius(input, &result);
    else
        status = decrypt_polybius(input, &result);

    if (status == CRYPTO_SUCCESS)
    {
        printf("\nResult: %s\n", result);
        free(result);
    }
    else 
        printf("\nError: %s\n", crypto_status_output(status));
}

void vigenere_menu()
{
    int action;
    char input[MAX_INPUT];
    char key[MAX_INPUT];
    char* result = NULL;
    enum crypto_status status;

    printf("\n--- Vigenere Cipher ---\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    printf("Select action>");

    if (scanf("%d", &action) != 1)
    {
        printf("Invalid input!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    if (action != 1 && action != 2)
    {
        printf("Invalid action!\n");
        return;
    }

    printf("Enter key (letters only)>");
    if (!fgets(key, MAX_INPUT, stdin))
    {
        printf("Failed to read key!\n");
        return;
    }

    size_t key_len = strlen(key);
    if (key_len > 0 && key[key_len-1] == '\n')
        key[key_len-1] = '\0';

    printf("Enter text>");
    if (!fgets(input, MAX_INPUT, stdin))
    {
        printf("Failed to read input!\n");
        return;
    }

    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n')
        input[len-1] = '\0';

    if (action == 1)
        status = encrypt_vigenere(input, key, &result);
    else
        status = decrypt_vigenere(input, key, &result);

    if (status == CRYPTO_SUCCESS)
    {
        printf("\nResult: %s\n", result);
        free(result);
    }
    else 
        printf("\nError: %s\n", crypto_status_output(status));
}

void vernam_menu()
{
    int action;
    char input[MAX_INPUT];
    char key[MAX_INPUT];
    unsigned char* result = NULL;
    enum crypto_status status;

    printf("\n--- Vernam Cipher (One-Time Pad) ---\n");
    printf("Note: XOR cipher, works with bytes\n");
    printf("1. Encrypt (text → hex)\n");
    printf("2. Decrypt (hex → text)\n");
    printf("Select action> ");

    if (scanf("%d", &action) != 1)
    {
        printf("Invalid input!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    if (action != 1 && action != 2)
    {
        printf("Invalid action!\n");
        return;
    }

    printf("Enter key>");
    if (!fgets(key, MAX_INPUT, stdin))
    {
        printf("Failed to read key!\n");
        return;
    }
    size_t key_len = strlen(key);
    if (key_len > 0 && key[key_len-1] == '\n')
        key[key_len-1] = '\0';
    key_len = strlen(key);

    if (action == 1)
    {
        printf("Enter text>");
        if (!fgets(input, MAX_INPUT, stdin))
        {
            printf("Failed to read input!\n");
            return;
        }
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n')
            input[len-1] = '\0';
        len = strlen(input);

        status = encrypt_vernam((unsigned char*)input, len, (unsigned char*)key, key_len, &result);

        if (status == CRYPTO_SUCCESS)
        {
            printf("\nResult (hex): ");
            for (size_t i = 0; i < len; i++)
                printf("%02X", result[i]);
            printf("\n");
            free(result);
        }
        else 
            printf("\nError: %s\n", crypto_status_output(status));
    }
    else 
    {
        printf("Enter hex (no spaces, e.g. 1F0A07)>");
        if (!fgets(input, MAX_INPUT, stdin))
        {
            printf("Failed to read input!\n");
            return;
        }
        size_t hex_len = strlen(input);
        if (hex_len > 0 && input[hex_len-1] == '\n')
            input[hex_len-1] = '\0';
        hex_len = strlen(input);

        if (hex_len % 2 != 0)
        {
            printf("Invalid hex: length must be even!\n");
            return;
        }

        size_t data_len = hex_len / 2;
        unsigned char* data = (unsigned char*)malloc(data_len);
        if (!data)
        {
            printf("Memory error!\n");
            return;
        }

        for (size_t i = 0; i < data_len; i++)
        {
            char byte_str[3] = {input[i*2], input[i*2+1], '\0'};
            data[i] = (unsigned char)strtol(byte_str, NULL, 16);
        }

        status = decrypt_vernam(data, data_len, (unsigned char*)key, key_len, &result);

        if (status == CRYPTO_SUCCESS)
        {
            printf("\nResult (text): ");
            for (size_t i = 0; i < data_len; i++)
                printf("%c", result[i]);
            printf("\n");
            free(result);
        }
        else 
            printf("\nError: %s\n", crypto_status_output(status));

        free(data);
    }
}

void gamma_menu()
{
    int action;
    char input[MAX_INPUT];
    uint32_t seed;
    unsigned char* result = NULL;
    enum crypto_status status;

    printf("\n--- Gamma Cipher (Block Transposition) ---\n");
    printf("1. Encrypt (text → hex)\n");
    printf("2. Decrypt (hex → text)\n");
    printf("Select action> ");

    if (scanf("%d", &action) != 1)
    {
        printf("Invalid input!\n");
        clear_input_buffer();
        return;
    }
    clear_input_buffer();

    if (action != 1 && action != 2)
    {
        printf("Invalid action!\n");
        return;
    }

    if (action == 1)
    {
        printf("Enter text>");
        if (!fgets(input, MAX_INPUT, stdin))
        {
            printf("Failed to read input!\n");
            return;
        }
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n')
            input[len-1] = '\0';
        len = strlen(input);

        printf("Enter seed>");
        if (scanf("%u", &seed) != 1)
        {
            printf("Invalid seed!\n");
            clear_input_buffer();
            return;
        }
        clear_input_buffer();

        status = encrypt_gamma((unsigned char*)input, len, seed, &result);

        if (status == CRYPTO_SUCCESS)
        {
            printf("\nResult (hex): ");
            for (size_t i = 0; i < len; i++)
                printf("%02X", result[i]);
            printf("\n");
            free(result);
        }
        else 
            printf("\nError: %s\n", crypto_status_output(status));
    }
    else 
    {
        printf("Enter hex (no spaces, e.g. 1F0A07)>");
        if (!fgets(input, MAX_INPUT, stdin))
        {
            printf("Failed to read input!\n");
            return;
        }
        size_t hex_len = strlen(input);
        if (hex_len > 0 && input[hex_len-1] == '\n')
            input[hex_len-1] = '\0';
        hex_len = strlen(input);

        if (hex_len % 2 != 0)
        {
            printf("Invalid hex: length must be even!\n");
            return;
        }

        size_t data_len = hex_len / 2;
        unsigned char* data = (unsigned char*)malloc(data_len);
        if (!data)
        {
            printf("Memory error!\n");
            return;
        }

        for (size_t i = 0; i < data_len; i++)
        {
            char byte_str[3] = {input[i*2], input[i*2+1], '\0'};
            data[i] = (unsigned char)strtol(byte_str, NULL, 16);
        }

        printf("Enter seed>");
        if (scanf("%u", &seed) != 1)
        {
            printf("Invalid seed!\n");
            clear_input_buffer();
            free(data);
            return;
        }
        clear_input_buffer();

        status = decrypt_gamma(data, data_len, seed, &result);

        if (status == CRYPTO_SUCCESS)
        {
            printf("\nResult (text): ");
            for (size_t i = 0; i < data_len; i++)
                printf("%c", result[i]);
            printf("\n");
            free(result);
        }
        else 
            printf("\nError: %s\n", crypto_status_output(status));

        free(data);
    }
}

int main()
{
    int choice;

    while (1)
    {
        clear_screen();
        print_menu();

        if (scanf("%d", &choice) != 1)
        {
            printf("Invalid input!\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (choice)
        {
            case 1:
                caesar_menu();
                break;
            case 2:
                trithemius_menu();
                break;
            case 3:
                polybius_menu();
                break;
            case 4:
                vigenere_menu();
                break;
            case 5:
                vernam_menu();
                break;
            case 6:
                gamma_menu();
                break;
            case 0:
                printf("\nExiting...\n");
                return 0;
            default:
                printf("\nInvalid choice!\n");
        }

        printf("\nPress Enter to continue...");
        getchar();
    }

    return 0;
}