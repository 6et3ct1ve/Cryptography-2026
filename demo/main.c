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