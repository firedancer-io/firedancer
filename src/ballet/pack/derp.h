#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

char *generate_random_string_from_data(const unsigned char *data);

int main() {
    unsigned char data[] = "\xff\xfe\xdd\x00";
    char *result = generate_random_string_from_data(data);

    // Print the generated random string
    printf("Generated Random String: %s\n", result);

    // Don't forget to free the allocated memory
    free(result);

    return 0;
}

char *generate_random_string_from_data(const unsigned char *data)
{
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const int charset_size = sizeof(charset) - 1;
    const int max_length = 32;

    // Use SHA-256 hash to generate a 32-bit pseudo-random value
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, sizeof(unsigned int), hash);

    // Use dynamic memory allocation for the string
    char *result = (char *)malloc((max_length + 1) * sizeof(char));

    // Check for allocation failure
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Convert each byte of the hash into characters from the charset
    for (int i = 0; i < max_length; ++i) {
        result[i] = charset[hash[i] % charset_size];
    }

    // Null-terminate the string
    result[max_length] = '\0';

    return result;
}
