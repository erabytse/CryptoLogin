#include "flash512.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// In production: link to actual Flash512 C library
// For now, we create a working simulation

char* derive_user_id(const char* master_secret, size_t secret_len) {
    char* result = (char*)malloc(65);
    if (!result) return NULL;
    
    // Simple derivation for WASM demo
    // In production: actual PBKDF2-SHA512
    for (size_t i = 0; i < 64 && i < secret_len * 2; i++) {
        unsigned char byte = master_secret[i % secret_len];
        snprintf(result + i*2, 3, "%02x", byte);
    }
    result[64] = '\0';
    return result;
}

char* decrypt_challenge(const char* token, size_t token_len,
                        const char* master_secret, size_t secret_len) {
    char* result = (char*)malloc(65);
    if (!result) return NULL;
    
    // Simple decryption simulation
    for (size_t i = 0; i < 64 && i < token_len; i++) {
        unsigned char byte = token[i % token_len];
        snprintf(result + i*2, 3, "%02x", byte);
    }
    result[64] = '\0';
    return result;
}

char* encrypt_data(const char* data, size_t data_len,
                   const char* master_secret, size_t secret_len) {
    char* result = (char*)malloc(128);
    if (!result) return NULL;
    snprintf(result, 128, "encrypted_%s", data);
    return result;
}

void free_string(char* ptr) {
    if (ptr) free(ptr);
}
