#ifndef FLASH512_WASM_H
#define FLASH512_WASM_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Derive user_id from master_secret
char* derive_user_id(const char* master_secret, size_t secret_len);

// Decrypt challenge_token with master_secret
char* decrypt_challenge(const char* token, size_t token_len, 
                        const char* master_secret, size_t secret_len);

// Encrypt data with master_secret
char* encrypt_data(const char* data, size_t data_len,
                   const char* master_secret, size_t secret_len);

// Free allocated memory
void free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // FLASH512_WASM_H
