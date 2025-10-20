#ifndef CRYPTO_WRAPPERS_H
#define CRYPTO_WRAPPERS_H

#include <stdint.h> // For uint64_t, uint8_t, uint32_t, uint16_t
#include "utils/utils.h" // For BYTE, SIZE, and prototypes of use...() functions

typedef unsigned char BYTE;
typedef unsigned long long SIZE;
// =================================================================
// 1. PARAMETER STRUCTURES
// =================================================================

// --- Speck ---
typedef struct {
    uint64_t* plaintext;
    uint64_t* key;
} SpeckParams;

// --- ChaCha20 ---
typedef struct {
  uint8_t* key;
  uint8_t* nonce;
  uint32_t count;
  uint8_t* data;
} ChaCha20Params;

// --- Gift64 ---
typedef struct {
  uint64_t plaintext;
  uint16_t* key;
} Gift64Params;

// --- Elephant ---
typedef struct {
  BYTE* plaintext;
  BYTE key[16];
  BYTE nonce[12];
} ElephantParams;

// --- TinyJambu ---
typedef struct {
  char* plaintext;
  char* key;
  char* nonce;
} TinyJambuParams;

// =================================================================
// 2. WRAPPER FUNCTIONS
// =================================================================

void speck_wrapper(void* context);
void chacha20_wrapper(void* context);
void gift64_wrapper(void* context);
void elephant_wrapper(void* context);
void tiny_jambu_wrapper(void *context);

// =================================================================
// 3. SETUP & TEARDOWN FUNCTIONS
// =================================================================

// --- For Speck ---
void* setup_speck(void);
void teardown_speck(void* context);

// --- For ChaCha20 ---
void* setup_chacha20(void);
void teardown_chacha20(void* context);

// --- For Gift64 ---
void* setup_gift64(void);
void teardown_gift64(void* context);

// --- For Elephant ---
void* setup_elephant(void);
void teardown_elephant(void* context);

// --- For TinyJambu ---
void* setup_tinyjambu(void);
void teardown_tinyjambu(void* context);

// =================================================================
// 4. HELPER FUNCTIONS
// =================================================================

/**
 * @brief Converts a list of uint8_t to a null-terminated char string.
 * @param uint8List The source byte array.
 * @param length The number of bytes in the source array.
 * @return A new, null-terminated char* allocated with malloc. The
 * caller is responsible for freeing this memory.
 */
char* convertUint8ToChar(uint8_t* uint8List, int length);

/**
 * @brief Fills a buffer with random bytes.
 * @param buffer The buffer to fill.
 * @param length The number of random bytes to generate.
 */
void generate_random_bytes(BYTE* buffer, SIZE length);

#endif // CRYPTO_WRAPPERS_H