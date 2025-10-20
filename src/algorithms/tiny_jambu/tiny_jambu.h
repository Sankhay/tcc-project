#ifndef TINYJAMBU_H
#define TINYJAMBU_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TinyJAMBU-128: 128-bit key, 96-bit IV
 * Header file for the reference implementation
 *
 * This header defines the API for the TinyJAMBU authenticated
 * encryption with associated data (AEAD) scheme.
 */

// For size_t and other standard types, though not strictly required by the function signatures below.
#include <string.h>

// --- Public Constants ---

// The following constants define the sizes in bytes for keys, nonces,
// and other data used by the TinyJAMBU-128 algorithm.

#define TJ_CRYPTO_KEYBYTES 16      // Key size (128 bits)
#define TJ_CRYPTO_NPUBBYTES 12     // Nonce size (96 bits)
#define TJ_CRYPTO_ABYTES 8         // Default associated data size for reference
#define CRYPTO_BYTES 64         // Default plaintext/ciphertext buffer size for reference
#define TJ_CRYPTO_NSECBYTES 0      // Secret message number (not used)
#define TJ_CRYPTO_NOOVERLAP 1      // Indicates that ciphertext and plaintext buffers must not overlap


// --- Public API Function Prototypes ---

/**
 * @brief Encrypts and authenticates a message with associated data.
 *
 * @param c       A pointer to the buffer where the ciphertext and tag will be stored.
 * The buffer must be at least `mlen + 8` bytes long.
 * @param clen    A pointer to an unsigned long long that will receive the final
 * ciphertext length (which is `mlen + 8`).
 * @param m       A pointer to the plaintext message to be encrypted.
 * @param mlen    The length of the plaintext message in bytes.
 * @param ad      A pointer to the associated data to be authenticated.
 * @param adlen   The length of the associated data in bytes.
 * @param nsec    A pointer to the secret message number (not used in this implementation, can be NULL).
 * @param npub    A pointer to the 12-byte (96-bit) public nonce.
 * @param k       A pointer to the 16-byte (128-bit) secret key.
 * @return int    Returns 0 on success.
 */
int crypto_aead_encrypt_tiny_jambu(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
);

void useTinyJambu(const char plaintext_in[CRYPTO_BYTES], const char keyhex_in[2*TJ_CRYPTO_KEYBYTES], const char nonce_in[2*TJ_CRYPTO_KEYBYTES], const char add_in[TJ_CRYPTO_ABYTES]);


/**
 * @brief Decrypts and verifies a ciphertext with associated data.
 *
 * @param m       A pointer to the buffer where the decrypted plaintext will be stored.
 * The buffer must be at least `clen - 8` bytes long.
 * @param mlen    A pointer to an unsigned long long that will receive the final
 * plaintext length (which is `clen - 8`).
 * @param nsec    A pointer to the secret message number (not used in this implementation, can be NULL).
 * @param c       A pointer to the ciphertext and tag to be decrypted.
 * @param clen    The length of the ciphertext and tag in bytes.
 * @param ad      A pointer to the associated data to be verified.
 * @param adlen   The length of the associated data in bytes.
 * @param npub    A pointer to the 12-byte (96-bit) public nonce.
 * @param k       A pointer to the 16-byte (128-bit) secret key.
 * @return int    Returns 0 on success (i.e., the tag is valid).
 * Returns -1 on failure (i.e., the tag is invalid).
 */
int crypto_aead_decrypt_tiny_jambu(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
);


#ifdef __cplusplus
}
#endif

#endif // TINYJAMBU_H