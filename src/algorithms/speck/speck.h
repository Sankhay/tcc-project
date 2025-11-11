#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>
#include "structs/structs.h"
/**
 * @file speck.h
 * @brief Declarations for the Speck 128/128 block cipher.
 *
 * This file contains the function prototypes for the Speck encryption
 * and decryption routines, along with helper functions for testing.
 */

// --- Function Declarations ---

/**
 * @brief Encrypts a 128-bit block of plaintext using Speck.
 * @param ct Pointer to an array to store the 128-bit ciphertext (2 x uint64_t).
 * @param pt Pointer to an array containing the 128-bit plaintext (2 x uint64_t).
 * @param K  Pointer to an array containing the 128-bit key (2 x uint64_t).
 */
void encrypt(uint64_t ct[2], uint64_t const pt[2], uint64_t const K[2]);

/**
 * @brief Decrypts a 128-bit block of ciphertext using Speck.
 * @param pt Pointer to an array to store the 128-bit decrypted plaintext (2 x uint64_t).
 * @param ct Pointer to an array containing the 128-bit ciphertext (2 x uint64_t).
 * @param K  Pointer to an array containing the 128-bit key (2 x uint64_t).
 */
void decrypt(uint64_t pt[2], uint64_t const ct[2], uint64_t const K[2]);

/**
 * @brief A test function to demonstrate and verify the Speck implementation.
 * It encrypts and then decrypts a sample text, printing the results
 * to the Serial monitor.
 */
void useSpeck(uint64_t*, uint64_t*, AlgorithmReturn*); 

#endif // SPECK_H
