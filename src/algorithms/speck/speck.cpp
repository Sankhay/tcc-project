#include "speck.h"
#include <Arduino.h>
#include <string.h>
#include "utils/utils.h"

#define ROR(x, r) ((x >> r) | (x << (64 - r)))
#define ROL(x, r) ((x << r) | (x >> (64 - r)))
#define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
#define RI(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x -= y, x = ROL(x, 8))
#define ROUNDS 32

void encrypt(uint64_t ct[2],
             uint64_t const pt[2],            
             uint64_t const K[2])
{
   uint64_t y = pt[0], x = pt[1], b = K[0], a = K[1];

   R(x, y, b);
   for (int i = 0; i < ROUNDS - 1; i++) {
      R(a, b, i);
      R(x, y, b);
   }

   ct[0] = y;
   ct[1] = x;
}

void decrypt(uint64_t pt[2],
             uint64_t const ct[2],
             uint64_t const K[2])
{
   uint64_t y = ct[0], x = ct[1];
   uint64_t b = K[0], a = K[1];
   
   // Precompute all round keys (same as encryption)
   uint64_t round_keys[ROUNDS];
   round_keys[0] = b;
   
   for (int i = 0; i < ROUNDS - 1; i++) {
      R(a, b, i);
      round_keys[i + 1] = b;
   }
   
   // Apply inverse operations in reverse order
   for (int i = ROUNDS - 1; i > 0; i--) {
      RI(x, y, round_keys[i]);
   }
   RI(x, y, round_keys[0]);
   
   pt[0] = y;
   pt[1] = x;
}

void string_to_blocks(const char* str, uint64_t blocks[2]) {
    memcpy(blocks, str, 16);
}

void useSpeck(uint64_t plaintext[2], uint64_t key[2], AlgorithmReturn* algorithmReturn) {
   uint64_t ciphertext[2], decrypted[2];

   encrypt(ciphertext, plaintext, key);
   algorithmReturn->encryptionTime = millis(); 
   
   const size_t size = 2 * sizeof(uint64_t);
   algorithmReturn->encryptedData = malloc(size);
   memcpy(algorithmReturn->encryptedData, ciphertext, size);

   decrypt(decrypted, ciphertext, key);
   
   if (memcmp(plaintext, decrypted, 16) == 0) {
      algorithmReturn->success = true;
   } else {
      algorithmReturn->success = false;
   }
}
