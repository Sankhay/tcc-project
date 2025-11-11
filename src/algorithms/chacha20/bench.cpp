#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "Arduino.h"
#include "utils/utils.h"
#define CHACHA20_IMPLEMENTATION
#define CHACHA20_DATA_SIZE 20
#include "ChaCha20.h"

/**
 * @brief Prints the inputs intended for a ChaCha20 function.
 * @param key The 32-byte (256-bit) key.
 * @param nonce The 12-byte (96-bit) nonce.
 * @param data Pointer to the data buffer.
 * @param dataLen The length of the data buffer (in bytes).
 */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

void returnChaCha20(void)
{
	ChaCha20_Ctx ctx;

}

void useChaCha20(key256_t key, nonce96_t nonce, uint8_t *data, int dataLen, AlgorithmReturn* algorithmReturn) {
  
  uint8_t *original_data = (uint8_t*)malloc(dataLen);

  memcpy(original_data, data, dataLen);

	ChaCha20_Ctx ctx_enc;
	ChaCha20_init(&ctx_enc, key, nonce, 0);	

	ChaCha20_xor(&ctx_enc, data, dataLen);

  algorithmReturn->encryptedData = malloc(dataLen); 
  memcpy(algorithmReturn->encryptedData, data, dataLen); 

  algorithmReturn->encryptionTime = millis();

	ChaCha20_Ctx ctx_dec;
	ChaCha20_init(&ctx_dec, key, nonce, 0);	

	ChaCha20_xor(&ctx_dec, data, dataLen);

  if (memcmp(original_data, data, dataLen) == 0) {
    algorithmReturn->success = true;
  }

  free(original_data);
}
