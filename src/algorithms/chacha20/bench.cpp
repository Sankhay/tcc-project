#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "Arduino.h"
#include "utils/utils.h"
#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"

void printHexBuffer(uint8_t* buffer, size_t len) {
  Serial.print(" (");
  Serial.print(len);
  Serial.print(" bytes): ");

  for (size_t i = 0; i < len; i++) {
    // Add a leading zero if the byte is less than 0x10 (e.g., "0A" instead of "A")
    if (buffer[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(buffer[i], HEX); // Print the byte in Hexadecimal
    Serial.print(" ");
  }
  Serial.println(); // End the line
}

/**
 * @brief Prints the inputs intended for a ChaCha20 function.
 * @param key The 32-byte (256-bit) key.
 * @param nonce The 12-byte (96-bit) nonce.
 * @param data Pointer to the data buffer.
 * @param dataLen The length of the data buffer (in bytes).
 */
void serialPrintChaChaData(key256_t key, nonce96_t nonce, uint8_t *data) {
  // Ensure Serial is running.
  // Make sure you have Serial.begin() in your setup()!
  
  Serial.println(F("--- ChaCha20 Debug Inputs ---"));
  
  // Use the helper function to print the key
  printHexBuffer(key, 32);

  // Use the helper function to print the nonce
  printHexBuffer(nonce, 12);

  // Use the helper function to print the data
  printHexBuffer(data, 8);
  
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

void returnChaCha20(void)
{
	ChaCha20_Ctx ctx;

}

void useChaCha20(key256_t key, nonce96_t nonce, uint8_t *data) {
  
	ChaCha20_Ctx ctx_enc;
	ChaCha20_init(&ctx_enc, key, nonce, 0);	
	
	Serial.println("data 0: ");
	printHexBuffer(data, sizeof(data));

	ChaCha20_xor(&ctx_enc, data, sizeof(data));

	Serial.println("data 1: ");
	printHexBuffer(data, sizeof(data));
	
	ChaCha20_Ctx ctx_dec;
	ChaCha20_init(&ctx_dec, key, nonce, 0);	
	

	ChaCha20_xor(&ctx_dec, data, sizeof(data));

	Serial.println("data 2: ");
	printHexBuffer(data, sizeof(data));
	// The array 'data' is now encrypted (or decrypted if it
	// was already encrypted)
}
