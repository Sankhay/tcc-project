#include <Arduino.h>
#include "algorithms/speck/speck.h" // Include the header with our function declarations
#include "algorithms/chacha20/ChaCha20.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "algorithms/gift64/GIFT64.h"
#include "Elephant/crypto_aead/elephant160v1/ref/api.h"
#include "Elephant/crypto_aead/elephant160v1/ref/crypto_aead.h"
#include "algorithms/Elephant/crypto_aead/elephant160v1/ref/elephant_160.h"
#include "algorithms/tiny_jambu/tiny_jambu.h"
#include "vector"

struct PerformanceMetrics {
  char* algorithmName;
  unsigned long totalExecutionTimeMicros;
  int ramUsedBytes;
};

const int NUM_ITERATIONS = 5; 
const int BAUD_RATE = 9600;

int freeRam() {
  extern int __heap_start, *__brkval;
  int v;
  return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval);
}

PerformanceMetrics measurePerformance(void (*functionToMeasure)()) {
  PerformanceMetrics metrics;
  
  unsigned long totalTime = 0;
  
  // Measure RAM usage before the loop.
  int ramBefore = freeRam();

  for (int i = 0; i < NUM_ITERATIONS; i++) {
    unsigned long startTime = micros();
    functionToMeasure();
    unsigned long endTime = micros();
    totalTime += (endTime - startTime);
  }

  int ramAfter = freeRam();

  metrics.totalExecutionTimeMicros = totalTime;
  // This metric primarily catches heap allocations, not temporary stack usage.
  metrics.ramUsedBytes = ramBefore - ramAfter; 

  return metrics;
}

void runAndPrintMetrics(const char* algorithmName, void (*testFunction)()) {
  Serial.print("--- Testing: ");
  Serial.println(algorithmName);

  PerformanceMetrics metrics = measurePerformance(testFunction);

  // Calculate the average execution time
  float averageTime = (float)metrics.totalExecutionTimeMicros / NUM_ITERATIONS;

  Serial.print("  Avg. Execution Time: ");
  Serial.print(averageTime);
  Serial.println(" microseconds");

  Serial.print("  Approx. Heap RAM Used: ");
  Serial.print(metrics.ramUsedBytes);
  Serial.println(" bytes\n");
}

void setup() {
  Serial.begin(BAUD_RATE);
  while (!Serial) {
    ; // Wait for serial port to connect. Needed for native USB port only.
  }
  Serial.println("\n--- Starting Encryption Algorithm Benchmark ---");
  Serial.print("Number of iterations per algorithm: ");
  Serial.println(NUM_ITERATIONS);


  // runAndPrintMetrics("Speck", useSpeck);
  // runAndPrintMetrics("ChaCha20", useChaCha20);
  // runAndPrintMetrics("GIFT64", useGift64);
  // runAndPrintMetrics("Elephant", useElephant);
  // runAndPrintMetrics("TinyJambu", useTinyJambu);

  
  uint16_t* list = createRandomList<uint16_t>(8);
  uint16_t keyGift64[8] = {0xbd91, 0x731e, 0xb6bc, 0x2713, 0xa1f9, 0xf6ff, 0xc750, 0x44e7};
  useGift64("hello world", keyGift64);

  uint64_t plaintextSpeck[2] = {0x48656c6c6f20576f, 0x726c642121212121}; // "Hello World!!!!"
  uint64_t keySpeck[2] = {0x0123456789abcdef, 0xfedcba9876543210};
  
  useSpeck(plaintextSpeck, keySpeck);

  key256_t keyChaCha20 = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};

	nonce96_t nonceChaCha20 = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	};

	uint32_t countChaCha20 = 0x00000001;

	uint8_t dataChaCha20[] = {
		0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
		0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
		// ...
		0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
		0x74, 0x2e,
	};

  useChaCha20(keyChaCha20, nonceChaCha20, countChaCha20, dataChaCha20);

  unsigned char keyElephant[CRYPTO_KEYBYTES] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
  unsigned char nonceElephant[CRYPTO_NPUBBYTES] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                                      0x77, 0x66, 0x55, 0x44};
  
  unsigned char plaintextElephant[] = "Hello, Elephant-200!";
  unsigned char adElephant[] = "Metadata";

  useElephant(keyElephant, nonceElephant, plaintextElephant, adElephant);

  char plaintextTinyJambu = "hello";
  char keyhexTinyJambu[2*CRYPTO_KEYBYTES+1]="000102030405060708090A0B0C0D0E0F";
  char nonceTinyJambu[2*CRYPTO_NPUBBYTES+1]="000102030405060708090A0B";
  char addTinyJambu[CRYPTO_ABYTES]="";


  useTinyJambu(plaintextElephant, keyhexTinyJambu, nonceTinyJambu, addTinyJambu);

  Serial.println("--- Benchmark Complete ---");
}

void loop() {

}