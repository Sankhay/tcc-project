#include "Arduino.h"
#include "utils/utils.h"
#include "algorithms/speck/speck.h"
#include "algorithms/chacha20/ChaCha20.h"
#include "algorithms/Elephant/crypto_aead/elephant160v1/ref/elephant_160.h"
#include "algorithms/gift64/GIFT64.h"
#include "algorithms/tiny_jambu/tiny_jambu.h"

long randNumber;
const int NUM_ITERATIONS = 5; 
const int NUM_ALGORITHMS = 5;

struct PerformanceMetrics {
  char* algorithmName;
  unsigned long totalExecutionTimeMicros;
  int ramUsedBytes;
};

typedef void (*MeasurableFunction)(void* context);

typedef struct {
    uint64_t* plaintext;
    uint64_t* key;
} SpeckParams;

typedef struct {
  uint8_t* key;
  uint8_t* nonce;
  uint32_t count;
  uint8_t* data;
} ChaCha20Params;

void chacha20_wrapper(void* context) {
  ChaCha20Params* params = (ChaCha20Params*)context;

  useChaCha20(params->key, params->nonce, params->count, params->data);
}

typedef struct {
  uint64_t plaintext;
  uint16_t* key;
} Gift64Params;

void gift64_wrapper(void* context) {
  Gift64Params* params = (Gift64Params*)context;

  useGift64(params->plaintext, params->key);
}

typedef struct {
  uint8_t* plaintext;
  uint8_t* key;
  uint8_t* nonce;
} ElephantParams;

void elephant_wrapper(void* context) {
  ElephantParams* params = (ElephantParams*)context;

  useElephant(params->key, params->nonce, params->plaintext, "");
}

typedef struct {
  uint8_t* plaintext;
  uint8_t* key;
  uint8_t* nonce;
} TinyJambuParams;

void tiny_jambu_wrapper(void *context) {
  TinyJambuParams* params = (TinyJambuParams*)context;

  useTinyJambu(params->plaintext, params->key, params->nonce, "");
}

// Wrapper Function (Matches MeasurableFunction signature)
void speck_wrapper(void* context) {
    SpeckParams* params = (SpeckParams*)context;
    
    // Call the actual function
    useSpeck(params->plaintext, params->key); 
}

int freeRam() {
  extern int __heap_start, *__brkval;
  int v;
  return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval);
}


PerformanceMetrics measurePerformance(MeasurableFunction functionToMeasure, void* context, char algorithmName[]) {
  PerformanceMetrics metrics;
  
  unsigned long totalTime = 0;
  
  int ramBefore = freeRam();

  unsigned long startTime = micros();
  functionToMeasure(context);
  unsigned long endTime = micros();
  totalTime += (endTime - startTime);
  
  int ramAfter = freeRam();

  metrics.totalExecutionTimeMicros = totalTime;
  metrics.ramUsedBytes = ramBefore - ramAfter; 
  metrics.algorithmName = algorithmName;

  return metrics;
}

void displayMetrics(PerformanceMetrics* metricsArray, int numItems) {
  Serial.println("\n--- Algorithm Performance Report ---");
  Serial.println("-------------------------------------------------------");
  Serial.println("Algorithm      | Exec. Time (us) | RAM Used (bytes)");
  Serial.println("-------------------------------------------------------");

  for (int i = 0; i < numItems; i++) {
    Serial.print(metricsArray[i].algorithmName);
    
    int padding = 15 - strlen(metricsArray[i].algorithmName);
    for(int j = 0; j < padding; j++) {
      Serial.print(" ");
    }
    Serial.print("| ");

    Serial.print(metricsArray[i].totalExecutionTimeMicros);
    padding = 16 - String(metricsArray[i].totalExecutionTimeMicros).length();
     for(int j = 0; j < padding; j++) {
      Serial.print(" ");
    }
    Serial.print("| ");
    
    Serial.println(metricsArray[i].ramUsedBytes);
  }
  
  Serial.println("-------------------------------------------------------");
}

void setup() {
  Serial.begin(9600);
  while (!Serial) {
    ;
  }

  PerformanceMetrics* performances = (PerformanceMetrics*)malloc(sizeof(PerformanceMetrics) * NUM_ITERATIONS * NUM_ALGORITHMS);

  // It's good practice to check if malloc was successful
  if (performances == NULL) {
      // CORRECTED ERROR HANDLING
      Serial.println("Error: Failed to allocate memory for performances");
      while(1); // Halt the program
  }

  for (int i = 0; i < NUM_ITERATIONS; i++) {
    SpeckParams speck_context = {
        .plaintext = createUint64List(2), 
        .key = createUint64List(2)
    };

    PerformanceMetrics performance = measurePerformance(speck_wrapper, &speck_context, "SPECK");

    performances[i] = performance;

    free(speck_context.plaintext);
    free(speck_context.key);

        // This IS supported
    ChaCha20Params chacha20_context = {
      0,                       // for .count
      createUint8List(8),      // for .data
      createUint8List(8),      // for .nonce
      createUint8List(32)      // for .key
    };

    performance = measurePerformance(chacha20_wrapper, &chacha20_context, "CHACHA20");

    performances[i + (1 * NUM_ALGORITHMS)] = performance;

    free(chacha20_context.data);
    free(chacha20_context.nonce);
    free(chacha20_context.key);
  }
  
  displayMetrics(performances, NUM_ITERATIONS * 2);
}

void loop() {

}

/* uint8_t* chacha20Key = createUint8List(32);
    uint8_t* chacha20Nonce = createUint8List(8);
    uint32_t chacha20Count = 0;
    uint8_t* chacha20Data = createUint8List(8);

    useChaCha20(chacha20Key, chacha20Nonce, chacha20Count, chacha20Data);

    uint64_t* gift64PlainText = createUint64List(1);
    uint16_t* gift64Key = createUint16List(8);

    useGift64(gift64PlainText[0], gift64Key);

    uint8_t* elephantPlainText = createUint8List(8);
    uint8_t* elephantKey = createUint8List(8);
    uint8_t* elephantNonce = createUint8List(12);

    char* elephantCharPlainText = (char*)elephantPlainText;
    char* elephantCharKey = (char*)elephantKey;
    char* elephantCharNonce = (char*)elephantNonce;

    useElephant(elephantCharKey, elephantCharNonce, elephantCharPlainText, "");

    uint8_t* tinyJambuPlainText = createUint8List(64);
    uint8_t* tinyJambuKey = createUint8List(33);
    uint8_t* tinyJambuNonce = createUint8List(33);

    */
      
    /*vai que funciona
    char* tinyJambuCharPlainText = (char*)tinyJambuPlainText;
    char* tinyJambuCharKey = (char*)tinyJambuKey;
    char* tinyJambuCharNonce = (char*)tinyJambuNonce;*/

    //useTinyJambu(tinyJambuPlainText, tinyJambuKey, tinyJambuNonce, "");  