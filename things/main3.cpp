#include "Arduino.h"
#include "utils/utils.h"
#include "algorithms/speck/speck.h"
#include "algorithms/chacha20/ChaCha20.h"
#include "algorithms/Elephant/crypto_aead/elephant160v1/ref/elephant_160.h"
#include "algorithms/gift64/GIFT64.h"
#include "algorithms/tiny_jambu/tiny_jambu.h"

// =================================================================
// 1. DATA STRUCTURES & WRAPPERS (Your existing code, slightly organized)
// =================================================================

// Generic function pointer type for any algorithm we want to measure.
typedef void (*MeasurableFunction)(void* context);

// --- Parameter Structs & Wrappers for each Algorithm ---

// Speck
typedef struct {
    uint64_t* plaintext;
    uint64_t* key;
} SpeckParams;

void speck_wrapper(void* context) {
    SpeckParams* params = (SpeckParams*)context;
    useSpeck(params->plaintext, params->key); 
}

// ChaCha20
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

// Gift64
typedef struct {
  uint64_t plaintext;
  uint16_t* key;
} Gift64Params;

void gift64_wrapper(void* context) {
  Gift64Params* params = (Gift64Params*)context;
  useGift64(params->plaintext, params->key);
}

// Elephant
typedef struct {
  uint8_t* plaintext;
  uint8_t* key;
  uint8_t* nonce;
} ElephantParams;

void elephant_wrapper(void* context) {
  ElephantParams* params = (ElephantParams*)context;
  useElephant(params->key, params->nonce, params->plaintext, "");
}

// TinyJambu
typedef struct {
  uint8_t* plaintext;
  uint8_t* key;
  uint8_t* nonce;
} TinyJambuParams;

void tiny_jambu_wrapper(void *context) {
  TinyJambuParams* params = (TinyJambuParams*)context;
  useTinyJambu(params->plaintext, params->key, params->nonce, "");
}


// =================================================================
// 2. SETUP & TEARDOWN FUNCTIONS (The new part)
// =================================================================

// --- For Speck ---
void* setup_speck() {
    SpeckParams* params = (SpeckParams*)malloc(sizeof(SpeckParams));
    if (!params) return NULL;
    params->plaintext = createUint64List(2);
    params->key = createUint64List(2);
    return params;
}

void teardown_speck(void* context) {
    SpeckParams* params = (SpeckParams*)context;
    free(params->plaintext);
    free(params->key);
    free(params);
}

// --- For ChaCha20 ---
void* setup_chacha20() {
    ChaCha20Params* params = (ChaCha20Params*)malloc(sizeof(ChaCha20Params));
    if (!params) return NULL;
    params->count = 0;
    params->data = createUint8List(8);
    params->nonce = createUint8List(8);
    params->key = createUint8List(32);
    return params;
}

void teardown_chacha20(void* context) {
    ChaCha20Params* params = (ChaCha20Params*)context;
    free(params->data);
    free(params->nonce);
    free(params->key);
    free(params);
}

// --- For Gift64 ---
void* setup_gift64() {
    Gift64Params* params = (Gift64Params*)malloc(sizeof(Gift64Params));
    if (!params) return NULL;
    params->plaintext = 0; // Or some random value
    params->key = (uint16_t*)createUint8List(16); // Assuming key is 128-bit
    return params;
}

void teardown_gift64(void* context) {
    Gift64Params* params = (Gift64Params*)context;
    free(params->key);
    free(params);
}

// --- For Elephant ---
void* setup_elephant() {
    ElephantParams* params = (ElephantParams*)malloc(sizeof(ElephantParams));
    if (!params) return NULL;
    params->plaintext = createUint8List(8);
    params->key = createUint8List(16); // 128-bit key
    params->nonce = createUint8List(12); // 96-bit nonce
    return params;
}

void teardown_elephant(void* context) {
    ElephantParams* params = (ElephantParams*)context;
    free(params->plaintext);
    free(params->key);
    free(params->nonce);
    free(params);
}

// --- For TinyJambu ---
void* setup_tinyjambu() {
    TinyJambuParams* params = (TinyJambuParams*)malloc(sizeof(TinyJambuParams));
    if (!params) return NULL;
    params->plaintext = createUint8List(8);
    params->key = createUint8List(16); // 128-bit key
    params->nonce = createUint8List(12); // 96-bit nonce
    return params;
}

void teardown_tinyjambu(void* context) {
    TinyJambuParams* params = (TinyJambuParams*)context;
    free(params->plaintext);
    free(params->key);
    free(params->nonce);
    free(params);
}


// =================================================================
// 3. THE BENCHMARKING FRAMEWORK
// =================================================================

// --- The Benchmark Definition Struct ---
struct AlgorithmBenchmark {
  const char* name;
  MeasurableFunction benchmark_function;
  void* (*setup_function)(void);
  void (*teardown_function)(void* context);
};

// --- The Array of All Algorithms to Test ---
AlgorithmBenchmark benchmarks[] = {
    {"SPECK",      speck_wrapper,      setup_speck,      teardown_speck},
    {"CHACHA20",   chacha20_wrapper,   setup_chacha20,   teardown_chacha20},
    {"GIFT64",     gift64_wrapper,     setup_gift64,     teardown_gift64},
    {"ELEPHANT",   elephant_wrapper,   setup_elephant,   teardown_elephant},
    {"TINYJAMBU",  tiny_jambu_wrapper, setup_tinyjambu,  teardown_tinyjambu}
};

// --- Configuration ---
const int NUM_ITERATIONS = 5;
// Calculate number of algorithms automatically!
const int NUM_ALGORITHMS = sizeof(benchmarks) / sizeof(benchmarks[0]);

// --- Your Performance Struct and Helper Functions (Unchanged) ---
struct PerformanceMetrics {
  char* algorithmName;
  unsigned long totalExecutionTimeMicros;
  int ramUsedBytes;
};

int freeRam() {
  extern int __heap_start, *__brkval;
  int v;
  return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval);
}

PerformanceMetrics measurePerformance(MeasurableFunction functionToMeasure, void* context, const char* algorithmName) {
  PerformanceMetrics metrics;
  
  int ramBefore = freeRam();
  unsigned long startTime = micros();
  
  functionToMeasure(context);
  
  unsigned long endTime = micros();
  int ramAfter = freeRam();

  metrics.totalExecutionTimeMicros = endTime - startTime;
  metrics.ramUsedBytes = ramBefore - ramAfter; 
  // We cast away const here, which is generally safe since we know we won't modify the string literals.
  metrics.algorithmName = (char*)algorithmName;

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
    for(int j = 0; j < padding; j++) Serial.print(" ");
    Serial.print("| ");

    Serial.print(metricsArray[i].totalExecutionTimeMicros);
    padding = 16 - String(metricsArray[i].totalExecutionTimeMicros).length();
    for(int j = 0; j < padding; j++) Serial.print(" ");
    Serial.print("| ");
    
    Serial.println(metricsArray[i].ramUsedBytes);
  }
  
  Serial.println("-------------------------------------------------------");
}


// =================================================================
// 4. THE SIMPLIFIED MAIN SETUP & LOOP
// =================================================================

void setup() {
  Serial.begin(9600);
  while (!Serial) { ; }

  size_t total_metrics = NUM_ITERATIONS * NUM_ALGORITHMS;
  PerformanceMetrics* performances = (PerformanceMetrics*)malloc(sizeof(PerformanceMetrics) * total_metrics);

  if (performances == NULL) {
      Serial.println("Error: Failed to allocate memory for performance results!");
      while(1); // Halt
  }

  // THE NEW, CLEAN LOOP
  for (int i = 0; i < NUM_ITERATIONS; i++) {
    Serial.print("Running iteration ");
    Serial.println(i + 1);
    
    for (int j = 0; j < NUM_ALGORITHMS; j++) {
      // Get the current algorithm's benchmark configuration
      AlgorithmBenchmark& current_benchmark = benchmarks[j];

      // 1. Setup: Create the context and parameters
      void* context = current_benchmark.setup_function();
      if (context == NULL) {
          Serial.print("Failed to allocate context for ");
          Serial.println(current_benchmark.name);
          continue; // Skip to the next algorithm
      }
      
      // 2. Measure: Run the actual performance test
      PerformanceMetrics result = measurePerformance(
          current_benchmark.benchmark_function, 
          context, 
          current_benchmark.name
      );

      // 3. Store: Save the result in the correct array slot
      int index = i * NUM_ALGORITHMS + j;
      performances[index] = result;

      // 4. Teardown: Clean up the memory used by the parameters
      current_benchmark.teardown_function(context);
    }
  }
  
  displayMetrics(performances, total_metrics);
  free(performances);
}

void loop() {
  // Nothing to do here
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