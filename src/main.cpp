#include "Arduino.h"
#include "utils/utils.h"
#include "setup/setup.h"

// Generic function pointer type for any algorithm we want to measure.
typedef void (*MeasurableFunction)(void* context);

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
const int NUM_ITERATIONS = 50;
// Calculate number of algorithms automatically!
const int NUM_ALGORITHMS = sizeof(benchmarks) / sizeof(benchmarks[0]);

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
