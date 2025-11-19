#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#pragma once

struct CommomParams {
  void* key;
  void* plaintext;
  void* nonce = NULL;
  void* add = NULL;
};

struct Algorithm {
  char algorithName[10];
  int plainTextSize;
  int keySize;
  int encryptedDataSize;
};

struct AlgorithmReturn {
  unsigned long encryptionTime;
  bool success = false;
  void* encryptedData = NULL;
};

typedef void (*MeasurableFunction)(void* context, AlgorithmReturn* algorithmReturn);

struct AlgorithmBenchmark {
  Algorithm algorithm;
  MeasurableFunction benchmark_function;
  void* (*setup_function)(CommomParams* commomParams);
  void (*teardown_function)(void* context);
};

struct PerformanceMetrics {
  Algorithm algorithm;
  void* key;
  void* plaintext;
  AlgorithmReturn algorithmReturn;
  unsigned long startTime;
  unsigned long endTime;
};



