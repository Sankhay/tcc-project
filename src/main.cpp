#include "Arduino.h"
#include "utils/utils.h"
#include "setup/setup.h"
#include "structs/structs.h"
#include <SD.h>
#include "config.h"

/**
 * @brief Displays a formatted report of performance metrics to the Serial monitor.
 * * This optimized version uses sprintf() to format the output efficiently, 
 * avoiding multiple String allocations within the loop.
 * It also prints "True" or "False" for better readability.
 * * @param metricsArray Pointer to the array of PerformanceMetrics structs.
 * @param numItems The number of items in the array.
 */

 char* bytesToHex(const void* src, size_t len) {
    // Cada byte (2 dígitos hex) + espaço + '\0'
    char* dest = (char*)malloc(len * 2 + 1);
    if (dest == NULL) return NULL; 

    const uint8_t* byteSrc = (const uint8_t*)src;
    
    for (size_t i = 0; i < len; i++) {
        sprintf(&dest[i * 2], "%02X", byteSrc[i]);
    }
    dest[len * 2] = '\0';

    return dest;
}

struct Algorithm speck = {"SPECK",  2 * sizeof(uint64_t),  2 * sizeof(uint64_t),  2 * sizeof(uint64_t)};
struct Algorithm chacha20 = {"CHACHA20", CHACHA20_DATA_SIZE * sizeof(uint8_t), 32 * sizeof(uint8_t),  CHACHA20_DATA_SIZE * sizeof(uint8_t)};
struct Algorithm gift64 = {"GIFT64", sizeof(uint64_t), 8 * sizeof(uint16_t), sizeof(uint64_t)};
struct Algorithm elephant = {"Elephant", 16 * sizeof(unsigned char), 8 * sizeof(unsigned char), 24 * sizeof(unsigned char)};
struct Algorithm tinyJambu = {"TINYJAMBU", 32 * sizeof(uint8_t), 16 * sizeof(uint16_t), 40 * sizeof(unsigned char)};
// --- The Array of All Algorithms to Test ---
AlgorithmBenchmark benchmarks[] = {
    //{speck,      speck_wrapper,      setup_speck,      teardown_speck},
    //{chacha20,   chacha20_wrapper,   setup_chacha20,   teardown_chacha20},
    //{gift64,     gift64_wrapper,     setup_gift64,     teardown_gift64},
    {elephant,   elephant_wrapper,   setup_elephant,   teardown_elephant},
    //{tinyJambu,  tiny_jambu_wrapper, setup_tinyjambu,  teardown_tinyjambu}
};

const int NUM_ALGORITHMS = sizeof(benchmarks) / sizeof(benchmarks[0]);

int freeRam() {
  extern int __heap_start, *__brkval;
  int v;
  return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval);
}

PerformanceMetrics measurePerformance(MeasurableFunction functionToMeasure, void* context) {
  PerformanceMetrics metrics;

  AlgorithmReturn algorithmReturnOrigin;

  metrics.startTime = millis();
  int ramBefore = freeRam();
  functionToMeasure(context, &algorithmReturnOrigin);
  metrics.endTime = millis();
  int ramAfter = freeRam();
  metrics.ramUsedBytes = ramBefore - ramAfter;


  metrics.algorithmReturn = algorithmReturnOrigin; 

  return metrics;
}

void displayAndSaveMetric(File& dataFile, const PerformanceMetrics& metric) {
    unsigned long totalExecutionTime = metric.endTime - metric.startTime;
    unsigned long encryptionTime = metric.algorithmReturn.encryptionTime - metric.startTime;
    unsigned long decryptionTime = metric.endTime - metric.algorithmReturn.encryptionTime;
    const char* successString = metric.algorithmReturn.success ? "True" : "False";

    // --- Generate Hex for Encrypted Data ---
    char* hexData = NULL;
    if (metric.algorithmReturn.encryptedData != NULL && metric.algorithm.encryptedDataSize > 0) {
        hexData = bytesToHex(metric.algorithmReturn.encryptedData, metric.algorithm.encryptedDataSize);
    } else {
        hexData = strdup("N/A");
    }
    
    // --- Generate Hex for Plaintext (NEW) ---
    char* plaintextHex = NULL;
    if (metric.plaintext != NULL && metric.algorithm.plainTextSize > 0) {
        plaintextHex = bytesToHex(metric.plaintext, metric.algorithm.plainTextSize);
    } else {
        plaintextHex = strdup("N/A");
    }

    // --- Generate Hex for Key (NEW) ---
    char* keyHex = NULL;
    if (metric.key != NULL && metric.algorithm.keySize > 0) {
        keyHex = bytesToHex(metric.key, metric.algorithm.keySize);
    } else {
        keyHex = strdup("N/A");
    }
    // ----------------------------------------------------


    // Increased buffer size significantly for long hex strings
    char serialBuffer[512]; 
    char csvBuffer[512]; 

    // Saída Serial: Adicionando colunas para dados cifrados, plaintext e key
    // Using %-15s for the hex columns to provide better structure.
    sprintf(serialBuffer, "%-15s| %-12lu | %-12lu | %-12lu | %-12d | %-7s | %-15s | %-15s | %s",
            metric.algorithm.algorithName,
            encryptionTime,
            decryptionTime,
            totalExecutionTime,
            metric.ramUsedBytes,
            successString,
            plaintextHex,      // NEW: Plaintext Hex
            keyHex,            // NEW: Key Hex
            hexData);          // Encrypted Data Hex

    // Saída CSV: Adicionando colunas (Note: Removed hexDataSize which was unused in final display)
    sprintf(csvBuffer, "%s,%lu,%lu,%lu,%d,%s,%s,%s,%s",
            metric.algorithm.algorithName,
            encryptionTime,
            decryptionTime,
            totalExecutionTime,
            metric.ramUsedBytes,
            successString,
            plaintextHex,
            keyHex,
            hexData);

    Serial.println(serialBuffer);
    
    if (dataFile) {
        dataFile.println(csvBuffer);
    }

    // --- LIMPEZA DE MEMÓRIA CRÍTICA ---
    // 1. Libera as strings Hex geradas (CRITICAL for memory)
    if (hexData != NULL) {
        free(hexData);
    }
    if (plaintextHex != NULL) {
        free(plaintextHex);
    }
    if (keyHex != NULL) {
        free(keyHex);
    }

    
    // 2. Libera o buffer de dados cifrados alocado na função de benchmark (if needed)
    if (metric.algorithmReturn.encryptedData != NULL) {
        free(metric.algorithmReturn.encryptedData);
    }

    // -----------------------------------
}

void readAndDisplayFile(const char* filename) {
    Serial.print("\n--- Conteúdo Completo do Arquivo SD (");
    Serial.print(filename);
    Serial.println(") ---");
    
    File dataFile = SD.open(filename);

    if (dataFile) {
        while (dataFile.available()) {
            Serial.write(dataFile.read());
        }
        
        dataFile.close();
        
        Serial.println("\n--- Fim da Leitura do Arquivo ---");
    } else {
        Serial.print("Erro ao abrir ");
        Serial.print(filename);
        Serial.println(" para leitura!");
    }
}

void setup() {
    Serial.begin(9600);
    while (!Serial) { ; }

    Serial.print("Inicializando cartão SD...");
    if (!SD.begin(SD_CS_PIN)) {
        Serial.println("Falha! Verifique:");
        Serial.println("- Cartão SD inserido?");
        Serial.println("- Conexões corretas?");
        Serial.println("- Cartão formatado (FAT16/FAT32)?");
        while (1) { ; }
    }
    Serial.println("OK!");

    Serial.print("Verificando e removendo arquivo de resultados anterior...");
    if (SD.exists(RESULTS_FILENAME)) {
        if (SD.remove(RESULTS_FILENAME)) {
            Serial.print(" Sucesso! ("); Serial.print(RESULTS_FILENAME); Serial.println(" removido)");
        } else {
            Serial.print(" ERRO ao remover "); Serial.print(RESULTS_FILENAME); Serial.println("!");
        }
    } else {
         Serial.print(" "); Serial.print(RESULTS_FILENAME); Serial.println(" não existe.");
    }
    

    File dataFile = SD.open(RESULTS_FILENAME, FILE_WRITE);
    
    Serial.println("\n--- Algorithm Performance Report ---");
    // Updated header to include Plaintext and Key, and remove size
    Serial.println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
    Serial.println("Algorithm      | Encrypt (us) | Decrypt (us) | Total (us)   | RAM (bytes)    | Success | Plaintext (Hex) | Key (Hex) | Encrypted Data (Hex)");
    Serial.println("---------------|--------------|--------------|--------------|----------------|---------|-----------------|-----------|---------------------");

    // Linhas de cabeçalho do CSV (REMOVED size)
    if (dataFile) {
        dataFile.println("Algorithm,Encrypt (us),Decrypt (us),Total (us),RAM (bytes),Success,Plaintext (Hex),Key (Hex),Encrypted Data (Hex)");
    } else {
        Serial.println("Erro ao abrir arquivo no cartão SD para escrita! Resultados não serão salvos.");
    }
    
    for (int i = 0; i < NUM_ITERATIONS; i++) {        
        for (int j = 0; j < NUM_ALGORITHMS; j++) {
            AlgorithmBenchmark& current_benchmark = benchmarks[j];

            CommomParams commomParam;
            
            void* context = current_benchmark.setup_function(&commomParam);
            if (context == NULL) {
                Serial.print("Failed to allocate context for ");
                Serial.println(current_benchmark.algorithm.algorithName);
                continue; 
            }

            PerformanceMetrics result = measurePerformance(
                current_benchmark.benchmark_function, 
                context
            );

            result.algorithm = current_benchmark.algorithm;
            result.key = commomParam.key;
            result.plaintext = commomParam.plaintext;

            displayAndSaveMetric(dataFile, result); 
            
            current_benchmark.teardown_function(context);
        }
    }
    
    Serial.println("---------------------------------------------------------------------------------------");
    
    if (dataFile) {
        dataFile.println("---------------------------------------------------------------------------------------");
        dataFile.close();
        Serial.println("Resultados salvos no cartão SD: results.txt");
    }
    
    readAndDisplayFile(RESULTS_FILENAME);
}

void loop() {
  
}
