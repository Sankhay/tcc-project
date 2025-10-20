#include "utils/utils.h"
#include <stdint.h>
#include <stdlib.h>
#include "setup/setup.h"
#include "algorithms/chacha20/ChaCha20.h"
#include "algorithms/Elephant/crypto_aead/elephant160v1/ref/elephant_160.h"
#include "algorithms/gift64/GIFT64.h"
#include "algorithms/speck/speck.h"
#include "algorithms/tiny_jambu/tiny_jambu.h"

void speck_wrapper(void* context) {
    SpeckParams* params = (SpeckParams*)context;
    useSpeck(params->plaintext, params->key); 
}

void chacha20_wrapper(void* context) {
  ChaCha20Params* params = (ChaCha20Params*)context;
  useChaCha20(params->key, params->nonce, params->data);
}

void gift64_wrapper(void* context) {
  Gift64Params* params = (Gift64Params*)context;
  useGift64(params->plaintext, params->key);
}


void elephant_wrapper(void* context) {
  ElephantParams* params = (ElephantParams*)context;
  useElephant(params->key, params->nonce, params->plaintext, NULL);
}

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
    params->data = createUint8List(8);
    params->nonce = createUint8List(12);
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

    params->plaintext = (uint64_t)createUint64List(1);; // Or some random value
    params->key = (uint16_t*)createUint8List(16); // Assuming key is 128-bit
    return params;
}

void teardown_gift64(void* context) {
    Gift64Params* params = (Gift64Params*)context;
    free(params->key);
    free(params->plaintext);
    free(params);
}

// --- For Elephant ---
void* setup_elephant() {
    ElephantParams* params = (ElephantParams*)malloc(sizeof(ElephantParams));
    
    if (!params) {
      return NULL;
    }

    params->plaintext = (BYTE*)malloc(16 * sizeof(BYTE));
    
    if (!params->plaintext) {
      free(params);
      return NULL;
    }
    

    generate_random_bytes(params->key, 16);
    generate_random_bytes(params->nonce, 12);
    generate_random_bytes(params->plaintext, 16);
   
    return params;
}

void teardown_elephant(void* context) {
    ElephantParams* params = (ElephantParams*)context;
    free(params->plaintext);
    free(params);
}

// --- For TinyJambu ---
void* setup_tinyjambu() {
    TinyJambuParams* params = (TinyJambuParams*)malloc(sizeof(TinyJambuParams));
    if (!params) return NULL;

    uint8_t* temp_list;

    temp_list = createUint8List(8); 
    if (!temp_list) { free(params); return NULL; }
    params->plaintext = convertUint8ToChar(temp_list, 8);
    free(temp_list);

    temp_list = createUint8List(32); 
    if (!temp_list) { free(params); return NULL; }
    params->key = convertUint8ToChar(temp_list, 32);
    free(temp_list);

    temp_list = createUint8List(32);
    if (!temp_list) { free(params); return NULL; }
    params->nonce = convertUint8ToChar(temp_list, 32);
    free(temp_list); 
    
    return params;
}

void teardown_tinyjambu(void* context) {
    TinyJambuParams* params = (TinyJambuParams*)context;
    free(params->plaintext);
    free(params->key);
    free(params->nonce);
    free(params);
}


char* convertUint8ToChar(uint8_t* uint8List, int length) {
    char *charList = (char *)malloc(length + 1); // +1 for null terminator
    if (!charList) return NULL; // Good to check malloc success

    for(int i = 0; i < length; i++) {
        charList[i] = (char)uint8List[i];
    }
    
    charList[length] = '\0'; // <-- THE FIX
    
    return charList;
}

void generate_random_bytes(BYTE* buffer, SIZE length) {
    for (SIZE i = 0; i < length; i++) {
        buffer[i] = rand() % 256;
    }
}

