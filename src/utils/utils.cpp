#include <stdint.h>
#include <string.h>
#include "Arduino.h"
#include "utils/utils.h"

uint64_t string_to_uint64(const char* str) {
    uint64_t result = 0;
    size_t len = strlen(str);
    size_t copy_len = (len > 8) ? 8 : len; // Only take first 8 characters for 64 bits
    
    for (size_t i = 0; i < copy_len; i++) {
        result |= ((uint64_t)str[i] << (8 * i));
    }
    return result;
}

void uint64_to_string(uint64_t value, char* buffer) {
    for (int i = 0; i < 8; i++) {
        buffer[i] = (char)(value >> (8 * i));
    }
    buffer[8] = '\0';
}

void uint8_to_string(uint8_t value, char* buffer) {
    // Place the single byte into the first position of the buffer.
    buffer[0] = (char)value;
    
    // Add the null terminator to make it a valid C-string.
    buffer[1] = '\0';
}


uint8_t* createUint8List(int size) {
  uint8_t* list = (uint8_t*)malloc(size * sizeof(uint8_t));
  
  if (list == NULL) {
    return NULL;
  }
  
  for (int i = 0; i < size; i++) {
      list[i] = (uint8_t)random(255);
  }

  return list;
}

uint16_t* createUint16List(int size) {
  uint16_t* list = (uint16_t*)malloc(size * sizeof(uint16_t));
  
  if (list == NULL) {
    return NULL;
  }
  
  for (int i = 0; i < size; i++) {
      list[i] = (uint16_t)random(65535);
  }

  return list;
}

uint32_t* createUint32List(int size) {
  uint32_t* list = (uint32_t*)malloc(size * sizeof(uint32_t));
  
  if (list == NULL) {
    return NULL;
  }
  
  for (int i = 0; i < size; i++) {
      list[i] = (uint32_t)random(4294967295);
  }

  return list;
}

uint64_t* createUint64List(int size) {
  uint64_t* list = (uint64_t*)malloc(size * sizeof(uint64_t));
  
  if (list == NULL) {
    return NULL;
  }
  
  for (int i = 0; i < size; i++) {
    uint64_t high_bits = (uint64_t)random(4294967295) << 32;
    uint64_t low_bits = (uint64_t)random(4294967295);
    list[i] = high_bits | low_bits;
  }

  return list;
}