#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <string.h>

/**
 * @brief Converts the first 8 characters of a string to a uint64_t.
 *
 * Each character is treated as a byte and placed into the uint64_t 
 * using a little-endian like structure (the first character is the 
 * least significant byte). Any remaining bytes are 0.
 *
 * @param str The null-terminated string to convert.
 * @return The resulting uint64_t value.
 */
uint64_t string_to_uint64(const char* str);

void uint64_to_string(uint64_t value, char* buffer); 
void uint8_to_string(uint8_t value, char* buffer);

uint8_t* createUint8List(int);
uint16_t* createUint16List(int);
uint32_t* createUint32List(int);
uint64_t* createUint64List(int);
#endif /* STRING_TO_UINT64_H */