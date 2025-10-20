#ifndef _GIFT64_H
#define _GIFT64_H
#include <inttypes.h>

// Add extern "C" block for C++ compatibility
#ifdef __cplusplus
extern "C" {
#endif

uint64_t GIFT64_Encryption(uint64_t, uint16_t*);
uint64_t GIFT64_Decryption(uint64_t, uint16_t*);
// It's cleaner to use the pointer form for the declaration:
void useGift64(uint64_t, uint16_t*); 

#ifdef __cplusplus
}
#endif

#endif // _GIFT64_H