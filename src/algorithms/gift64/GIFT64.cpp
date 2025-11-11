#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "utils/utils.h"
#include "algorithms/gift64/GIFT64.h"
#include "Arduino.h"

static const uint8_t s_box[16] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x01, 0x0a, 0x04, 0x0c, 0x06, 0x0f, 0x03, 0x09, 0x02, 0x0d, 0x0b, 0x07, 0x05, 0x00, 0x08, 0x0e};

static const uint8_t inv_s_box[16] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x0d, 0x00, 0x08, 0x06, 0x02, 0x0c, 0x04, 0x0b, 0x0e, 0x07, 0x01, 0x0a, 0x03, 0x09, 0x0f, 0x05
    };

static const uint8_t PermTable[64] = {
0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3, 
4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7, 
8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11, 
12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15
};
static const uint8_t InvPermTable[64] = {
    0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63, 
    12, 1, 6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59, 
    8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55, 
    4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51
};

static const uint8_t Constant[49] = {
   //1   2    3    4    5     6     7     8    9     10     11    12     13   14    15   16
0x0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0xe, 
0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30, 0x21, 0x2, 0x5, 0xb, 0x17, 0x2e, 0x1c, 0x38, 
0x31, 0x23, 0x6, 0xd, 0x1b, 0x36, 0x2d, 0x1a, 0x34, 0x29, 0x12, 0x24, 0x8, 0x11, 0x22, 0x4
};

static void FreeKeySchedule(uint16_t ** W) {
    if (!W) return;
    
    // Start from i=1 because W[0] is the original 'key' pointer
    // and must not be freed here.
    for (int i = 1; i < 28; i++) {
        free(W[i]); // Free each 16-byte round key
    }
    free(W); // Free the main array of pointers
}

static uint64_t SubCells(uint64_t x){
    uint64_t y = 0;
    int i;
    uint64_t value, sub_value;
    for(i = 0; i < 16; i++ ) {
        value = (x >> 4*i) & 0x0f;
        //printf("SubCells value: %"SCNd8 "\n", value);
        sub_value = s_box[value];
        y = (sub_value << 4*i) ^ y;
    }    
    return y;
}

static uint64_t InvSubCells(uint64_t x){
    uint64_t y = 0;
    int i;
    uint64_t value, sub_value;
    for(i = 0; i < 16; i++ ) {
        value = (x >> 4*i) & 0x0f;
        sub_value = inv_s_box[value];
        y = (sub_value << 4*i) ^ y;
    }    
    return y;
}

static uint64_t PermBits(uint64_t x) {
    uint8_t TextArr[64];
    int i;
    for(i = 0; i <64; i++) {
        TextArr[i]=(x>>i) & 0x01;
    }
    uint64_t y = 0;
    for(i = 0; i < 64; i++) {
        uint8_t index = PermTable[i];
        uint64_t temp = TextArr[i];
        uint64_t temp2 = temp << index;
        y = temp2 ^ y;
    }

    return y;
 }

static uint64_t InvPermBits(uint64_t x) {
    uint8_t TextArr[64];
    int i;
    for(i = 0; i <64; i++) {
        TextArr[i]=(x>>i) & 0x01;
    }
    uint64_t y = 0;
    for(i = 0; i < 64; i++) {
        uint8_t index = InvPermTable[i];
        uint64_t temp = TextArr[i];
        uint64_t temp2 = temp << index;
        y = (temp2) ^ y;
    }
    return y;
 }

static uint16_t BitRotation(uint16_t Value, int Rotation_Num) {
    int i;
    uint16_t Num = Value;
    uint8_t rotatedBit;
    for(i = 1; i <= Rotation_Num; i ++) {
        rotatedBit = Num & 0x01;
        Num = (Num >> 1) | (rotatedBit <<15);
    }
    return Num;
}

static uint16_t ** KeySchedule(uint16_t * key) {
    uint16_t ** W = (uint16_t **)malloc(28*sizeof(uint16_t *));
    int i;
    //W[0] = (uint16_t *)malloc(8*sizeof(uint16_t));
    W[0] = key;
    
    for(i=1; i < 28; i++) {
        W[i] = (uint16_t *)malloc(8*sizeof(uint16_t));
        uint16_t k0 = BitRotation(W[i-1][7], 12);
        uint16_t k1 = BitRotation(W[i-1][6], 2);
        W[i][7] = W[i-1][7-2];
        W[i][6] = W[i-1][7-3];
        W[i][5] = W[i-1][7-4];
        W[i][4] = W[i-1][7-5];
        W[i][3] = W[i-1][7-6];
        W[i][2] = W[i-1][7-7];
        W[i][1] = k0;
        W[i][0] = k1;
    }
    return W;
}

static uint64_t AddRoundKey(uint64_t x, uint16_t * key, int Round) {
    //Add Key 
    uint16_t U = key[6];
    uint16_t V = key[7];
    int i;
    uint64_t u,v;
    for(i = 0; i < 16; i++) {
        u= (U >> i) & 0x01;
        v= (V >> i) & 0x01;
        x = (u<<4*i+1) ^ x;
        x = (v<< 4*i) ^ x; 
    }
    //Add Constant
    uint64_t constant = Constant[Round];
    uint64_t c0 = constant & 0x01;
    uint64_t c1 = (constant>>1) & 0x01;
    uint64_t c2 = (constant>>2) & 0x01;
    uint64_t c3 = (constant>>3) & 0x01;
    uint64_t c4 = (constant>>4) & 0x01;
    uint64_t c5 = (constant>>5) & 0x01;
    uint64_t constant1 = 1;
    x = x ^(constant1<<63);
    x = x ^(c5<< 23);
    x = x ^(c4<< 19);
    x = x ^(c3<< 15);
    x = x ^(c2<< 11);
    x = x ^(c1<< 7);
    x = x ^(c0<< 3);
    return x;
}


uint64_t GIFT64_Encryption(uint64_t plaintext, uint16_t * key) {
    uint64_t text = plaintext;
    uint16_t** W = KeySchedule(key);

    //Round 1-28
    int i;
    for(i = 1; i <=28; i++) {
        text = SubCells(text);
        text = PermBits(text);
        uint16_t * Roundkey = W[i-1];
        text = AddRoundKey(text, Roundkey, i);
        int k;
      
        }

    FreeKeySchedule(W);
    return text;
}

uint64_t GIFT64_Decryption(uint64_t ciphertext, uint16_t * key) {
    uint64_t text = ciphertext;
    uint16_t** W = KeySchedule(key);

    int i;
    for(i = 28; i >=1; i--) {
        uint16_t * Roundkey = W[i-1];
        text = AddRoundKey(text, Roundkey, i);
        text = InvPermBits(text);
        text = InvSubCells(text);
        
    }
    FreeKeySchedule(W);
    return text;
}

void useGift64(uint64_t plaintext, uint16_t key[8], AlgorithmReturn* algorithmReturn) {

    uint64_t EncryptedValue = GIFT64_Encryption(plaintext, key);
    algorithmReturn->encryptionTime = millis();

    algorithmReturn->encryptedData = malloc(sizeof(uint64_t));

    if (algorithmReturn->encryptedData != NULL) {
        // 2. CÓPIA SEGURA: Agora o ponteiro aponta para a memória alocada.
        memcpy(algorithmReturn->encryptedData, &EncryptedValue, sizeof(uint64_t));
    } else {
        Serial.println("não alocou memoria");

    }
    //memcpy(algorithmReturn->encryptedData, &EncryptedValue, sizeof(uint64_t));
    
    uint64_t DecryptedValue = GIFT64_Decryption(EncryptedValue, key);
    algorithmReturn->success = (plaintext == DecryptedValue);
};