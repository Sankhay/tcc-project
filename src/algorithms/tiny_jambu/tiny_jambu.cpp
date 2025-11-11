/* TinyJAMBU-128: 128-bit key, 96-bit IV  
     Reference implementation for 32-bit CPU 
     The state consists of four 32-bit registers      
     state[3] || state[2] || state[1] || state[0]   

     Implemented by: Hongjun Wu 
*/  

#include <string.h> 
#include <stdio.h>
#include <stdint.h> // <-- Added for uint32_t
#include <algorithms/tiny_jambu/tiny_jambu.h>
#include <Arduino.h>

#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50  //Framebits for plaintext/ciphertext      
#define FrameBitsFinalization 0x70       

#define NROUND1 128*5 
#define NROUND2 128*10

void useTinyJambu(unsigned char plaintext[CRYPTO_BYTES], unsigned char key[TJ_CRYPTO_KEYBYTES], unsigned char nonce[TJ_CRYPTO_NPUBBYTES], unsigned char add[TJ_CRYPTO_ABYTES], AlgorithmReturn* algorithmReturn) {
        
        unsigned long long mlen;
        unsigned long long clen;

        unsigned char cipher[CRYPTO_BYTES + 8]; 

        unsigned char plaintext_decrypted[CRYPTO_BYTES];
       
        int ret = crypto_aead_encrypt_tiny_jambu(
                cipher,&clen,
                plaintext, CRYPTO_BYTES,
                add,TJ_CRYPTO_ABYTES,
                NULL,nonce,key);

        algorithmReturn->encryptionTime = millis();

        algorithmReturn->encryptedData = malloc(40 * sizeof(CRYPTO_BYTES + 8));
        memcpy(algorithmReturn->encryptedData, cipher, 40 * sizeof(CRYPTO_BYTES + 8));

        int retDecrypt = crypto_aead_decrypt_tiny_jambu(
                plaintext_decrypted,&mlen,
                NULL,
                cipher,clen,
                add,TJ_CRYPTO_ABYTES,
                nonce,key);

        if (retDecrypt == ret && retDecrypt == 0) {
                algorithmReturn->success = true;
        } else {
                algorithmReturn->success = false;
        }
} 

 
void state_update(uint32_t *state, const unsigned char *key, uint32_t number_of_steps) 
{
        uint32_t i;  
        uint32_t t1, t2, t3, t4, feedback; 
        for (i = 0; i < (number_of_steps >> 5); i++)
        {
                t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
                t2 = (state[2] >> 6)  | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
                t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
                t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
                feedback = state[0] ^ t1 ^ (~(t2 & t3)) ^ t4 ^ ((uint32_t*)key)[i & 3];
                // shift 32 bit positions 
                state[0] = state[1]; state[1] = state[2]; state[2] = state[3]; 
                state[3] = feedback;
        }
}

// The initialization  
/* The input to initialization is the 128-bit key; 96-bit IV;*/
void initialization(const unsigned char *key, const unsigned char *iv, uint32_t *state)
{
        int i;

        //initialize the state as 0  
        for (i = 0; i < 4; i++) state[i] = 0;     

        //update the state with the key  
        state_update(state, key, NROUND2);  

        //introduce IV into the state  
        for (i = 0;  i < 3; i++)  
        {
                state[1] ^= FrameBitsIV;   
                state_update(state, key, NROUND1); 
                state[3] ^= ((uint32_t*)iv)[i]; 
        }   
}

//process the associated data   
void process_ad(const unsigned char *k, const unsigned char *ad, unsigned long long adlen, uint32_t *state)
{
        unsigned long long i; 
        unsigned int j; 

        for (i = 0; i < (adlen >> 2); i++)
        {
                state[1] ^= FrameBitsAD;
                state_update(state, k, NROUND1);
                state[3] ^= ((uint32_t*)ad)[i];
        }

        // if adlen is not a multiple of 4, we process the remaining bytes
        if ((adlen & 3) > 0)
        {
                state[1] ^= FrameBitsAD;
                state_update(state, k, NROUND1);
                for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
                state[1] ^= adlen & 3;
        }   
}     

//encrypt plaintext   
int crypto_aead_encrypt_tiny_jambu(
        unsigned char *c,unsigned long long *clen,
        const unsigned char *m,unsigned long long mlen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *nsec,
        const unsigned char *npub,
        const unsigned char *k
        )
{
        unsigned long long tj_i;
        unsigned int j; 
        unsigned char mac[8]; 
        uint32_t state[4];   

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state); 

        //process the plaintext    
        for (tj_i = 0; tj_i < (mlen >> 2); tj_i++)
        {
                state[1] ^= FrameBitsPC;  
                state_update(state, k, NROUND2); 
                state[3] ^= ((uint32_t*)m)[tj_i];  
                ((uint32_t*)c)[tj_i] = state[2] ^ ((uint32_t*)m)[tj_i];  
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((mlen & 3) > 0)
        {   
                state[1] ^= FrameBitsPC; 
                state_update(state, k, NROUND2);    
                for (j = 0; j < (mlen & 3); j++)  
                {
                        ((unsigned char*)state)[12 + j] ^= m[(tj_i << 2) + j];   
                        c[(tj_i << 2) + j] = ((unsigned char*)state)[8 + j] ^ m[(tj_i << 2) + j];
                }   
                state[1] ^= mlen & 3;   
        }

        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND2);
        ((uint32_t*)mac)[0] = state[2];

        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND1);
        ((uint32_t*)mac)[1] = state[2];

        *clen = mlen + 8; 
        for (j = 0; j < 8; j++) c[mlen+j] = mac[j];  

        return 0;
}

// decrypt a message
int crypto_aead_decrypt_tiny_jambu(
        unsigned char *m,unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c,unsigned long long clen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
        )
{
        unsigned long long tj_i;
        unsigned int tj_j, check = 0;
        unsigned char mac[8];
        uint32_t state[4];

        *mlen = clen - 8; 

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state);

        //process the ciphertext    
        for (tj_i = 0; tj_i < (*mlen >> 2); tj_i++)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                ((uint32_t*)m)[tj_i] = state[2] ^ ((uint32_t*)c)[tj_i];
                state[3] ^= ((uint32_t*)m)[tj_i]; 
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((*mlen & 3) > 0)   
        {
                state[1] ^= FrameBitsPC;  
                state_update(state, k, NROUND2);
                for (tj_j = 0; tj_j < (*mlen & 3); tj_j++)
                {
                        m[(tj_i<< 2) + tj_j] = c[(tj_i << 2) + tj_j] ^ ((unsigned char*)state)[8 + tj_j];
                        ((unsigned char*)state)[12 + tj_j] ^= m[(tj_i << 2) + tj_j];
                }   
                state[1] ^= *mlen & 3;  
        }
        
        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND2);
        ((uint32_t*)mac)[0] = state[2];
        
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND1);    
        ((uint32_t*)mac)[1] = state[2];

        //verification of the authentication tag   
        for (tj_j = 0; tj_j < 8; tj_j++) { check |= (mac[tj_j] ^ c[clen - 8 + tj_j]); }
        if (check == 0) return 0;  
        else return -1;
}
