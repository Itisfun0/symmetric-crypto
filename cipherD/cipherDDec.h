/* cipherDDec.h
 * Perform decryption using CipherD 16-bit
 * @author Xiaxi
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"

using namespace std;

/* Inverse bit permutation
 * using inv_p
 */
void InversePerm(unsigned char * state){
    unsigned char newState[4] = {
        0x0, 0x0, 0x0, 0x0
    };
    for(int i = 0; i < 4; ++i){
        for(int j = 0; j < 4; ++j){
            int i1 = 0;
            int j1 = 0;
            j1 = inv_p[4 * j + i] % 4;
            i1 = (inv_p[4 * j + i] - j1) % 4;
            newState[i1] += 2^j1 * (state[i] / 2^j % 2);
        }
    }
}

/* Inverse SubBytes
 * using inv_s
 */
void InverseSubBytes(unsigned char * state){
    for(int i = 0; i < 4; ++i){
        state[i] = inv_opt_s[state[i]];
    }
}

/* Serve as the initial round during decryption
 * AddRoundKey is simply an XOR of a 16-bit block with the 16-bit Key.
 */
void SubRoundKey(unsigned char * state, unsigned char * roundKey){
    for(int i = 0; i < 4; ++i){
        state[i] ^= roundKey[i];
    }
}

/* Each round operates on 16 bits at a time
 * The number of rounds is defined in CipherDecrypt()
 */
void DecRound(unsigned char * state, unsigned char * key){
    InversePerm(state);
    InverseSubBytes(state);
    SubRoundKey(state, key);
}

void InitialDecRound(unsigned char * state, unsigned char * key){
    InverseSubBytes(state);
    SubRoundKey(state, key);
}

void CipherDDecrypt(unsigned char * encryptedMessage, unsigned char * Key, unsigned char * decryptedMessage, int numberOfRounds){
    unsigned char state[4];
    for(int i = 0; i < 4; ++i){
        state[i] = encryptedMessage[i];
    }
    SubRoundKey(state, Key + 4 * numberOfRounds);
    InitialDecRound(state, Key + 4 * (numberOfRounds-1));
    for(int i = numberOfRounds-2; i >= 0; --i){
        DecRound(state, Key + 4 * i);
    }
    for(int i = 0; i < 4; ++i){
        decryptedMessage[i] = state[i];
    }
}