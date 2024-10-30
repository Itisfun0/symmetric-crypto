/* cipherDEnc.h
 * Perform encryption using CipherD 16-bit
 * @author Xiaxi
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"

using namespace std;

/* Serve as the initial round during encryption
 * AddRoundKey is simply an XOR of a 16-bit block with the 16-bit Key.
 */
void AddRoundKey(unsigned char * state, unsigned char * roundKey){
    for(int i = 0; i < 4; ++i){
        state[i] ^= roundKey[i];
    }
}

/* Perform substitution to each of the 1 byte
 * Use S-box as lookup table
 */
void SubBytes(unsigned char * state){
    for(int i = 0; i < 4; ++i){
        state[i] = opt_s[state[i]];
    }
}

/* Perform permutation to the block of 16 bites
 * Use bit permutation
 */
void Perm(unsigned char * state){
    unsigned char newState[4] = {
        0x0, 0x0, 0x0, 0x0
    };
    for(int i = 0; i < 4; ++i){
        for(int j = 0; j < 4; ++j){
            // the j-th bit of i-th byte goes to the j1-th bit of i1-th byte
            int i1 = 0;
            int j1 = 0;
            j1 = p[4 * j + i] % 4;
            i1 = (p[4 * j + i] - j1) / 4;
            newState[i1] += 2^j1 * (state[i] / 2^j % 2);
        }
    }
}

/* Each round operates on 16 bits at a time
 * The number of rounds is defined in CipherDEncrypt
 */
void EncRound(unsigned char * state, unsigned char * key){
    AddRoundKey(state, key);
    SubBytes(state);
    Perm(state);
}

/* Same as Round() except it doesn't permute bits*/
void FinalEncRound(unsigned char * state, unsigned char * key){
    AddRoundKey(state, key);
    SubBytes(state);
}

/* The CipherD encryption function
 */
void CipherDEncrypt(unsigned char * message, unsigned char * Key, unsigned char * encryptedMessage, int numberOfRounds){
    unsigned char state[4];
    for (int i = 0; i < 4; ++i){
        state[i] = message[i];
    }
    for (int i = 0; i < numberOfRounds-1; ++i){
        EncRound(state, Key + (4 * i));
    }
    FinalEncRound(state, Key + 4 * (numberOfRounds-1));
    // whitening key
    AddRoundKey(state, Key + 4 * numberOfRounds);
    for (int i = 0; i < 4; ++i){
        encryptedMessage[i] = state[i];
    }
}