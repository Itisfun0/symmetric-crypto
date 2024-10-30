/* cipherDEval.h
 * Generate DDT, LAT of cipherD
 * Perform key recovery attack via 2-round linear characteristic
 * @author Xiaxi
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <random>
#include <cmath>
#include "structures.h"
#include "cipherDEnc.h"
#include "cipherDDec.h"

using namespace std;

// computing DDT for 4-bit sBox
void difference_distribution_matrix(int DDT[16][16], unsigned char * sBox){
    memset(DDT[0], 0, sizeof(int) * 16 * 16);
    for(unsigned char in0 = 0; in0 < 16; ++in0){
        for(unsigned char in1 = 0; in1 < 16; ++in1){
            unsigned char id = in0 ^ in1;
            unsigned char od = sBox[in0] ^ sBox[in1];
            DDT[id][od]++;
        }
    }
}
// computing LAT for 4-bit sBox
void linear_approximation_matrix(int LAT[16][16], unsigned char * sBox){
    memset(LAT[0], 0, sizeof(int) * 16 * 16);
    for(unsigned char im = 0; im < 16; ++im){
        for(unsigned char om = 0; om < 16; ++om){
            for(unsigned char x = 0; x < 16; ++x){
                unsigned char ia = im & x;
                unsigned char oa = om & sBox[x];
                if(hamming_weight_mod_2(ia ^ oa) == 0){
                    LAT[im][om]++;
                }
            }
        }
    }
    for(unsigned char im = 0; im < 16; ++im){
        for(unsigned char om = 0; om < 16; ++om){
            LAT[im][om] = LAT[im][om] - 8;
        }
    }
}
// key recovery: 1-bit information + 4-th 16-bit round key
bool key_recovery(unsigned char * Key, unsigned char * guessKey, double successProb){
    std::random_device rd;
    default_random_engine generator {rd()};
    uniform_int_distribution<unsigned char> dis(0,0xf);
    int numberOfSamples;
    numberOfSamples = (int)(1.0/(1-successProb)) * (int)(1.0/(1-successProb)) * 100;
    unsigned char message[numberOfSamples][4];
    unsigned char encryptedMessage[numberOfSamples][4];
    int counter[256];
    int numberOfList = 40;
    memset(counter, 0, sizeof(int) * 256);
    for(int i = 0; i < numberOfSamples; ++i){
        // cout << "I am here!" << '\n';
        for(int j = 0; j < 4; ++j){
            message[i][j] = dis(generator);
        }
        CipherDEncrypt(message[i], Key, encryptedMessage[i], 4);
        unsigned char guess1;
        unsigned char guess2;
        for(guess1 = 0; guess1 < 16; ++guess1){
            for(guess2 = 0; guess2 < 16; ++guess2){
                unsigned char state1 = encryptedMessage[i][0];
                unsigned char state2 = encryptedMessage[i][2];
                state1 ^= guess1;
                state1 = inv_opt_s[state1];
                state2 ^= guess2;
                state2 = inv_opt_s[state2];
                unsigned char P0 = message[i][0] % 2;
                unsigned char P3 = message[i][0] / 8 % 2;
                unsigned char Z3_0 = state1 % 2;
                unsigned char Z3_2 = state1 / 4 % 2;
                unsigned char Z3_8 = state2 % 2;
                unsigned char Z3_10 = state2 / 4 % 2;
                if(P0 ^ P3 ^ Z3_0 ^ Z3_2 ^ Z3_8 ^ Z3_10 == 0){
                        counter[guess1+16*guess2]++;
                }
            }
        }

    }
    // want to maintain top numberOfCandidate <= 50 possible round keys
    int counterMax;
    int max;
    int candidatesMax[numberOfList][2];
    int numberOfCandidateMax = 1;
    int counterMin;
    int min;
    int candidatesMin[numberOfList][2];
    int numberOfCandidateMin = 1;
    // initialize candidatesMax and candidatesMin
    max = 0;
    counterMax = counter[0];
    candidatesMax[0][0] = 0;
    candidatesMax[0][1] = counter[0];
    min = 0;
    counterMin = counter[0];
    candidatesMin[0][0] = 0;
    candidatesMin[0][1] = counter[0];
    for(int i = 1; i < 256; ++i){
        if(counter[i] > counterMax){
            // update counterMax
            counterMax = counter[i];
            max = i;
        }
        if(numberOfCandidateMax < numberOfList){
            numberOfCandidateMax++;
            candidatesMax[numberOfCandidateMax-1][0] = i;
            candidatesMax[numberOfCandidateMax-1][1] = counter[i];
            continue;
        }
        else{
            int tmp[2];
            tmp[0] = i;
            tmp[1] = counter[i];
            for(int j = 0; j < numberOfList; ++j){
                if(candidatesMax[j][1] < tmp[1]){
                    int copy[2];
                    copy[0] = candidatesMax[j][0];
                    copy[1] = candidatesMax[j][1];
                    candidatesMax[j][0] = tmp[0];
                    candidatesMax[j][1] = tmp[1];
                    tmp[0] = copy[0];
                    tmp[1] = copy[1];
                }
            }
        }
    }
    for(int i = 1; i < 256; ++i){
        if(counter[i] < counterMin){
            // update counterMin 
            counterMin = counter[i];
            min = i;
        }
        if(numberOfCandidateMin < numberOfList){
            numberOfCandidateMin++;
            candidatesMin[numberOfCandidateMin-1][0] = i;
            candidatesMin[numberOfCandidateMin-1][1] = counter[i];
            continue;
        }
        else{
            int tmp[2];
            tmp[0] = i;
            tmp[1] = counter[i];
            for(int j = 0; j < numberOfList; ++j){
                if(candidatesMin[j][1] > tmp[1]){
                    int copy[2];
                    copy[0] = candidatesMin[j][0];
                    copy[1] = candidatesMin[j][1];
                    candidatesMin[j][0] = tmp[0];
                    candidatesMin[j][1] = tmp[1];
                    tmp[0] = copy[0];
                    tmp[1] = copy[1];
                }
            }
        }
    }
    /*
    if(counterMax + counterMin > numberOfSamples){
        for(int i = 0; i < numberOfCandidateMax; ++i){
            (*guessKey + i)[0] = candidatesMax[i][0] % 16;
            (*guessKey + i)[1] = candidatesMax[i][0] / 16 % 16;
            (*guessKey + i)[2] = candidatesMax[i][0] / 256 % 16;
            (*guessKey + i)[3] = candidatesMax[i][0] / 4096 % 16;
        }
    }
    else{
        for(int i = 0; i < numberOfCandidateMin; ++i){
            (*guessKey + i)[0] = candidatesMin[i][0] % 16;
            (*guessKey + i)[1] = candidatesMin[i][0] / 16 % 16;
            (*guessKey + i)[2] = candidatesMin[i][0] / 256 % 16;
            (*guessKey + i)[3] = candidatesMin[i][0] / 4096 % 16;
        }
    }
    cout << '\n' << dec << (int)counterMax << ' ';
    for(int i = 0; i < numberOfList; ++i){
        cout << dec << (int)candidatesMax[i][1] << ' ';
    }
    cout << '\n' << dec << (int)counterMin << ' ';
    for(int i = 0; i < numberOfList; ++i){
        cout << dec << (int)candidatesMin[i][1] << ' ';
    }
    cout << '\n' << "true key" << dec << (int)counter[Key[17]+16*Key[19]];
    */
    if(counterMax + counterMin > numberOfSamples){
        for(int i = 0; i < numberOfList; ++i){
            //cout << '\n' << hex << (int)candidatesMax[i][0]%16 << hex << (int)candidatesMax[i][0]/16%16;
            if(Key[16]+16*Key[18] == candidatesMax[i][0]) return true;
        }
        return false;
    }
    else{
        for(int i = 0; i < numberOfList; ++i){
            //cout << '\n' << hex << (int)candidatesMin[i][0]%16 << hex << (int)candidatesMin[i][0]/16%16;
            if(Key[16]+16*Key[18] == candidatesMin[i][0]) return true;
        }
        return false;
    }
}