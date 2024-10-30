#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <cmath>
//#include "structures.h"
//#include "cipherDEnc.h"
//#include "cipherDDec.h"
#include "cipherDEval.h"

using namespace std;

int main(){
    unsigned char message[4];
    unsigned char Key[12];
    int numberOfTests = 100;
    double prob[numberOfTests];
    double prob_avg = 0;
    for(int i = 0; i < numberOfTests; ++i){
        std::random_device rd;
        default_random_engine generator {rd()};
        uniform_int_distribution<unsigned char> dis(0,0xf);
        for(int j = 0; j < 12; ++j){
            Key[j] = dis(generator);
        }
        int counter = 0;
        for(message[0] = 0; message[0] < 16; ++message[0]){
            for(message[1] = 0; message[1] < 16; ++message[1]){
                for(message[2] = 0; message[2] < 16; ++message[2]){
                    for(message[3] = 0; message[3] < 16; ++message[3]){
                        unsigned char encryptedMessage[4];
                        CipherDEncrypt(message, Key, encryptedMessage, 2);
                        if((message[0] / 4 % 2) ^ (encryptedMessage[0] / 4 % 2) == 0){
                            counter++;
                        }
                    }
                }
            }
        }
        prob[i] = (double)(counter/65536.0);
        prob_avg += prob[i];
    }
    std::cout << dec << (double)abs(0.5-prob_avg/numberOfTests) << std::endl;
    return 0;
}