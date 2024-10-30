/* cipherD.cpp
 * Perform encryption and decryption using CipherD 16-bit
 * @author Xiaxi
 */

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
    
    unsigned char message[4] = {
        0xC, 0x1, 0x6, 0x8
    };
    unsigned char Key[20] = {
        0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x2, 0x2, 0x9, 0x5, 0xa, 0x7
    };
    unsigned char encryptedMessage[4] = {
        0x0, 0x0, 0x0, 0x0
    };
    unsigned char decryptedMessage[4] = {
        0x0, 0x0, 0x0, 0x0
    };
    /*
    const int total_width = 6;
    // encryption
    CipherDEncrypt(message, Key, encryptedMessage, 4);
    ofstream outfile;
    outfile.open("cipher.cipherD", ios::out | ios::binary);
    if(outfile.is_open()){
        //outfile << encryptedMessage;
        for(int i = 0; i < 4; ++i){
            outfile << hex << (int)encryptedMessage[i] << " ";
        }
        outfile.close();
        cout << "Wrote encrypted message to file message.cipherD" << endl;
    }
    else cout << "Unable to open file";
    // decryption
    CipherDDecrypt(encryptedMessage, Key, decryptedMessage, 4);
    cout << "Decrypted message in hex:" << endl;
    for(int i = 0; i < 4; ++i){
        cout << hex << (int)decryptedMessage[i] << " ";
    }*/
    
    /*
    // DDT for s
    int DDT[16][16];
    difference_distribution_matrix(DDT, s);
    cout << '\n' << "The DDT is computed already!";
    std::cout << std::left;
    cout << '\n' << std::setw(total_width) << ' ';
    for(int i = 0; i < 16; ++i){
        cout << std::setw(total_width) << '&' << i;
    }
    for(int i = 0; i < 16; ++i){
        cout << '\n' << std::setw(total_width) << hex << i;
        for(int j = 0; j < 16; ++j){
            std::cout << std::setw(total_width) << '&' << dec << (int)DDT[i][j];
        }
    }
    // DDT for opt_s
    difference_distribution_matrix(DDT, opt_s);
    cout << '\n' << "The DDT is computed already!";
    std::cout << std::left;
    cout << '\n' << std::setw(total_width) << ' ';
    for(int i = 0; i < 16; ++i){
        cout << std::setw(total_width) << '&' << hex << i;
    }
    for(int i = 0; i < 16; ++i){
        cout << '\n' << std::setw(total_width) << hex << i;
        for(int j = 0; j < 16; ++j){
            std::cout << std::setw(total_width) << '&' << dec << (int)DDT[i][j];
        }
    }
    // LAT for s
    int LAT[16][16];
    linear_approximation_matrix(LAT, s);
    cout << '\n' << "The LAT is computed already!";
    std::cout << std::left;
    cout << '\n' << std::setw(total_width) << ' ';
    for(int i = 0; i < 16; ++i){
        cout << std::setw(total_width) << '&' << hex << i;
    }
    for(int i = 0; i < 16; ++i){
        cout << '\n' << std::setw(total_width) << hex << i;
        for(int j = 0; j < 16; ++j){
            std::cout << std::setw(total_width) << '&' << dec << (int)LAT[i][j];
        }
    }
    // LAT for opt_s
    linear_approximation_matrix(LAT, opt_s);
    cout << '\n' << "The LAT is computed already!";
    std::cout << std::left;
    cout << '\n';
    for(int i = 0; i < 16; ++i){
        for(int j = 0; j < 16; ++j){
            std::cout << dec << (int)LAT[i][j];
            std::cout << ", ";
        }
    }
    */
    
    // 3-round linear hull
    auto start = std::chrono::high_resolution_clock::now();
    double top_linear_hull = 0;
    int in_mask = 0;
    int out_mask = 0;
    for(int im = 1; im < 16; ++im){
        for(int om = 1; om < 65536; ++om){
            float current = 0;
            for(int m1 = 0; m1 < 65536; ++m1){
                //for(int m2 = 0; m2 < 65536; ++m2){
                    float current_trail = 1;
                    unsigned char s_in[4] = {0x0, 0x0, 0x0, 0x0};
                    unsigned char s_out[4] = {0x0, 0x0, 0x0, 0x0};
                    // 1st round linear approximation propagation
                    int tmp = im;
                    // divide 1 << 16 to 4 4-bit 
                    for(int i = 0; i < 4; ++i){
                        s_in[i] = tmp % 16;
                        tmp /= 16;
                    }
                    tmp = m1;
                    for(int i = 0; i < 4; ++i){
                        s_out[i] = tmp % 16;
                        tmp /= 16;
                    }
                    for(int i = 0; i < 4; ++i){
                        current_trail *= lat_s[s_in[i]][s_out[i]]/16.0;
                    }
                    current_trail *= 8;
                    if(current_trail == 0) continue;
                    // 2nd round linear approximation propagation
                    Perm(s_out);
                    for(int i = 0; i < 4; ++i){
                        s_in[i] = s_out[i];
                    }
                    tmp = om;
                    for(int i = 0; i < 4; ++i){
                        s_out[i] = tmp % 16;
                        tmp /= 16;
                    }
                    for(int i = 0; i < 4; ++i){
                        current_trail *= lat_s[s_in[i]][s_out[i]]/16.0;
                    }
                    current_trail *= 8;
                    if(current_trail == 0) continue;
                    current += current_trail;
                    // 3rd round linear approximation propagation
                    /*
                    Perm(s_out);
                     for(int i = 0; i < 4; ++i){
                        s_in[i] = s_out[i];
                    }
                    tmp = om;
                    for(int i = 0; i < 4; ++i){
                        s_out[i] = tmp % 16;
                        tmp /= 16;
                    }
                    for(int i = 0; i < 4; ++i){
                        current_trail *= lat_s[s_in[i]][s_out[i]]/16.0;
                    }
                    current_trail *= 8;
                    current += current_trail;*/
                //}
            }
            //cout << current;
            if(abs(current) > abs(top_linear_hull)){
                top_linear_hull = current;
                in_mask = im;
                out_mask = om;
            }
        }
    }
    std::cout << dec << (double)top_linear_hull << '\n' << in_mask << '\n' << out_mask;
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    std::cout << '\n' << "Elapsed time: " << elapsed.count() << "s\n";
    
    // key-recovery
    /*
    unsigned char guessKey[40];
    bool is_success;
    
    for(int i = 0; i < 20; ++i){
        cout << '\n';
        for(int j = 0; j < 4; ++j){
            cout << hex << (int)(*guessKey + i)[j] << " ";
        }
    }
    int counter = 0;
    int numberOfTests = 100;
    for(int i = 0; i < numberOfTests; ++i){
        // generate random 20 * 4-bit key
        std::random_device rd;
        default_random_engine generator {rd()};
        uniform_int_distribution<unsigned char> dis(0,0xf);
        for(int j = 0; j < 20; ++j){
            Key[j] = dis(generator);
        }
        is_success = key_recovery(Key, guessKey, 0.5); // 400 CP pairs
        counter += is_success;
    }
    std::cout << "The success probability is: " << dec << (double)counter/numberOfTests << '\n';
    for(int i = 0; i < numberOfTests; ++i){
        // generate random 20 * 4-bit key
        std::random_device rd;
        default_random_engine generator {rd()};
        uniform_int_distribution<unsigned char> dis(0,0xf);
        for(int j = 0; j < 20; ++j){
            Key[j] = dis(generator);
        }
        is_success = key_recovery(Key, guessKey, 0.75); // 1600 CP pairs
        counter += is_success;
    }
    std::cout << "The success probability is: " << dec << (double)counter/numberOfTests << '\n';
    for(int i = 0; i < numberOfTests; ++i){
        // generate random 20 * 4-bit key
        std::random_device rd;
        default_random_engine generator {rd()};
        uniform_int_distribution<unsigned char> dis(0,0xf);
        for(int j = 0; j < 20; ++j){
            Key[j] = dis(generator);
        }
        is_success = key_recovery(Key, guessKey, 0.8); // 2500 CP pairs
        counter += is_success;
    }
    std::cout << "The success probability is: " << dec << (double)counter/numberOfTests << '\n';
    for(int i = 0; i < numberOfTests; ++i){
        // generate random 20 * 4-bit key
        std::random_device rd;
        default_random_engine generator {rd()};
        uniform_int_distribution<unsigned char> dis(0,0xf);
        for(int j = 0; j < 20; ++j){
            Key[j] = dis(generator);
        }
        is_success = key_recovery(Key, guessKey, 0.9); // 10000 CP pairs
        counter += is_success;
    }
    std::cout << "The success probability is: " << dec << (double)counter/numberOfTests << '\n';
    for(int i = 0; i < numberOfTests; ++i){
        // generate random 20 * 4-bit key
        std::random_device rd;
        default_random_engine generator {rd()};
        uniform_int_distribution<unsigned char> dis(0,0xf);
        for(int j = 0; j < 20; ++j){
            Key[j] = dis(generator);
        }
        is_success = key_recovery(Key, guessKey, 0.95); // 40000 CP pairs
        counter += is_success;
    }
    std::cout << "The success probability is: " << dec << (double)counter/numberOfTests << std::endl;
    */
    return 0;
}