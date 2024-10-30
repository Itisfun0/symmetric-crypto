/* "structures.h" defines the look-up tables
 * used in cipherD.cpp
 */
#ifndef STRUCTURES_H
#define STRUCTURES_H

// Encryption: CipherD S-box
unsigned char s[16] = {
    0xF, 0xE, 0xB, 0xC, 0x6, 0xD, 0x7, 0x8, 0x0, 0x3, 0x9, 0xA, 0x4, 0x2, 0x1, 0x5
};

// Envryption: CipherD bit-permutation
unsigned char p[16] = {
    0x0, 0x4, 0x8, 0xC, 0x1, 0x5, 0x9, 0xD, 0x2, 0x6, 0xA, 0xE, 0x3, 0x7, 0xB, 0xF
};

// Decryption: Inverse CipherD S-box
unsigned char inv_s[16] = {
    0x8, 0xE, 0xD, 0x9, 0xC, 0xF, 0x4, 0x6, 0x7, 0xA, 0xB, 0x2, 0x3, 0x5, 0x1, 0x0
};

// Decryption: Inverse CipherD bit-permutation
unsigned char inv_p[16] = {
    0x0, 0x4, 0x8, 0xC, 0x1, 0x5, 0x9, 0xD, 0x2, 0x6, 0xA, 0xE, 0x3, 0x7, 0xB, 0xF
};

// optimal 4-bit Sbox used in [PRESENT ches2007]
unsigned char opt_s[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

unsigned char inv_opt_s[16] = {
    0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa
};

// reference 4-bit Sbox
unsigned char ref_s[16] = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

// For LAT computation
int hamming_weight_mod_2(unsigned char x){
    int cnt = 0;
    while(x > 0){
        cnt += x % 2;
        x /= 2;
    }
    return cnt % 2;
}

// LAT[im][om]
int lat_s[16][16] = {
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -4, 0, -4, 0, 0, 0, 0, 0, -4, 0, 4, 0, 0, 2, 2, -2, -2, 0, 0, 2, -2, 0, 4, 0, 4, -2, 2, 0, 0, 2, 2, 2, -2, -4, 0, -2, 2, -4, 0, 0, 0, -2, -2, 0, 0, -2, 2, -2, -2, 0, 4, -2, -2, 0, -4, 0, 0, -2, 2, 0, 0, -2, 2, -2, 2, 0, 0, 2, 2, -4, 0, 4, 0, 2, 2, 0, 0, 0, -4, 0, 0, -4, 0, 0, -4, 0, 0, 4, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 0, 0, -4, 0, 0, 0, 0, 4, 0, 0, 0, 2, -2, 0, 0, -2, 2, -2, 2, 0, 0, -2, 2, 4, 4, 0, 4, -2, -2, 0, 0, 2, -2, -2, -2, -4, 0, -2, 2, 0, 0, 0, 0, 4, 0, 2, 2, 2, -2, 0, 0, 0, -4, 2, 2, -2, 2, 0, -4, 0, 0, -2, -2, 2, -2, -4, 0, 0, 0, 2, 2, 2, -2, 0, 0, 0, 0, -2, -2, -2, -2, 4, 0, 0, -4, -2, 2, 2, -2, 0, 4, 4, 0, -2, -2, 2, 2, 0, 0, 0, 0, 2, -2, 2, -2, 0, 0, 2, 2, -4, 4, -2, -2, -2, -2, 0, 0, -2, -2, 0, 0, 0, 4, -2, 2, 0, 0, -2, -2, -2, 2, 4, 0, 2, 2, 0, 0
};
#endif /* STRUCTURES_H */