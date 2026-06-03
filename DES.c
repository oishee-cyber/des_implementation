#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ROUNDS 16

/* Initial Permutation Table */
int IP[64] = {
58,50,42,34,26,18,10,2,
60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6,
64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,
59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,
63,55,47,39,31,23,15,7
};

/* Final Permutation Table */
int FP[64] = {
40,8,48,16,56,24,64,32,
39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,
35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,
33,1,41,9,49,17,57,25
};

/* Expansion Table */
int E[48] = {
32,1,2,3,4,5,
4,5,6,7,8,9,
8,9,10,11,12,13,
12,13,14,15,16,17,
16,17,18,19,20,21,
20,21,22,23,24,25,
24,25,26,27,28,29,
28,29,30,31,32,1
};

/* Permutation P */
int P[32] = {
16,7,20,21,
29,12,28,17,
1,15,23,26,
5,18,31,10,
2,8,24,14,
32,27,3,9,
19,13,30,6,
22,11,4,25
};

/* PC-1 */
int PC1[56] = {
57,49,41,33,25,17,9,
1,58,50,42,34,26,18,
10,2,59,51,43,35,27,
19,11,3,60,52,44,36,
63,55,47,39,31,23,15,
7,62,54,46,38,30,22,
14,6,61,53,45,37,29,
21,13,5,28,20,12,4
};

/* PC-2 */
int PC2[48] = {
14,17,11,24,1,5,
3,28,15,6,21,10,
23,19,12,4,26,8,
16,7,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32
};

/* Left Shifts */
int SHIFTS[16] = {
1,1,2,2,
2,2,2,2,
1,2,2,2,
2,2,2,1
};

/* Round Keys */
int roundKeys[16][48];

/* Function Prototypes */
void stringToBits(char *str, int bits[]);
void bitsToString(int bits[], char str[]);
void permute(int input[], int output[], int table[], int n);
void leftShift(int key[], int shifts, int size);
void generateKeys(int keyBits[]);
void xorBits(int a[], int b[], int result[], int n);
void feistel(int right[], int key[], int output[]);
void encryptBlock(int plainBits[], int cipherBits[]);
void decryptBlock(int cipherBits[], int plainBits[]);

/* ================= S-BOXES ================= */

int S[8][4][16] = {

{
{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
},

{
{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
},

{
{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
},

{
{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
},

{
{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
},

{
{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
},

{
{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
},

{
{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
}

};

/* ============ STRING TO BITS ============ */

void stringToBits(char *str, int bits[])
{
    int i, j;

    for(i = 0; i < 8; i++)
    {
        unsigned char ch = str[i];

        for(j = 0; j < 8; j++)
        {
            bits[i * 8 + j] = (ch >> (7 - j)) & 1;
        }
    }
}

/* ============ BITS TO STRING ============ */

void bitsToString(int bits[], char str[])
{
    int i, j;

    for(i = 0; i < 8; i++)
    {
        char ch = 0;

        for(j = 0; j < 8; j++)
        {
            ch = (ch << 1) | bits[i * 8 + j];
        }

        str[i] = ch;
    }

    str[8] = '\0';
}

/* ============ PERMUTATION ============ */

void permute(int input[], int output[], int table[], int n)
{
    int i;

    for(i = 0; i < n; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

/* ============ XOR ============ */

void xorBits(int a[], int b[], int result[], int n)
{
    int i;

    for(i = 0; i < n; i++)
    {
        result[i] = a[i] ^ b[i];
    }
}

/* ============ LEFT SHIFT ============ */

void leftShift(int key[], int shifts, int size)
{
    while(shifts--)
    {
        int first = key[0];

        for(int i = 0; i < size - 1; i++)
            key[i] = key[i + 1];

        key[size - 1] = first;
    }
}

/* ============ KEY GENERATION ============ */

void generateKeys(int keyBits[])
{
    int permuted[56];
    int C[28], D[28];
    int CD[56];

    permute(keyBits, permuted, PC1, 56);

    for(int i = 0; i < 28; i++)
    {
        C[i] = permuted[i];
        D[i] = permuted[i + 28];
    }

    for(int round = 0; round < 16; round++)
    {
        leftShift(C, SHIFTS[round], 28);
        leftShift(D, SHIFTS[round], 28);

        for(int i = 0; i < 28; i++)
        {
            CD[i] = C[i];
            CD[i + 28] = D[i];
        }

        permute(CD, roundKeys[round], PC2, 48);
    }
}

/* ============ FEISTEL FUNCTION ============ */

void feistel(int right[], int key[], int output[])
{
    int expanded[48];
    int xored[48];
    int row, col;
    int sboxOut[32];
    int temp[32];

    /* Expansion from 32 to 48 bits */
    permute(right, expanded, E, 48);

    /* XOR with round key */
    xorBits(expanded, key, xored, 48);

    /* S-box substitution (48 -> 32) */
    for(int i = 0; i < 8; i++)
    {
        row = (xored[i*6] << 1) + xored[i*6 + 5];
        col = (xored[i*6 + 1] << 3) +
              (xored[i*6 + 2] << 2) +
              (xored[i*6 + 3] << 1) +
              xored[i*6 + 4];

        int val = S[i][row][col];

        sboxOut[i*4 + 0] = (val >> 3) & 1;
        sboxOut[i*4 + 1] = (val >> 2) & 1;
        sboxOut[i*4 + 2] = (val >> 1) & 1;
        sboxOut[i*4 + 3] = val & 1;
    }

    /* Permutation P */
    permute(sboxOut, output, P, 32);
}

/* ============ DES ENCRYPT BLOCK ============ */

void encryptBlock(int plainBits[], int cipherBits[])
{
    int perm[64];
    int L[32], R[32], newR[32];

    /* Initial Permutation */
    permute(plainBits, perm, IP, 64);

    for(int i = 0; i < 32; i++)
    {
        L[i] = perm[i];
        R[i] = perm[i + 32];
    }

    /* 16 Rounds */
    for(int round = 0; round < 16; round++)
    {
        int temp[32];

        feistel(R, roundKeys[round], temp);

        for(int i = 0; i < 32; i++)
        {
            newR[i] = L[i] ^ temp[i];
        }

        for(int i = 0; i < 32; i++)
        {
            L[i] = R[i];
            R[i] = newR[i];
        }
    }

    /* Final swap */
    int preoutput[64];
    for(int i = 0; i < 32; i++)
    {
        preoutput[i] = R[i];
        preoutput[i + 32] = L[i];
    }

    /* Final Permutation */
    permute(preoutput, cipherBits, FP, 64);
}

/* ============ DES DECRYPT BLOCK ============ */

void decryptBlock(int cipherBits[], int plainBits[])
{
    int perm[64];
    int L[32], R[32], newR[32];

    permute(cipherBits, perm, IP, 64);

    for(int i = 0; i < 32; i++)
    {
        L[i] = perm[i];
        R[i] = perm[i + 32];
    }

    /* Reverse rounds */
    for(int round = 15; round >= 0; round--)
    {
        int temp[32];

        feistel(R, roundKeys[round], temp);

        for(int i = 0; i < 32; i++)
        {
            newR[i] = L[i] ^ temp[i];
        }

        for(int i = 0; i < 32; i++)
        {
            L[i] = R[i];
            R[i] = newR[i];
        }
    }

    int preoutput[64];
    for(int i = 0; i < 32; i++)
    {
        preoutput[i] = R[i];
        preoutput[i + 32] = L[i];
    }

    permute(preoutput, plainBits, FP, 64);
}

int main()
{
    char plaintext[9], key[9];
    int plainBits[64], cipherBits[64], decryptedBits[64];
    int keyBits[64];

    printf("===== SIMPLE DES IMPLEMENTATION =====\n");

printf("Enter 8-character plaintext: ");
scanf("%8s", plaintext);

printf("Enter 8-character key: ");
scanf("%8s", key);

    /* remove newline if present */
    plaintext[strcspn(plaintext, "\n")] = 0;
    key[strcspn(key, "\n")] = 0;

    if(strlen(plaintext) < 8 || strlen(key) < 8)
    {
        printf("Error: Input must be at least 8 characters.\n");
        return 1;
    }

    /* Take only first 8 characters */
    plaintext[8] = '\0';
    key[8] = '\0';

    /* Convert to bit arrays */
    stringToBits(plaintext, plainBits);
    stringToBits(key, keyBits);

    /* Generate 16 round keys */
    generateKeys(keyBits);

    /* Encrypt */
    encryptBlock(plainBits, cipherBits);

    /* Decrypt */
    decryptBlock(cipherBits, decryptedBits);

    char cipherText[9], decryptedText[9];

    bitsToString(cipherBits, cipherText);
    bitsToString(decryptedBits, decryptedText);

    printf("\n===== OUTPUT =====\n");
    printf("Plaintext  : %s\n", plaintext);

    printf("Ciphertext (hex): ");
    for(int i = 0; i < 8; i++)
        printf("%02X", (unsigned char)cipherText[i]);

    printf("\nDecrypted  : %s\n", decryptedText);

    printf("\n===== DONE =====\n");

    return 0;
}
