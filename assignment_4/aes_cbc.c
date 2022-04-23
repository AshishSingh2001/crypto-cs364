/** @file 201951034.c
 *  @brief Code for CS364 lab Assignment 3
 *  Compression function using AES-128
 *  h(m1||m2) = AES-128(m1, m2)
 *  find the second pre image of the for the compression function h
 *  with the given m1 and m2
 *  @author Ashish Kumar Singh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char word8; // 8 bit
typedef unsigned int word32; // 32 bit

// swap elements
#define SWAP(a, b) \
    do             \
    {              \
        temp = a;  \
        a = b;     \
        b = temp;  \
    } while (0)

// get sbox value from array
#define getSBox(num) (sbox[(num)])

// get inv sbox value from array
#define getInvSBox(num) (inv_sbox[(num)])

/* Primitive polynomial x^8 + x^4 + x^3 + x + 1 for GF 8 used in AES */
const word8 min_poly = 0b11011;

// Variable to store the 44,   32 bit words
word32 w[60];

// Utility functions
void print_state(word8 arr[4][4]);
void my_gets(char *inp, int len);
word32 merge_word8(word8 arr[4]);
void matrixify(word8 arr[17], word8 state[4][4]);
void dematrixify(word8 state[4][4], word8 arr[17]);
void print_arr(word8 arr[17], int len);

// Galois Field Calculations
word8 mul(word8 a, word8 b);
word8 xf(word8 f);

// AES Helpers
void rotate_row(word8 *state, size_t shiftBy);
void inv_rotate_row(word8 *state, word8 shiftBy);

// Key expansion
void key_expansion(word8 key[16]);
word32 subword(word32 w);
word32 rotword(word32 w);
void get_key(int round, word8 key[4][4]);

// AES Encrypt
word8 *aes_cbc_encrypt(word8 *text, int msg_len, word8 key[33], word8 *Iv);
word8 *aes_encrypt(word8 text[17], word8 key[17]);
void add_round_key(word8 arr[4][4], int round);
void subbytes(word8 text[4][4]);
void shiftrows(word8 text[4][4]);
void mixcolumns(word8 arr[4][4]);

// AES Decrypt
word8 *aes_cbc_decrypt(word8 *text, int len, word8 key[33], word8 *Iv);
word8 *aes_decrypt(word8 cipher[17], word8 key[17]);
void inv_subbytes(word8 cipher_text[4][4]);
void inv_shiftrows(word8 cipher_text[4][4]);
void inv_mixcolumns(word8 arr[4][4]);

word8 sbox[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

word8 inv_sbox[256] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// Driver Code
int main()
{

#ifndef LIVE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif
    printf("INPUT expected to be a 16 letter string\n");
    // input m1
    const int ml = 16;
    // word8 plain_text[20] =
    //     {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22};
    word8 plain_text[65] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    // word8 plain_text[16 + 1] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    plain_text[32] = '\0';
    // printf("Enter m1 : ");
    // my_gets(plain_text, 18);
    printf("text : ");
    print_arr(plain_text, 32);

    // input m2
    // word8 plain_key[33] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    word8 plain_key[33] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x28, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    plain_text[32] = '\0';

    word8 iv[17] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    iv[16] = '\0';
    // printf("Enter m2 : ");
    // my_gets(plain_key, 33);
    printf("key  : ");
    print_arr(plain_key, 32);

    // Part 1 - Implement Compression function h(m1||m2) using AES-128
    word8 *cipher = aes_cbc_encrypt(plain_text, 32, plain_key, iv);
    // word8 *cipher = aes_encrypt(plain_text, plain_key);
    printf("cipher : ");
    print_arr(cipher, 32);
    word8 *text = aes_cbc_decrypt(cipher, 32, plain_key, iv);
    printf("text : ");
    print_arr(text, 32);
}

/*****************************************************************************/
/* Utility :                                                                 */
/*****************************************************************************/

/**
 * @brief wrapper for fgets
 * gets is deprecated so a wrapper for it using fgets
 * and some formatting for the out put string
 */
void my_gets(char *inp, int len)
{
    fgets(inp, len, stdin);
    inp[strcspn(inp, "\n")] = 0;
    printf("\n");
}

/**
 * @brief convert array of 16 word8 to a 4x4 matrix
 */
void matrixify(word8 arr[17], word8 state[4][4])
{
    for (int i = 0; i < 16; i++)
        state[i % 4][i / 4] = arr[i];
}

/**
 * @brief convert array of 4x4 2d array word8 to a 1d array of len 16
 */
void dematrixify(word8 state[4][4], word8 arr[17])
{
    for (int i = 0; i < 16; i++)
        arr[i] = state[i % 4][i / 4];
}

/**
 * @brief merge 4 word8 to a word32
 */
word32 merge_word8(word8 arr[4])
{
    word32 merged_word = 0;
    for (int i = 0; i < 4; i++)
    {
        merged_word <<= 8; /* redundant on first loop */
        merged_word |= arr[i];
    }
    return merged_word;
}

/**
 * @brief pretty print 4x4 2d array
 */
void print_state(word8 arr[4][4])
{
    for (size_t i = 0; i < 4; i++)
    {
        for (size_t j = 0; j < 4; j++)
        {
            printf("%02X ", arr[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

/**
 * @brief pretty print 1d array of len 16
 */
void print_arr(word8 *arr, int len)
{
    // printf("CHAR : %s\n", arr);
    printf("0x");
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", arr[i]);
    }
    printf("\n\n");
}

/*****************************************************************************/
/* Galois Field Calculations                                                 */
/*****************************************************************************/

/**
 * @brief Mulitply by x in GF 8
 */
word8 xf(word8 f)
{
    return (f >> 7 == 0) ? (f << 1) : (f << 1) ^ min_poly;
}

/**
 * @brief Galois Field 8 multiplication
 */
word8 mul(word8 a, word8 b)
{
    word8 res = 0;
    for (; b; b >>= 1)
    {
        if (b & 1)
            res ^= a;
        a = xf(a);
    }
    return res;
}

/*****************************************************************************/
/* AES Helpers :                                                             */
/*****************************************************************************/

/**
 * @brief rotate row to the right by mentioned offset
 */
void inv_rotate_row(word8 *state, word8 shiftBy)
{
    int i, j;
    word8 tmp;
    /* each iteration shifts the row to the right by 1 */
    for (i = 0; i < shiftBy; i++)
    {
        tmp = state[3];
        for (j = 3; j > 0; j--)
            state[j] = state[j - 1];
        state[0] = tmp;
    }
}

/**
 * @brief rotate row to the left by mentioned offset
 */
void rotate_row(word8 *state, size_t shiftBy)
{
    int i, j;
    word8 tmp;
    /* each iteration shifts the row to the left by 1 */
    for (i = 0; i < shiftBy; i++)
    {
        tmp = state[0];
        for (j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}

/**
 * @brief xor with IV
 */
void xor_iv(word8 text[17], word8 iv[17])
{
    for (size_t i = 0; i < 16; i++)
    {
        text[i] ^= iv[i];
    }
}

/*****************************************************************************/
/* Key Expansion :                                                           */
/******************************************************************************/

/**
 * @brief expand the 128 bit key to 44 32 bit words which will
 * be further concatenated to generate 11 keys
 */
void key_expansion(word8 key[32])
{
    word32 Rcon[11] = {
        0x12000000,
        0x01000000,
        0x02000000,
        0x04000000,
        0x08000000,
        0x10000000,
        0x20000000,
        0x40000000,
        0x80000000,
        0x1b000000,
        0x36000000,
    };

    for (size_t i = 0; i < 8; i++)
    {
        word8 arr[4] = {
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3],
        };
        w[i] = merge_word8(arr);
    }
    for (size_t i = 8; i < 4 * (14 + 1); i++)
    {
        word32 temp = w[i - 1];
        if (i % 8 == 0)
        {
            temp = subword(rotword(temp));
            temp ^= Rcon[(i / 8)];
        }
        if (i % 8 == 4)
        {
            temp = subword(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }
}

/**
 * @brief apply subbytes function on each byte
 */
word32 subword(word32 w)
{
    word8 sub[4];
    // printf("%032b\n", w);
    for (size_t i = 0; i < 4; i++)
    {
        word8 temp = (w >> (3 - i) * 8);
        // printf("%08b\n", temp);
        // printf("%02x\n", temp);
        sub[i] = getSBox(temp);
        // printf("%02x\n", sub[i]);
    }
    return merge_word8(sub);
}

/**
 * @brief rotate word one byte left
 */
word32 rotword(word32 w)
{
    return (w << 8) | (w >> (32 - 8));
}

/**
 * @brief Get the key fromt he global array w of word32
 */
void get_key(int round, word8 key[4][4])
{
    for (size_t i = 0; i < 4; i++)
    {
        word32 t = w[(round * 4) + i];
        for (size_t j = 0; j < 4; j++)
        {
            word8 temp = (t >> (3 - j) * 8);
            key[j][i] = temp;
        }
    }
}

/*****************************************************************************/
/* AES Encryption :                                                          */
/*****************************************************************************/

word8 *aes_cbc_encrypt(word8 *text, int len, word8 key[33], word8 *Iv)
{
    key_expansion(key);
    word8 *iv = Iv;
    int chunks = len / 16;
    word8 *enc = malloc(len * sizeof(word8));
    word8 *buf = malloc(len*sizeof(word8));
    memcpy(buf, text, len);
    for (int i = 0; i < chunks; i++)
    {
        xor_iv(buf, iv);
        iv = aes_encrypt(buf, key);
        memcpy(enc + i * 16, iv, 16);
        buf += 16;
    }
    free(buf);
    return enc;
}

/**
 * @brief function that implements the compression function with AES-128
 */
word8 *aes_encrypt(word8 text[17], word8 key[33])
{
    key_expansion(key);
    word8 text_state[4][4], key_state[4][4];
    matrixify(text, text_state);
    matrixify(key, key_state);
    size_t round = 0;
    while (round <= 14)
    {
        if (round != 0)
        {
            subbytes(text_state);
            shiftrows(text_state);
            if (round != 14)
                mixcolumns(text_state);
        }
        add_round_key(text_state, round);
        // printf("After round %lu\n", round);
        // print_state(text_state);
        round++;
    }
    word8 *cipher = malloc(17 * sizeof(word8));
    dematrixify(text_state, cipher);
    return cipher;
}

/**
 * @brief add round key to the matrix
 */
void add_round_key(word8 arr[4][4], int round)
{
    word8 key[4][4];
    // printf("key %d :\n", round);
    get_key(round, key);
    // print_state(key);
    for (size_t i = 0; i < 4; i++)
    {
        for (size_t j = 0; j < 4; j++)
        {
            arr[i][j] ^= key[i][j];
        }
    }
}

/**
 * @brief calculate subbytes for each byte of the array
 */
void subbytes(word8 text[4][4])
{
    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t j = 0; j < 4; ++j)
        {
            text[j][i] = getSBox(text[j][i]);
        }
    }
}

/**
 * @brief shiftrow left by 0 1 2 3 respectively
 */
void shiftrows(word8 text[4][4])
{
    size_t i;
    for (i = 0; i < 4; i++)
        rotate_row(text[i], i);
}

/**
 * @brief implement mixcolumn on the matrix
 */
void mixcolumns(word8 arr[4][4])
{
    for (size_t i = 0; i < 4; i++)
    {
        word8 a = arr[0][i];
        word8 b = arr[1][i];
        word8 c = arr[2][i];
        word8 d = arr[3][i];
        arr[0][i] = xf(a) ^ xf(b) ^ b ^ c ^ d;
        arr[1][i] = xf(b) ^ xf(c) ^ c ^ d ^ a;
        arr[2][i] = xf(c) ^ xf(d) ^ d ^ a ^ b;
        arr[3][i] = xf(d) ^ xf(a) ^ a ^ b ^ c;
    }
}

/*****************************************************************************/
/* AES Decryption :                                                          */
/*****************************************************************************/

word8 *aes_cbc_decrypt(word8 *text, int len, word8 key[33], word8 *Iv)
{
    key_expansion(key);
    word8 *iv = Iv;
    int chunks = len / 16;
    word8 *dec = malloc(len * sizeof(word8));
    word8 *buf = text;
    for (int i = 0; i < chunks; i++)
    {
        word8 *temp = aes_decrypt(buf, key);
        xor_iv(temp, iv);
        iv = buf;
        memcpy(dec + i * 16, temp, 16);
        buf += 16;
    }
    return dec;
}

/**
 * @brief function that implents the decryption of the AES-128
 */
word8 *aes_decrypt(word8 cipher[17], word8 key[17])
{
    key_expansion(key);
    word8 cipher_state[4][4], key_state[4][4];
    matrixify(cipher, cipher_state);
    matrixify(key, key_state);
    int round = 14;
    while (round >= 0)
    {
        add_round_key(cipher_state, round);
        if (round != 0)
        {
            if (round != 14)
                inv_mixcolumns(cipher_state);
            inv_shiftrows(cipher_state);
            inv_subbytes(cipher_state);
        }
        // printf("After round %d\n", round);
        // print_state(cipher_text);
        round--;
    }
    word8 *text = malloc(17 * sizeof(word8));
    dematrixify(cipher_state, text);
    return text;
}

/**
 * @brief calculate subbytes inverse for each byte of the array
 */
void inv_subbytes(word8 cipher_text[4][4])
{
    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t j = 0; j < 4; ++j)
        {
            cipher_text[j][i] = getInvSBox(cipher_text[j][i]);
        }
    }
}

/**
 * @brief shiftrow right by 0 1 2 3 respectively
 */
void inv_shiftrows(word8 cipher_text[4][4])
{
    int i;
    /* iterate over the 4 rows and call rotate_row() with that row */
    for (i = 0; i < 4; i++)
        inv_rotate_row(cipher_text[i], i);
}

/**
 * @brief implements inverse of the aes mixcolumn
 */
void inv_mixcolumns(word8 arr[4][4])
{
    for (size_t i = 0; i < 4; i++)
    {
        word8 a = arr[0][i];
        word8 b = arr[1][i];
        word8 c = arr[2][i];
        word8 d = arr[3][i];
        arr[0][i] = mul(a, 0x0e) ^ mul(b, 0x0b) ^ mul(c, 0x0d) ^ mul(d, 0x09);
        arr[1][i] = mul(a, 0x09) ^ mul(b, 0x0e) ^ mul(c, 0x0b) ^ mul(d, 0x0d);
        arr[2][i] = mul(a, 0x0d) ^ mul(b, 0x09) ^ mul(c, 0x0e) ^ mul(d, 0x0b);
        arr[3][i] = mul(a, 0x0b) ^ mul(b, 0x0d) ^ mul(c, 0x09) ^ mul(d, 0x0e);
    }
}
