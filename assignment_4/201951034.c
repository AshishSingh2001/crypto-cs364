/** @file 201951034.c
 *  @brief Code for Crypto lab Assignment 4
 *  @author Ashish Kumar Singh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

typedef unsigned char word8;       // 8 bit
typedef unsigned int word32;       // 32 bit
typedef unsigned long long word64; // 64 bit

// Elliptic Curve Constants for y^2 = x^3 + 25x + 31 mod 101

int M = 101;
int coeff_a = 25;
int coeff_b = 31;
word8 theta[2] = {0, 0};

// Store generated words for AES

word32 w[60];

// SHA Constants and Macros

const word32 k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define DEC(x) (x - 1)
#define S(len) ((len + 1 + 8 + DEC(64)) & ~DEC(64))
#define SHA256_CHUNK_COUNT(len) (S(len) / 64)

// AES 256 CBC constants and macros

/* Primitive polynomial x^8 + x^4 + x^3 + x + 1 for GF 8 used in AES */
const word8 min_poly = 0b11011;

const word8 sbox[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

const word8 inv_sbox[256] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// get sbox value from array
#define getSBox(num) (sbox[(num)])

// get inv sbox value from array
#define getInvSBox(num) (inv_sbox[(num)])

// Common Utility

#define getName(var) #var
int mult_inv(int a);
int add_inv(int x);
void my_gets(char *inp, int len);
word32 merge_word8(word8 arr[4]);
void add_word32_array(word32 *dst, const word32 *src, size_t len);
word8 *split_word32(word32 x);
void print_word32(word32 *a, int len);
void print_word8(word8 *a, int len);
void print_state(word8 arr[4][4]);
void matrixify(word8 arr[17], word8 state[4][4]);
void dematrixify(word8 state[4][4], word8 arr[17]);
void print_arr(word8 arr[17], int len);
bool compare_string(word8 *desc, word8 *a, word8 *b);

// ECDH Helpers

word8 print_point(char *s, word8 arr[2]);
bool is_in_E(word8 x, word8 y);
bool is_theta(word8 a[2]);
word8 *add(word8 x[2], word8 y[2]);

// ECDH Functions

word8 *get_random_point_on_el();
word8 *nadd(word8 x[2], word8 n);
word8 when_theta(word8 a[2]);

// SHA 256 Helper

word32 rotl(word32 a, word32 b);
word32 rotr(word32 a, word32 b);
word32 ch(word32 x, word32 y, word32 z);
word32 maj(word32 x, word32 y, word32 z);
word32 big_sig0(word32 x);
word32 big_sig1(word32 x);
word32 sig0(word32 x);
word32 sig1(word32 x);
word8 *sha_pad(word8 *s, int chunks);
word8 *format(word8 *raw);

// SHA 256 functions

word8 *sha(word8 *raw);

// AES 256 CBC Helpers

word8 mul(word8 a, word8 b);
word8 xf(word8 f);
void rotate_row(word8 *state, size_t shiftBy);
void inv_rotate_row(word8 *state, word8 shiftBy);
void key_expansion(word8 key[16]);
word32 subword(word32 w);
word32 rotword(word32 w);
void get_key(int round, word8 key[4][4]);

// AES 256 CBC Mode Functions

word8 *aes_cbc_encrypt(word8 *text, int msg_len, word8 key[33], word8 *Iv);
word8 *aes_encrypt(word8 text[17], word8 key[17]);
void add_round_key(word8 arr[4][4], int round);
void subbytes(word8 text[4][4]);
void shiftrows(word8 text[4][4]);
void mixcolumns(word8 arr[4][4]);
word8 *aes_cbc_decrypt(word8 *text, int len, word8 key[33], word8 *Iv);
word8 *aes_decrypt(word8 cipher[17], word8 key[17]);
void inv_subbytes(word8 cipher_text[4][4]);
void inv_shiftrows(word8 cipher_text[4][4]);
void inv_mixcolumns(word8 arr[4][4]);

int main()
{
#ifdef LIVE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif

    // Step 1
    printf("Curve EL: y^2 = x^3 + 25x + 31 over P=101\n");

    // Step 2,3
    word8 *alpha = get_random_point_on_el();
    print_point("point α", alpha);

    // Step 4
    int na;
    printf("Enter Alice's Private Key na [0,100] : ");
    scanf("%d", &na);
    printf("%d\n", na);

    int nb;
    printf("Enter Bob's Private Key nb [0,100] : ");
    scanf("%d", &nb);
    printf("%d\n", nb);

    // Step 5 - shared secret key = na*nb*alpha
    printf("\nExchanging na*α and nb*α\n\ngenerating secret key na*nb*α\n");
    word8 *shared_key = nadd(alpha, na * nb);
    print_point("SK = (x1 , y1)", shared_key);

    // Step 6
    word8 *ka = sha(shared_key);

    // Step 7
    word8 *kb = sha(shared_key);

    // Step 8
    printf("\nka : ");
    print_word8(ka, 32);
    printf("kb : ");
    print_word8(kb, 32);

    // Step 9
    printf("Enter ma : ");
    scanf("\n");
    int len_ma = 32; // length of space separted 32 bits
    word8 *ma = malloc((len_ma * 3 + 1) * sizeof(word8));
    my_gets(ma, len_ma * 3 + 1);
    ma = format(ma);

    // Step 10
    word8 *iv = calloc(16 * sizeof(word8), 0x00);
    word8 *ca = aes_cbc_encrypt(ma, 32, ka, iv);
    
    // Step 11
    word8 *maca = malloc(96 * sizeof(word8));
    memcpy(maca, ka, 32);
    maca[31] ^= 1;

    word8 *ka2 = malloc(32 * sizeof(word8));
    memcpy(ka2, ka, 32);
    ka2[31] ^= 2;
    word8 *sha_ka2 = sha(ka2);

    memcpy(maca + 32, sha_ka2, 32);
    memcpy(maca + 64, ma, 32);

    maca = sha(maca);

    // Step 12
    printf("Ca : ");
    print_word8(ca, 32);

    printf("MACa : ");
    print_word8(maca, 32);

    // Step 13
    printf("Exchanging variables Ca , MACa and IV alice -> bob\n\n");

    // Step 14
    word8 *mb = aes_cbc_decrypt(ca, 32, kb, iv);

    // Step 15
    word8 *macb = malloc(96 * sizeof(word8));
    memcpy(macb, kb, 32);
    macb[31] ^= 1;

    word8 *kb2 = malloc(32 * sizeof(word8));
    memcpy(kb2, kb, 32);
    kb2[31] ^= 2;
    word8 *sha_kb2 = sha(kb2);

    memcpy(macb + 32, sha_kb2, 32);
    memcpy(macb + 64, mb, 32);

    macb = sha(macb);

    // Step 16
    printf("Mb : ");
    print_word8(mb, 32);

    printf("MACb : ");
    print_word8(macb, 32);

    printf("comparing mac, cipher text and plain text : \n");
    compare_string("MAC", maca, macb);
    compare_string("M", ma, mb);
    compare_string("K", ka, kb);
}

/*****************************************************************************/
/* Shared Utility :                                                          */
/*****************************************************************************/

/**
 * @brief additive inverse under MOD M for Elliptic Curve
 */
int add_inv(int x)
{
    return M - x;
}

/**
 * @brief Multiplicative inverse under MOD M for Elliptic Curve
 */
int mult_inv(int a)
{
    for (int x = 1; x < M; x++)
        if (((a % M) * (x % M)) % M == 1)
            return x;
}

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
 * @brief split a 32 bit word into array of size of 4 word8
 */
word8 *split_word32(word32 x)
{
    word8 *w = calloc(0, 4 * sizeof(word8));
    for (size_t i = 0; i < 4; i++)
    {
        w[i] |= (x >> (3 - i) * 8);
    }
    return w;
}

/**
 * @brief add two 32 word arrays
 */
void add_word32_array(word32 *dst, const word32 *src, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        dst[i] += src[i];
    }
}

/**
 * @brief print word8 array in hex
 */
void print_word8(word8 *a, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X ", a[i]);
    }
    printf("\n\n");
}

/**
 * @brief print word32 array in hex
 */
void print_word32(word32 *a, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%08X ", a[i]);
    }
    printf("\n");
}

/**
 * @brief merge 4 word8 into a word32
 */
word32 merge_word8(word8 *arr)
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

/**
 * @brief compare string and print the result
 */
bool compare_string(word8 *desc, word8 *a, word8 *b)
{
    if (memcmp(a, b, 32) == 0)
    {
        printf("%3sa == %2sb\n", desc, desc);
    }
    else
    {
        printf("%3sa != %2sb\n", desc, desc);
    }
}

/*****************************************************************************/
/* ECDH Helpers :                                                            */
/*****************************************************************************/

/**
 * @brief print a point formatted
 */
word8 print_point(char *s, word8 arr[2])
{
    printf("%s : (%d, %d)\n", s, arr[0], arr[1]);
}

/**
 * @brief check if a point is in a elliptic curve
 */
bool is_in_E(word8 x, word8 y)
{
    word8 lhs = ((x * x * x) + coeff_a * x + coeff_b) % M;
    word8 rhs = (y * y) % M;
    return (lhs == rhs);
}

/**
 * @brief check if the point is theta
 */
bool is_theta(word8 a[2])
{
    if (theta[0] == a[0] && theta[1] == a[1])
    {
        return true;
    }
    else
    {
        return false;
    }
}

/**
 * @brief add two points in a elliptic curve
 */
word8 *add(word8 a[2], word8 b[2])
{
    word8 *ans = malloc(2 * sizeof(word8));
    word8 m = 0;

    // Theta conditions

    if (is_theta(a))
    {
        return b;
    }
    if (is_theta(b))
    {
        return a;
    }
    if (a[0] == b[0] && a[1] == add_inv(b[1]))
    {
        return theta;
    }

    // Return condition
    if (a[0] != b[0] && a[1] != b[1])
    {
        m = ((b[1] + add_inv(a[1])) * mult_inv(b[0] + add_inv(a[0]))) % M;
    }
    else if (a[0] == b[0] && a[1] == b[1])
    {
        m = ((3 * a[0] * a[0] + coeff_a) * mult_inv(2 * a[1])) % M;
    }
    ans[0] = ((m * m) + add_inv(a[0]) + add_inv(b[0])) % M;
    ans[1] = ((m * (ans[0] + add_inv(a[0]))) + a[1]) % M;
    ans[1] = add_inv(ans[1]);
    return ans;
}

/*****************************************************************************/
/* ECDH Functions :                                                         */
/*****************************************************************************/

/**
 * @brief when does a point converge to theta
 */
word8 when_theta(word8 a[2])
{
    word8 ctr = 1;
    word8 *ans = a;
    while (!is_theta(ans))
    {
        ans = add(ans, a);
        // printf("(%2d, %2d)\n", ans[0], ans[1]);
        ctr++;
    }
    return ctr;
}

/**
 * @brief add a point to itself n times
 */
word8 *nadd(word8 x[2], word8 n)
{
    if (n == 1)
        return x;
    word8 *ans = x;
    for (size_t i = 0; i < n - 1; i++)
    {
        ans = add(ans, x);
    }
    return ans;
}

/**
 * @brief Get a random point on Elliptic Curve
 */
word8 *get_random_point_on_el()
{
    time_t t;
    srand((unsigned)time(&t));
    // there are total 91 number of points in the curve mod 101
    int random_number = rand() % 91;
    int ctr = 0;
    for (int x = 0; x < M; x++)
    {
        for (int y = 0; y < M; y++)
        {
            int a = ((x * x * x) + coeff_a * x + coeff_b) % M;
            int b = (y * y) % M;
            if (a == b)
            {
                if (ctr == random_number)
                {
                    word8 *arr = malloc(2 * sizeof(int));
                    arr[0] = x;
                    arr[1] = y;
                    return arr;
                }
                ctr++;
                // printf("(%d, %d) \n", x, y);
            }
        }
    }
}

/*****************************************************************************/
/* SHA 256 Helpers:                                                           */
/*****************************************************************************/

/**
 * @brief rotate a word to left
 */
word32 rotl(word32 a, word32 b)
{
    return (((a) << (b)) | ((a) >> (32 - (b))));
}

/**
 * @brief rotate a word to right
 */
word32 rotr(word32 a, word32 b)
{
    return ((a >> b) | (a << (32 - b)));
}

/**
 * @brief Ch(X, Y, Z) = (X ∧ Y ) ⊕ (~X ∧ Z),
 */
word32 ch(word32 x, word32 y, word32 z)
{
    return (x & y) ^ (~x & z);
}

/**
 * @brief Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
 */
word32 maj(word32 x, word32 y, word32 z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/**
 * @brief Σ0(X) = RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22)
 */
word32 big_sig0(word32 x)
{
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

/**
 * @brief Σ1(X) = RotR(X, 6) ⊕ RotR(X, 11) ⊕ RotR(X, 25)
 */
word32 big_sig1(word32 x)
{
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

/**
 * @brief σ0(X) = RotR(X, 7) ⊕ RotR(X, 18) ⊕ ShR(X, 3)
 */
word32 sig0(word32 x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

/**
 * @brief σ1(X) = RotR(X, 17) ⊕ RotR(X, 19) ⊕ ShR(X, 10)
 */
word32 sig1(word32 x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

/**
 * @brief pad the string for SHA 256
 */
word8 *sha_pad(word8 *s, int chunks)
{
    word8 *a = malloc(chunks * 64 * sizeof(word8));
    word64 len = strlen(s) * 8;
    int ctr = strlen(s);
    memcpy(a, s, ctr);
    a[ctr++] = 0b10000000;
    while (ctr < chunks * 64 - 8)
    {
        a[ctr++] = 0;
    }
    for (size_t i = ctr + 7; i >= ctr; i--)
    {
        word8 x = 0;
        x = x | len;
        a[i] = x;
        len >>= 8;
    }
    return a;
}

/**
 * @brief format a hex string with spaces
 * @return word8* char array
 */
word8 *format(word8 *raw)
{
    word8 *a = malloc(strlen(raw) * sizeof(word8));
    int ctr = 0;
    int l, r;
    for (int i = 0; i < strlen(raw); i += 3)
    {
        if (i % 3 == 0)
        {
            word8 ch[2];
            strncpy(ch, &raw[i], 2);
            a[ctr++] = strtol(ch, NULL, 16);
        }
    }
    a[ctr] = '\0';
    return a;
}

/*****************************************************************************/
/* SHA 256 :                                                                 */
/*****************************************************************************/

/**
 * @brief hash a raw string using SHA256
 */
word8 *sha(word8 *raw)
{
    // word8 *fmt = format(raw);
    word8 *fmt = raw;
    // print_word8(raw, 2);
    int chunks = SHA256_CHUNK_COUNT(strlen(fmt));
    word8 *pad = sha_pad(fmt, chunks);
    word8 **blocks = malloc(chunks * sizeof(int *));
    for (size_t i = 0; i < chunks; i++)
    {
        blocks[i] = malloc(64 * sizeof(word8));
        memcpy(blocks[i], pad + i * 64, 64);
    }

    word32 h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    for (size_t b = 0; b < chunks; b++)
    {
        word8 *m = blocks[b];
        word32 *w = malloc(64 * sizeof(word32));
        for (size_t i = 0; i < 16; i++)
        {
            w[i] = merge_word8(m + i * 4);
        }
        for (size_t i = 16; i < 64; i++)
        {
            w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];
        }

        // internal copy of h
        word32 *_h = malloc(8 * sizeof(word32));
        memcpy(_h, h, 32);
        for (size_t i = 0; i < 64; i++)
        {
            word32 t1 = _h[7] + big_sig1(_h[4]) + ch(_h[4], _h[5], _h[6]) + k[i] + w[i];
            word32 t2 = big_sig0(_h[0]) + maj(_h[0], _h[1], _h[2]);
            _h[7] = _h[6];
            _h[6] = _h[5];
            _h[5] = _h[4];
            _h[4] = _h[3] + t1;
            _h[3] = _h[2];
            _h[2] = _h[1];
            _h[1] = _h[0];
            _h[0] = t1 + t2;
        }
        add_word32_array(h, _h, 8);
    }

    word8 *hash = malloc(32 * sizeof(32));
    for (size_t i = 0; i < 8; i++)
    {
        memcpy(hash + i * 4, split_word32(h[i]), 4);
    }
    return hash;
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

/**
 * @brief AES CBC encrypt
 */
word8 *aes_cbc_encrypt(word8 *text, int len, word8 key[33], word8 *Iv)
{
    key_expansion(key);
    word8 *iv = Iv;
    int chunks = len / 16;
    word8 *enc = malloc(len * sizeof(word8));
    word8 *buf = malloc(len * sizeof(word8));
    memcpy(buf, text, len);
    for (int i = 0; i < chunks; i++)
    {
        xor_iv(buf, iv);
        iv = aes_encrypt(buf, key);
        memcpy(enc + i * 16, iv, 16);
        buf += 16;
    }
    // free(buf);
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

/**
 * @brief AES CBC decrypt
 */
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
