/**
 * @file sha.c
 * @author Ashish Kumar Singh
 * @brief SHA-256
 *
 * input
 *  61 62 63 64 62 63 64 65 63 64 65 66 64 65 66 67 65 66 67 68 66 67 68 69 67 68 69 6a 68 69 6a 6b 69 6a 6b 6c 6a 6b 6c 6d 6b 6c 6d 6e 6c 6d 6e 6f 6d 6e 6f 70 6e 6f 70 71
 * output
 * 24 8D 6A 61 D2 06 38 B8 E5 C0 26 93 0C 3E 60 39 A3 3C E4 59 64 FF 21 67 F6 EC ED D4 19 DB 06 C1
 *
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

// SHA 256 Helper functions

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

// SHA main functions

word8 *sha(word8 *raw);

// utility
void my_gets(char *inp, int len);
word32 merge_word8(word8 arr[4]);
void add_word32_array(word32 *dst, const word32 *src, size_t len);
word8 *split_word32(word32 x);
void print_word32(word32 *a, int len);
void print_word8(word8 *a, int len);

const word32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define DEC(x) (x - 1)
#define S(len) ((len + 1 + 8 + DEC(64)) & ~DEC(64))
#define SHA256_CHUNK_COUNT(len) (S(len) / 64)

int main()
{
#ifndef LIVE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif
    int len = 5;
    word8 plain_text[len + 1];
    printf("Enter m1 : ");
    my_gets(plain_text, len + 1);

    word8 *hash = sha(plain_text);
    print_word8(hash, 32);
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

word8 *split_word32(word32 x)
{
    word8 *w = calloc(0, 4 * sizeof(word8));
    for (size_t i = 0; i < 4; i++)
    {
        w[i] |= (x >> (3 - i) * 8);
    }
    return w;
}

void add_word32_array(word32 *dst, const word32 *src, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        dst[i] += src[i];
    }
}

void print_word8(word8 *a, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X ", a[i]);
    }
    printf("\n");
}

void print_word32(word32 *a, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%08X ", a[i]);
    }
    printf("\n");
}

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

/*****************************************************************************/
/* SHA 256 Helpers:                                                           */
/*****************************************************************************/

word32 rotl(word32 a, word32 b)
{
    return (((a) << (b)) | ((a) >> (32 - (b))));
}

word32 rotr(word32 a, word32 b)
{
    return ((a >> b) | (a << (32 - b)));
}

word32 ch(word32 x, word32 y, word32 z)
{
    return (x & y) ^ (~x & z);
}

word32 maj(word32 x, word32 y, word32 z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

word32 big_sig0(word32 x)
{
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

word32 big_sig1(word32 x)
{
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

word32 sig0(word32 x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

word32 sig1(word32 x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

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

word8 *sha(word8 *raw)
{
    word8 *fmt = format(raw);
    // print_word8(fmt,2);
    int chunks = SHA256_CHUNK_COUNT(strlen(fmt));
    word8 *pad = sha_pad(fmt, chunks);
    word8 **blocks = malloc(chunks * sizeof(int *));
    for (size_t i = 0; i < chunks; i++)
    {
        blocks[i] = malloc(64 * sizeof(word8));
        memcpy(blocks[i], pad + i * 64, 64);
    }

    // print blocks
    // for (size_t j = 0; j < chunks; j++)
    // {
    //     for (size_t i = 0; i < 64; i++)
    //     {
    //         printf("%02X ", blocks[j][i]);
    //     }
    //     printf("\n");
    // }

    word32 h[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };

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
