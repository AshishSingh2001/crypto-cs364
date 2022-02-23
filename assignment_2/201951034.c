/** @file 201951034.c
 *  @brief Code for CS364 lab Assignment 
 *  @author Ashish Kumar Singh
 * 
 *  DES Cipher
 *  A Simple implementation for DES works on input 
 *  text of size 64 bit and key 64 and 56 bits both
 * 
 *  The implementation has been made using the specification
 *  given in [FIPS46]
 *  "Specifications for the Data Encryption Standard." Federal 
 *  Information Processing Standards Publication 46 (January 15, 1977).
 * https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
 * 
 *  The test vectors are taken from [Riv85]
 *  Ronald L. Rivest ,Testing Implementations of {DES}
 *  https://people.csail.mit.edu/rivest/pubsRiv85.txt
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

// Stores keys for all the rounds
char *round_keys[16];

// Utility functions

void my_gets(char *inp, int len);
char *xor_string(char *a, char *b);
char *int_to_binary(int decimal, int maxlen);
char *remove_parity(char *x);

// Generate Keys

char *shift_left(char *key_chunk, int l);
void generate_keys(char *key);
char *key_pc1(char *key64);
char *key_pc2(char *key64);

// DES Algorithm

char *data_encryption_algorithm(char *plain_text, bool isDecrypt);
char *initial_permutation(char *plain_text);
char *expansion_permutation(char *text_chunk);
char *substitution_box(char *xored, int i);
char *final_permutation(char *combined_text);
char *p_permutation(char *substituted);

char *des(char *input, char *key, bool isDecrypt);
void validate_des();

// Driver Code
int main(int argc, char const *argv[])
{
    // use input.txt and output.txt as stdin and stdout for debugging
#ifdef DEBUG
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif
    // validate the des implementation
    validate_des();

    char plain_text[65];
    printf("Enter 64 bit Text : ");
    my_gets(plain_text, 66);

    char key[65];
    printf("Enter 56 bit key : ");
    my_gets(key, 66);

    // encrypting using DES
    char *encrypted_text = des(plain_text, key, false);
    printf("Encrypted Text : %s\n", encrypted_text);

    // perform decryption on the encrypted text
    char *decrypted_text = des(encrypted_text, key, true);
    printf("Decrypted Text : %s\n", decrypted_text);

    if (strcmp(plain_text, decrypted_text) == 0)
    {
        printf("\nThe Input Text and the Text received after decrypting are identical\n");
    }

    return 0;
}

/**
 * @brief DES Implementation
 * 
 * @param input plain text 64 bit
 * @param key key 64 bit
 * @param isDecrypt bool is decryption mode
 * @return char* encrypted text
 */
char *des(char *input, char *key, bool isDecrypt)
{
    if (strlen(key) == 64)
    {
        // remove parity bits to make key 56 bits
        key = remove_parity(key);
    }
    if (strlen(key) == 56)
    {
        // generate keys for each round
        generate_keys(key);
        // maine des algorithm
        return data_encryption_algorithm(input, isDecrypt);
    }
    else
    {
        perror("Use 56 bit key followe by a \\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Validates the implementation of DES
 * using method mentioned in [Riv85]
 *  i       Xi                      Number of errors NOT detected
	--      ----------------        -----------------------------
	0       9474B8E8C73BCA7D        36,568
	1       8DA744E0C94E5E17        14,170
	2       0CDB25E3BA3C6D79         4,842
	3       4784C4BA5006081F         2,866
	4       1CF1FC126F2EF842         1,550
	5       E4BE250042098D13           996
	6       7BFC5DC6ADB5797C           652
	7       1AB3B4D82082FB28           458
	8       C1576A14DE707097           274
	9       739B68CD2E26782A           180
	10      2A59F0C464506EDB           126
	11      A5C39D4251F0A81E            94
	12      7239AC9A6107DDB1            72
	13      070CAC8590241233            52
	14      78F87B6E3DFECF61            20
	15      95EC2578C2C433F0             4
	16      1B1A2DDB4C642438             0 
    Reference - [Riv85]

    we input the X0 and check if the final output is X16 after 16 rounds
 */
void validate_des()
{
    // X0 = 0x9474B8E8C73BCA7D

    char *input = "1001010001110100101110001110100011000111001110111100101001111101";
    for (int i = 0; i < 16; i++)
    {
        input = des(input, input, (i % 2 != 0));
    }
    char *output = "0001101100011010001011011101101101001100011001000010010000111000";
    int l = strlen(output);
    int x = strlen(input);
    // X16 = 0x1B1A2DDB4C642438
    if (strcmp(input, output) == 0)
    {
        printf("\nCurrent implementation is valid using methods mentioned in [Riv85]\n\n");
    }
}

// *************** Utility *****************

/**
 * @brief removes parity bit for a binary string
 */
char *remove_parity(char *x)
{
    char *s = (char *)malloc(57);
    int l = strlen(x);
    for (size_t i = 0; i < l; i++)
    {
        // remove 8th parity bit
        if ((i + 1) % 8 != 0)
        {
            strncat(s, &x[i], 1);
        }
    }
    int temp = strlen(s);
    return s;
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
 * @brief converts decimal to binary string
 * 
 * @param decimal 
 * @return char* binary string
 */
char *int_to_binary(int decimal, int maxlen)
{
    char *binary = (char *)malloc(maxlen + 1);
    int curr = maxlen - 1;
    for (size_t i = 0; i < 4; i++)
    {
        binary[i] = '0';
    }
    while (decimal != 0)
    {
        binary[curr--] = (decimal % 2 == 0) ? '0' : '1';
        decimal = decimal / 2;
    }
    while (curr > 0)
    {
        binary[curr--] = '0';
    }
    return binary;
}

/**
 * @brief xor two strings
 * 
 * @param a
 * @param b
 * @return char* xored string
 */
char *xor_string(char *a, char *b)
{
    int la = strlen(a);
    char *xored = (char *)malloc(la + 1);
    for (size_t i = 0; i < la; i++)
    {
        xored[i] = (a[i] == b[i]) ? '0' : '1';
    }
    return xored;
}

/**
 * @brief convert hexadecimal string to 64bit binary
 * 
 * @param hex 
 * @return char* binary string
 */
char *hex_to_bin(char *hex)
{
    return int_to_binary(strtol(hex, NULL, 10), 64);
}

// *************** Generate Keys *****************

/**
 * @brief shifts the key to left according to the round number
 * 
 * @param s string which is to be shifted
 * @param round round number
 * @return char* left shifted key according to the round number
 */
char *shift_left(char *s, int round)
{
    int shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    int shift = shifts[round - 1];
    int len = strlen(s);
    int i = shift, l = 0, curr = 0;
    char *temp = (char *)malloc(28 + 1);
    while (i < len)
    {
        temp[curr++] = s[i++];
    }
    while (l < shift)
    {
        temp[curr++] = s[l++];
    }
    s = temp;
    return s;
}

/**
 * @brief generate 16 keys for each round
 * 
 * @param key key
 */
void generate_keys(char *key)
{
    int len = strlen(key);

    // Commpressing using PC1
    char *key_gen = key_pc1(key);

    // Dividing in two halves
    char *left = (char *)malloc(28 + 1);
    char *right = (char *)malloc(28 + 1);
    memcpy(left, &key_gen[0], 28);
    memcpy(right, &key_gen[28], 28);
    // printf("%s\n%s\n", left, right);

    // generating 16 keys
    for (int i = 0; i < 16; i++)
    {
        // left shift each half according to the round
        left = shift_left(left, i + 1);
        right = shift_left(right, i + 1);
        // printf("%s\n%s\n", left, right);

        // merging both halves
        strcpy(key_gen, left);
        strcat(key_gen, right);

        // compressing using pc2
        char *curr_key = key_pc2(key_gen);

        // storing in global variable for keys
        round_keys[i] = curr_key;
        // printf("Key %d: %s\n", i + 1, round_keys[i]);
    }
}

/**
 * @brief compress the 64 bit key to 56 key using pc1
 * 
 * @param key64 64 bit key
 * @return char* 56 bit compressed key
 */
char *key_pc1(char *key64)
{
    // The PC1 table
    // int PC1[56] = {
    //     57, 49, 41, 33, 25, 17, 9,
    //     1, 58, 50, 42, 34, 26, 18,
    //     10, 2, 59, 51, 43, 35, 27,
    //     19, 11, 3, 60, 52, 44, 36,
    //     63, 55, 47, 39, 31, 23, 15,
    //     7, 62, 54, 46, 38, 30, 22,
    //     14, 6, 61, 53, 45, 37, 29,
    //     21, 13, 5, 28, 20, 12, 4};

    int PC1[56] = {
        50, 43, 36, 29, 22, 15, 8, 1,
        51, 44, 37, 30, 23, 16, 9, 2,
        52, 45, 38, 31, 24, 17, 10, 3,
        53, 46, 39, 32, 56, 49, 42, 35,
        28, 21, 14, 7, 55, 48, 41, 34,
        27, 20, 13, 6, 54, 47, 40, 33,
        26, 19, 12, 5, 25, 18, 11, 4};
    char *key56 = (char *)malloc(56 + 1);
    for (int i = 0; i < 56; i++)
    {
        key56[i] = key64[PC1[i] - 1];
    }
    return key56;
}

/**
 * @brief compress the 56 bit key to 48 key using pc2
 * 
 * @param key64 56 bit key
 * @return char* 48 bit compressed key
 */
char *key_pc2(char *key56)
{
    // The PC2 table
    int PC2[48] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32};
    int len = strlen(key56);
    char *key48 = (char *)malloc(48 + 1);
    for (size_t i = 0; i < 48; i++)
    {
        key48[i] = key56[PC2[i] - 1];
    }
    return key48;
}

// *************** DES Algorithm *****************

/**
 * @brief Main algorithm for DES
 * 
 * @param plaintext 64 bit text
 * @param isDecrypt is decryption mode
 * @return char* encrypted/decrypted text
 */
char *data_encryption_algorithm(char *plain_text, bool isDecrypt)
{
    //initial permutation
    char *text_ip = (char *)malloc(64);
    text_ip = initial_permutation(plain_text);

    // divide in two halves
    char *left = (char *)malloc(28 + 1);
    char *right = (char *)malloc(28 + 1);
    memcpy(left, &text_ip[0], 32);
    memcpy(right, &text_ip[32], 32);

    // 16 rounds of encryption
    for (int i = 0; i < 16; i++)
    {
        // expanding the right side of plain text
        char *right_expanded = expansion_permutation(right);
        int key_num = isDecrypt ? 15 - i : i;
        char *xored = xor_string(round_keys[key_num], right_expanded);

        // divide in 8 equal parts
        char *substituted = (char *)malloc(16 + 1);
        for (size_t i = 0; i < 8; i++)
        {
            // substitute the parts from size of 6 to 4
            char *curr_text = substitution_box(xored, i);
            strcat(substituted, curr_text);
        }
        // printf("%s\n", substituted);
        char *perm_2 = p_permutation(substituted);

        left = xor_string(perm_2, left);

        if (i < 15)
        {
            char *temp = right;
            right = left;
            left = temp;
        }
    }

    char *combined_text = (char *)malloc(64 + 1);
    // merging both halves
    strcpy(combined_text, left);
    strcat(combined_text, right);

    char *cipher_text = final_permutation(combined_text);
    return cipher_text;
}

/**
 * @brief Initial permutation for text
 */
char *initial_permutation(char *plain_text)
{
    // The initial permutation table
    int IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7};
    int len = strlen(plain_text);
    char *permuted_text = (char *)malloc(64 + 1);
    for (size_t i = 0; i < 64; i++)
    {
        permuted_text[i] = plain_text[IP[i] - 1];
    }
    return permuted_text;
}

/**
 * @brief final permutation or the inverse or the initial permutation
 */
char *final_permutation(char *combined_text)
{
    // The final permutation table
    int INV_P[64] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25};
    int len = strlen(combined_text);
    char *inverted_text = (char *)malloc(64 + 1);
    for (size_t i = 0; i < 64; i++)
    {
        inverted_text[i] = combined_text[INV_P[i] - 1];
    }
    return inverted_text;
}

/**
 * @brief p box permutation
 */
char *p_permutation(char *substituted)
{
    // The array elements denote the bit numbers
    int P[32] = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25};
    int len = strlen(substituted);
    char *permuted_text = (char *)malloc(64 + 1);
    for (size_t i = 0; i < 32; i++)
    {
        permuted_text[i] = substituted[P[i] - 1];
    }
    return permuted_text;
}

/**
 * @brief expansion permutation
 * 
 * @param text_chunk 
 * @return char* 
 */
char *expansion_permutation(char *text_chunk)
{
    // expansiona table
    int expansion_table[48] = {
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1};
    int len = strlen(text_chunk);
    char *expanded = (char *)malloc(64 + 1);
    for (int i = 0; i < 48; i++)
    {
        expanded[i] = text_chunk[expansion_table[i] - 1];
    }
    return expanded;
}

/**
 * @brief s box compression
 */
char *substitution_box(char *xored, int i)
{
    // The substitution table with values [0,16)
    int substition_boxes[8][4][16] = {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
    };

    char *row = (char *)malloc(2), *col = (char *)malloc(2);
    row[0] = xored[i * 6];
    row[1] = xored[i * 6 + 5];
    memcpy(col, &xored[i * 6 + 1], 4);
    int r = strtol(row, NULL, 2);
    int c = strtol(col, NULL, 2);
    int val = substition_boxes[i][r][c];
    return int_to_binary(val, 4);
}
