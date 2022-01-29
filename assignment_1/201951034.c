/** @file 201951034.c
 *  @brief Code for CS364 lab Assignment 
 *  Playfair cipher -> Caesar Cipner -> Affine Cipher
 * 
 *  @author Ashish Kumar Singh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

char *sanitisePlayfairText(char *plainText);
char *sanitisePlayfairKey(char *plainText);
void generateKeyTable(char *key, char keyMatrix[5][5]);
char *encryptPlayfair(char *key, char *plainText, char keyMatrix[5][5]);
void searchKeyMatrix(char a, int aind[2], char keyMatrix[5][5]);
void printKeyMatrix(char keyMatrix[5][5]);
char *encryptCaesar(int key, char *plainText);

/**
 * @brief wrapper for fgets
 * gets is deprecated so a wrapper for it using fgets
 * and some formatting for the out put string
 */
void myGets(char *inp, int len)
{
    fgets(inp, len, stdin);
    inp[strcspn(inp, "\n")] = 0;
    printf("\n");
}

int main(int argc, char const *argv[])
{
#ifndef ONLINE_JUDGE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif
    // Task 1 - Input Plain Text

    char rawText[50];
    printf("Enter Plain Text : ");
    myGets(rawText, 50);

    // Task 2 - sanitise text

    char *plainText = sanitisePlayfairText(rawText);
    // free(rawText);

    // Task 3 - Output ∆

    printf("∆ : %s\n", plainText);

    // Task 4 - Input Playfair Key

    char rawK1[50];
    printf("Enter Playfair Key : ");
    myGets(rawK1, 50);
    char *k1 = sanitisePlayfairKey(rawK1);

    // Task 5 - Output generated 5x5 key matrix

    char keyMatrix[5][5];
    generateKeyTable(k1, keyMatrix);
    printKeyMatrix(keyMatrix);

    // Task 6 - Encrypt using playfair cipher

    char *c1 = encryptPlayfair(k1, plainText, keyMatrix);
    printf("C1 : %s\n", c1);

    // Task 7 - Encrypt C1 using caesar cipher with key(k2) = 3
    int k2 = 3;
    char *c2 = encryptCaesar(k2, c1);
    printf("C2 : %s\n", c2);

    // task 8 - 

    return 0;
}

/**
 * @brief sanitises raw text for playfair cipher
 * 
 * remove spaces and non alphanumeric characters,converts
 * to lower case, replaces j with i and adds filler char
 * 'x' when there is repetition of letters in a digram 
 * or the length of the final text is odd
 * 
 * @param plainText the raw text input
 * @return char* sanitised text
 */
char *sanitisePlayfairText(char *rawText)
{

    char sanitisedText[50];
    int j = 0;
    for (size_t i = 0; i < strlen(rawText); i++)
    {
        // convert to lower text and replace j with i
        rawText[i] = tolower(rawText[i]);
        if (rawText[i] == 'j')
        {
            rawText[i] = 'i';
        }
        // skip spaces and non alpha numeric characters
        if (isalpha(rawText[i]))
        {
            // remove repetition of letter if its a digram
            if (sanitisedText[j - 1] == rawText[i] && (j - 1) % 2 == 0)
            {
                sanitisedText[j++] = 'x';
            }
            sanitisedText[j++] = rawText[i];
        }
    }

    // add filler char 'x' if length is odd
    if (j % 2 != 0)
    {
        sanitisedText[j++] = 'x';
    }
    sanitisedText[j] = '\0';

    // allocate memory and return sanitised text
    char *copy = (char *)malloc(j + 1);
    strcpy(copy, sanitisedText);
    return copy;
}

/**
 * @brief sanitises raw text for playfair cipher
 * 
 * remove spaces and non alphanumeric characters,converts
 * to lower case, replaces j with i 
 * 
 * @param plainText the raw text input
 * @return char* sanitised text
 */
char *sanitisePlayfairKey(char *rawK1)
{
    char sanitisedKey[50];
    ;
    int j = 0;
    // convert to lower text and replace j with i
    int len = strlen(rawK1);
    for (size_t i = 0; i < len; i++)
    {
        rawK1[i] = tolower(rawK1[i]);
        if (rawK1[i] == 'j')
        {
            rawK1[i] = 'i';
        }
        if (isalpha(rawK1[i]))
        {
            sanitisedKey[j++] = rawK1[i];
        }
    }
    sanitisedKey[j] = '\0';

    // allocate memory and return sanitised text
    char *copy = (char *)malloc(strlen(sanitisedKey) + 1);
    strcpy(copy, sanitisedKey);
    return copy;
}

/**
 * @brief Make the 5x5 Key Matrix for Playfair Cipher
 * 
 * @param key Key used to encrypt
 * @param keyMatrix matrix which is generated
 */
void generateKeyTable(char *key, char keyMatrix[5][5])
{
    int indexedAlphabet[26] = {0}, keyLen = strlen(key);
    for (size_t i = 0; i < keyLen; i++)
    {
        indexedAlphabet[key[i] - 97] = 2;
    }
    indexedAlphabet['j' - 97] = 1;
    // to separate 'j' from being processed

    int i = 0, j = 0; // indexes for keyMatrix

    // insert characters of key first in the matrix
    for (size_t k = 0; k < keyLen; k++)
    {
        if (indexedAlphabet[key[k] - 97] == 2)
        {
            indexedAlphabet[key[k] - 97]--;
            keyMatrix[i][j++] = key[k];
            if (j >= 5)
            {
                i++;
                j = 0;
            }
        }
    }
    // adding remaining alphabets to the keyMatrix
    for (size_t k = 0; k < 26; k++)
    {
        if (indexedAlphabet[k] == 0)
        {
            keyMatrix[i][j++] = (char)(k + 97);
            if (j >= 5)
            {
                i++;
                j = 0;
            }
        }
    }
}

/**
 * @brief Print the matrix for palayfair encryption
 * 
 * @param keyMatrix playfair key matrix
 */
void printKeyMatrix(char keyMatrix[5][5])
{
    for (size_t i = 0; i < 5; i++)
    {
        for (size_t j = 0; j < 5; j++)
            printf("%c ", keyMatrix[i][j]);
        printf("\n");
    }
}

/**
 * @brief Search a particular char in Key Matrix
 * 
 * @param keyMatrix Matrix which is searched
 * @param a char which is being searched for
 * @param aind indexes of char if found else -1
 */
void searchKeyMatrix(char a, int aind[2], char keyMatrix[5][5])
{
    for (size_t i = 0; i < 5; i++)
    {
        for (size_t j = 0; j < 5; j++)
        {
            if (keyMatrix[i][j] == a)
            {
                aind[0] = i;
                aind[1] = j;
            }
        }
    }
}

/**
 * @brief encrypt plain text using playfair cipher
 * 
 * @param key key for encryption
 * @param plainText text to be encrypted
 * @param keyMatrix matrix used for encryption
 * @return char* encrypted text
 */
char *encryptPlayfair(char *key, char *plainText, char keyMatrix[5][5])
{
    int len = strlen(plainText);
    char *encryptedText = (char *)malloc(len + 1);
    for (size_t i = 0; i < len; i += 2)
    {
        int aind[2] = {-1}, bind[2] = {-1};
        searchKeyMatrix(plainText[i], aind, keyMatrix);
        searchKeyMatrix(plainText[i + 1], bind, keyMatrix);

        if (aind[0] == bind[0])
        {
            encryptedText[i] = keyMatrix[aind[0]][(aind[1] + 1) % 5];
            encryptedText[i + 1] = keyMatrix[aind[0]][(bind[1] + 1) % 5];
        }
        else if (aind[1] == bind[1])
        {
            encryptedText[i] = keyMatrix[(aind[0] + 1) % 5][aind[1]];
            encryptedText[i + 1] = keyMatrix[(bind[0] + 1) % 5][aind[1]];
        }
        else
        {
            encryptedText[i] = keyMatrix[aind[0]][bind[1]];
            encryptedText[i + 1] = keyMatrix[bind[0]][aind[1]];
        }
    }
    return encryptedText;
}

char *encryptCaesar(int key, char *plainText)
{
    int len = strlen(plainText);
    char *encryptedText = (char *)malloc(len + 1);
    for (size_t i = 0; i < len; i++)
    {
        // shft character by key

        int shiftedAplhaIndex = (((int)plainText[i] - 97 + key) % 26);
        encryptedText[i] = (char)(shiftedAplhaIndex + 97);
    }
    return encryptedText;
}