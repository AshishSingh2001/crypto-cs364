#include <bits/stdc++.h>
using namespace std;

/**
 * @brief Encrypts text using feistel cipher
 * 
 * @param plainText unencrypted text that needs to be encrypted
 * @param key Key given by the user
 * @return long encrypted text
 */
long cipher(long plainText, long key)
{
    // convert plaintText and key into bits
    bitset<64> plainTextbits(plainText), keybits(key);

    // cout << plainTextbits << endl
    //      << keybits << endl
    //      << endl;

    // Split the left and right bits of plain text
    bitset<64> L1(plainTextbits >> 32), R1((plainTextbits << 32) >> 32);

    // cout << L1 << endl
    //      << R1 << endl
    //      << endl;

    bitset<64> R2, L2, cipherText;

    // round 1 feistel
    L2 = R1;
    R2 = keybits ^ L1;

    // cout << L2 << endl
    //      << R2 << endl
    //      << endl;

    // merge the newright and newleft
    cipherText = (L2 << 32) | R2;
    return cipherText.to_ulong();
}

/**
 * @brief Decrypts feistel cipher
 * 
 * @param cipherText Encrypted text that needs to be decrypted
 * @param key Key given by the user
 * @return long decrypted text
 */
long decipher(long cipherText, long key)
{
    // convert cipherText and key into bits
    bitset<64> cipherTextbits(cipherText), keybits(key);

    // cout << cipherTextbits << endl
    //      << endl;

    // Split the left and right bits of cipher text
    bitset<64> L2(cipherTextbits >> 32), R2((cipherTextbits << 32) >> 32);

    // cout << L2 << endl
    //      << R2 << endl
    //      << endl;

    bitset<64> L1, R1, plainText;
    L1 = R2 ^ keybits;
    R1 = L2;

    // cout << L1 << endl
    //      << R1 << endl
    //      << endl;

    // merge the L1 and R1
    plainText = (L1 << 32) | R1;
    return plainText.to_ulong();
}

int main()
{
    long plainText, key;

    cout << "Enter plain text :";
    cin >> plainText;

    cout << "Enter Key : ";
    cin >> key;

    long cipherText = cipher(plainText, key);
    cout << "CipherText = " << cipherText << endl;

    long decipherText = decipher(cipherText, key);
    cout << "DecipherText = " << decipherText << endl;
    return 0;
}