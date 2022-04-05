/** @file 201951034.c
 *  @brief Code for CS364 lab Assignment
 *  Compression function using AES-128s
 *  h(m1||m2) = AES-128(m1, m2).
 *  @author Ashish Kumar Singh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int square_and_multiply(int x, int y, int mod);
int gen_bob_random();
int gen_alice_random();

int main()
{
    #ifndef LIVE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif
    time_t t;
    srand((unsigned)time(&t));

    int p = 131;
    int g = 2;

    int n1 = gen_alice_random();
    int n2 = gen_bob_random();
    printf("n1 : %d\n", n1);
    printf("n2 : %d\n", n2);

    int g1 = square_and_multiply(g, n1, p);
    int g2 = square_and_multiply(g, n2, p);
    printf("g1 : %d\n", g1);
    printf("g2 : %d\n", g2);

    // Alice verifying key
    int v1 = square_and_multiply(g2, n1, p);
    // Bob verifying key
    int v2 = square_and_multiply(g1, n2, p);

    printf("v1 : %d\n", v1);
    printf("v2 : %d\n", v2);
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

int square_and_multiply(int x, int y, int mod)
{
    int ans = 1;
    while (y > 0)
    {
        // mulitiply by x if y is odd
        if (y & 1)
            ans = (ans * x) % mod;

        // y = y/2
        y = y >> 1;
        // replace x by x^2
        x = (x * x) % mod;
    }
    return ans;
}

int gen_alice_random()
{
    return rand() + 1;
}

int gen_bob_random()
{
    return rand() + 1;
}
