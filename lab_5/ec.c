/** @file 201951034.c
 *  @brief Code for CS364 lab Assignment
 *  @author Ashish Kumar Singh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int M = 11;
int coeff_a = 1;
int coeff_b = 6;
int theta[2] = {0, 0};

// utilities

int mult_inv(int a);
int add_inv(int x);

// helpers

bool is_in_E(int x, int y);
bool is_theta(int a[2]);

// Elliptic curve operations

int *add(int x[2], int y[2]);
int *nadd(int x[2], int n);
int when_theta(int a[2]);

int main()
{
#ifndef LIVE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif

    int a[2] = {2, 7};
    // int b[2] = {2, 4};

    // int *temp = add(b, a);
    // printf("(%2d, %2d)", temp[0], temp[1]);

    // for (int i = 1; i < 14; i++)
    // {
    //     int *temp = nadd(a, i);
    //     printf("%2d times (%2d, %2d) : ", i, a[0], a[1]);
    //     printf("(%2d, %2d)", temp[0], temp[1]);
    //     printf("\n");
    // }

    int temp = when_theta(a);
    // printf("%2d times (%2d, %2d) : ", temp[0], temp[1]);
    printf("%2d", temp);
    printf("\n");
}

bool is_theta(int a[2])
{
    return (theta[0] == a[0] && theta[1] == a[1]);
}

bool is_in_E(int x, int y)
{
    int lhs = ((x * x * x) + coeff_a * x + coeff_b) % M;
    int rhs = (y * y) % M;
    return (lhs == rhs);
}

int when_theta(int a[2])
{
    int ctr = 1;
    int *ans = a;
    while (!is_theta(ans))
    {
        ans = add(ans, a);
        // printf("(%2d, %2d)\n", ans[0], ans[1]);
        ctr++;
    }
    return ctr;
}

int *nadd(int x[2], int n)
{
    if (n == 1)
        return x;
    int *ans = x;
    for (size_t i = 0; i < n - 1; i++)
    {
        ans = add(ans, x);
    }
    return ans;
}

int *add(int a[2], int b[2])
{
    int *ans = malloc(2 * sizeof(int));
    int m = 0;

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

int add_inv(int x)
{
    return M - x;
}

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

// for (int x = 0; x < M; x++)
// {
//     for (int y = 0; y < M; y++)
//     {
//         int a = ((x * x * x) + x + 6) % M;
//         int b = (y * y) % M;
//         if (a == b)
//         {
//             printf("(%d, %d) \n", x, y);
//         }
//     }
// }