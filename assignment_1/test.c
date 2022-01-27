/** @file 201951034.c
 *  @brief Code for CS364 lab Assignment 
 *  @author Ashish Kumar Singh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/** @brief Kernel entrypoint.
 *
 *  This is the entrypoint for your kernel.
 *  You will use this to test and debug your
 *  drivers and it will eventually hold the
 *  code for your game.  Right now, it is
 *  A tight while loop.
 *
 * @return Should not return
 */
char* sanitise(char *plainText)
{
    char sanitisedText[50];
    int j = 0;
    for (int i = 0; plainText[i] != '\0'; i++)
    {
        // skip spaces
        if (plainText[i] != ' ')
        {
            // replcae j with i for playfair cipher
            if (plainText[i] == 'j')
            {
                sanitisedText[j++] = 'i';
            }
            else
            {
                sanitisedText[j++] = plainText[i];
            }
        }
    }
    int len = strlen(sanitisedText);
    char* copy = (char *)malloc(len + 1);
    strcpy(copy, sanitisedText);
    return copy;
}

int main(int argc, char const *argv[])
{
#ifndef ONLINE_JUDGE
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
#else
#endif
    char plainText[50];

    printf("Enter a Plain Text : ");
    scanf("%[^\n]s", plainText);

    char* sanitisedText = sanitise(plainText);
    printf("Hello World %s\n", sanitisedText);

    return 0;
}
