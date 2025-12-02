/**
Course: Theory of Cryptography - ET3310
Lecturers: Do Trong Tuan, Ma Viet Duc
School: Hanoi University of Science and Technology - HUST
Group: 4
Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43
Created: Wed 03 Dec 2025 12:25:09 Hanoi, Vietnam
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sha512.c"

int main(int argc, char* argv[]){
    SHA512Context sha;
    int i, j, err;
    uint8_t Message_Digest[SHA512HashSize];
    char *input = argv[1];
    printf( "Input van ban: '%s'\t\n", input);

    err = SHA512Reset(&sha);
    
    if (err){
        fprintf(stderr, "SHA1Reset Error %d.\n", err );
        return 0;
    }
    if (argc >= 3){
        sha.Print_Block_Input = (uint8_t) argv[2][0] - 48;      /* print padding input data */
    }

    err = SHA512Input(&sha, (const unsigned char *) input, strlen(input));
    if (err) {
        fprintf(stderr, "SHA512 Input Error %d.\n", err );
        return 0;
    }
    err = SHA512Result(&sha, Message_Digest);
    if (err) {
        fprintf(stderr,
        "SHA512 Result Error %d, không thể tính được message digest.\n", err );
    }
    else {
        printf("Output: ");
        for(i = 0; i < SHA512HashSize ; ++i)
            printf("%02x ", Message_Digest[i]);
        printf("\n");
    }
    return 0;
}
