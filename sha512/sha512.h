/**
Course: Theory of Cryptography - ET3310
Lecturers: Do Trong Tuan, Ma Viet Duc
School: Hanoi University of Science and Technology - HUST
Group: 4
Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43
Created: Wed 03 Dec 2025 12:26:39 Hanoi, Vietnam
 */

#ifndef _SHA512_H_
#define _SHA512_H_

#include <stdint.h>
#include <stdio.h>

#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data qua dai */
    shaStateError       /* loi :)*/
};
#endif
#define SHA512HashSize 64     /*HashResults=64 bytes*/

/*
 *  Structure cua khoi thuc hien SHA1
 */
typedef struct SHA512Context
{
    uint64_t Intermediate_Hash[8]; /*Mang ket qua 8 phan tu 64 bit --> 512 bit*/

    uint64_t Length_Low;
    uint64_t Length_High;

    int Message_Block_Index;
    uint8_t Message_Block[128];  /*Blocksize=1024 bit --> 128 phan tu*/

    int Computed;
    int Corrupted;
    int Process_Count;

    uint8_t Print_Block_Input;     /* Optional, print binary tung khoi */

} SHA512Context;

/*
 *  Function Prototypes
 */
int SHA512Reset(  SHA512Context *);
int SHA1512nput(  SHA512Context *,
                const uint8_t *,
                unsigned int);
int SHA512Result( SHA512Context *,
                uint8_t Message_Digest[SHA512HashSize]);

#endif
