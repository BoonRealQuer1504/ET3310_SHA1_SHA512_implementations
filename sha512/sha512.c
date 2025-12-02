/**
Course: Theory of Cryptography - ET3310
Lecturers: Do Trong Tuan, Ma Viet Duc
School: Hanoi University of Science and Technology - HUST
Group: 4
Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43
Created: Wed 03 Dec 2025 12:26:19 Hanoi, Vietnam
 */
#include "sha512.h"
#include <string.h>
#include <stdio.h>

#define ROTR(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x,n)  ((x) >> (n))
#define SIG0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define SIG1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sig0(x) (ROTR(x,1)  ^ ROTR(x,8)  ^ SHR(x,7))
#define sig1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))


static const uint64_t K[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

void SHA512PadMessage(SHA512Context *);
void SHA512ProcessMessageBlock(SHA512Context *);

/**
 * @brief Khoi tao SHA512Context cho SHA512 message moi
 * 
 * @param context [in/out]
 *          The context to reset.
 * @return sha Error Code.
 */
int SHA512Reset(SHA512Context *context) {
    if (!context)
        return shaNull;

    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;
    context->Process_Count          = 0;
    
/*Message Digest Initialization, first 64 bits of fractional parts of sqrt of primes*/
    context->Intermediate_Hash[0] = 0x6a09e667f3bcc908ULL;
    context->Intermediate_Hash[1] = 0xbb67ae8584caa73bULL;
    context->Intermediate_Hash[2] = 0x3c6ef372fe94f82bULL;
    context->Intermediate_Hash[3] = 0xa54ff53a5f1d36f1ULL;
    context->Intermediate_Hash[4] = 0x510e527fade682d1ULL;
    context->Intermediate_Hash[5] = 0x9b05688c2b3e6c1fULL;
    context->Intermediate_Hash[6] = 0x1f83d9abfb41bd6bULL;
    context->Intermediate_Hash[7] = 0x5be0cd19137e2179ULL;

    context->Computed   = 0;
    context->Corrupted  = 0;
    return shaSuccess;
}

/**
 * @brief Tra ve ket qua cuoi cung
 * 
 * @param context [in/out]
 * @param Message_Digest [out]
 * @return sha Error Code.
 */
int SHA512Result( SHA512Context *context,
                uint8_t Message_Digest[SHA512HashSize]) {
    int i;

    if (!context || !Message_Digest)
        return shaNull;

    if (context->Corrupted)
        return context->Corrupted; /*Lỗi quá dài*/

    if (!context->Computed) {
        SHA512PadMessage(context);
        for(i=0; i<128; ++i)
            context->Message_Block[i] = 0;
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
    }

    for (i = 0; i < 8; ++i) {
        Message_Digest[i*8 + 0] = (uint8_t)(context->Intermediate_Hash[i] >> 56);
        Message_Digest[i*8 + 1] = (uint8_t)(context->Intermediate_Hash[i] >> 48);
        Message_Digest[i*8 + 2] = (uint8_t)(context->Intermediate_Hash[i] >> 40);
        Message_Digest[i*8 + 3] = (uint8_t)(context->Intermediate_Hash[i] >> 32);
        Message_Digest[i*8 + 4] = (uint8_t)(context->Intermediate_Hash[i] >> 24);
        Message_Digest[i*8 + 5] = (uint8_t)(context->Intermediate_Hash[i] >> 16);
        Message_Digest[i*8 + 6] = (uint8_t)(context->Intermediate_Hash[i] >> 8);
        Message_Digest[i*8 + 7] = (uint8_t)(context->Intermediate_Hash[i]);
    }
    return shaSuccess;
}

/**
 * @brief Input tu message_array
 * 
 * @param context [in/out]
 * @param message_array [in]
 * @param length [in] Chieu dai cua message_array
 * @return sha Error Code.
 */
int SHA512Input(    SHA512Context    *context,
                  const uint8_t  *message_array,
                  unsigned       length) {
    if (!length)
        return shaSuccess;

    if (!context || !message_array)
        return shaNull;

    if (context->Computed) {
        context->Corrupted = shaStateError;
        return shaStateError;
    }

    if (context->Corrupted)
        return context->Corrupted;
    while(length-- && !context->Corrupted) {
    context->Message_Block[context->Message_Block_Index++] =
                    (*message_array & 0xFF);

    context->Length_Low += 8;
    if (context->Length_Low == 0) {
        context->Length_High++;
        if (context->Length_High == 0)
            context->Corrupted = 1;
    }

    if (context->Message_Block_Index == 128)
        SHA512ProcessMessageBlock(context);

    message_array++;
    }

    return shaSuccess;
}

/**
 * Print binary for uint32_t 
*/
static void toBinary(uint32_t n)
{
    char binary[32];
    int k = 0;
    for (unsigned i = (1 << 32-1); i > 0; i = i/2) {
        binary[k++] = (n & i) ? '1' : '0';
    }
    binary[k] = '\0';
    printf("%s", binary);
}

/**
 * @brief Ham thuc hien 512 bit cua message
 * 
 * @param context 
 */
void SHA512ProcessMessageBlock(SHA512Context *context)
{
    
    int           t;                 /* Loop counter                */
    uint64_t      temp;              /* Temporary word value        */
    uint64_t      W[80];             /* Word sequence               */
    uint64_t      A, B, C, D, E, F,G,H;     /* Word buffers                */

    if(context->Print_Block_Input)
    {
        printf("Thuc hien SHA512 khoi thu %d:\n", context->Process_Count+1);
        context->Process_Count++;
    }

    for (t = 0; t < 16; ++t) {
        int i0 = t * 8;
        W[t] = ((uint64_t)context->Message_Block[i0] << 56) |
               ((uint64_t)context->Message_Block[i0+1] << 48) |
               ((uint64_t)context->Message_Block[i0+2] << 40) |
               ((uint64_t)context->Message_Block[i0+3] << 32) |
               ((uint64_t)context->Message_Block[i0+4] << 24) |
               ((uint64_t)context->Message_Block[i0+5] << 16) |
               ((uint64_t)context->Message_Block[i0+6] << 8)  |
               ((uint64_t)context->Message_Block[i0+7]);
        if (context->Print_Block_Input){
            toBinary(W[t]);
        }
    }
    if(context->Print_Block_Input)
        printf("\n");

    for(t = 16; t < 80; t++)
       W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];
    F = context->Intermediate_Hash[5];
    G = context->Intermediate_Hash[6];
    H = context->Intermediate_Hash[7];

    for(t = 0; t < 80; t++) {
        uint64_t temp1 = H + SIG1(E) + ((E & F) ^ ((~E) & G)) + K[t] + W[t]; /*Conditional Function*/
        uint64_t temp2 = SIG0(A) + ((A & B) ^ (A & C) ^ (B & C)); /*Majority Function*/
        H = G;
        G = F;
        F = E;
        E= D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1+ temp2;
    }

    

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Intermediate_Hash[5] += F;
    context->Intermediate_Hash[6] += G;
    context->Intermediate_Hash[7] += H;
    context->Message_Block_Index = 0;
}

/**
 * @brief Padding message
 * 
 * @param context [in/out]
 *          Context duoc pad
 */
void SHA512PadMessage(SHA512Context *context) {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    if (context->Message_Block_Index > 112){
        while (context->Message_Block_Index < 128)
            context->Message_Block[context->Message_Block_Index++] = 0;
        SHA512ProcessMessageBlock(context);
        while (context->Message_Block_Index < 112)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }
    else {
        while (context->Message_Block_Index < 112)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }

    for (int i = 0; i < 8; ++i)
        context->Message_Block[112 + i] = (uint8_t)(context->Length_High >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i)
        context->Message_Block[120 + i] = (uint8_t)(context->Length_Low >> (56 - 8 * i));


    SHA512ProcessMessageBlock(context);
    context->Computed = 1;
}
