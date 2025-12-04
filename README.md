# Lập trình hàm băm (Hash Function) SHA-512 dựa trên cấu trúc SHA-1.
**Course: Theory of Cryptography - ET3310**

**Lecturers: Do Trong Tuan, Ma Viet Duc**

**School: Hanoi University of Science and Technology - HUST**

**Group: 4**

**Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43**

**Created: Wed 03 Dec 2025 12:25:05 Hanoi, Vietnam**


_Báo cáo này trình bày quá trình phân tích mã nguồn SHA-1 ban đầu, sau đó nâng cấp thuật toán lên SHA-512 theo chuẩn FIPS PUB 180-4 (SHA-2). Mục tiêu là giữ nguyên cấu trúc có sẵn (SHAContext, Reset, Input, Result) nhưng mở rộng kích thước khối, phép quay bit, hàm nén và số vòng lặp theo yêu cầu của SHA-512._

_Quá trình này minh họa rõ ràng sự khác biệt về kiến trúc giữa SHA-1 (32-bit) và SHA-512 (64-bit), đồng thời cho thấy cách áp dụng mô hình Merkle–Damgård chung cho cả hai thuật toán._

_Original Project created by  * @author Ma Duc (mavietduc@gmail.com)_

## 1. Phân tích cấu trúc SHA-1 đã cho.
_Để đảm bảo tính kế thừa, cần phân tích kỹ lưỡng cấu trúc dữ liệu và logic của SHA-1 đã được cung cấp trong thư mục sha1._
### 1.1 Cấu trúc SHA-1 
_Cấu trúc SHA1Context cơ sở được định nghĩa như sau:_
```
typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize/4];

    uint32_t Length_Low;
    uint32_t Length_High;

    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];

    int Computed;
    int Corrupted;
    int Process_Count;

    uint8_t Print_Block_Input;     /* Optional, print binary tung khoi */

} SHA1Context;
``` 


Đặc trưng của hàm băm SHA-1:
- Khối xử lý (Message Block): 512 bit (64 byte)

- Hash output: 160 bit (20 byte)

- Intermediate state: 5 × 32-bit word (A, B, C, D, E)

- Số vòng: 80 vòng
### 1.2. Các giao diện hàm
_Thuật toán SHA-1 được xây dựng theo mô hình Merkle–Damgård với các hàm chính:_

- Hàm SHA1Reset: Khởi tạo giá trị băm ban đầu (Initial Hash Value - H0)
```
int SHA1Reset(SHA1Context *context) {
    if (!context)
        return shaNull;

    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;
    context->Process_Count          = 0;
    context->Print_Block_Input      = 0;

    context->Intermediate_Hash[0]   = 0x67452301;
    context->Intermediate_Hash[1]   = 0xEFCDAB89;
    context->Intermediate_Hash[2]   = 0x98BADCFE;
    context->Intermediate_Hash[3]   = 0x10325476;
    context->Intermediate_Hash[4]   = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;
    return shaSuccess;
}
```


- Hàm SHA1Input: Nhận dữ liệu đầu vào và gọi hàm nén khi khối 512 bit được lấp đầy.

```
int SHA1Input(    SHA1Context    *context,
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

    if (context->Message_Block_Index == 64)
        SHA1ProcessMessageBlock(context);

    message_array++;
    }

    return shaSuccess;
}
```

- Hàm SHA1Result: Thực hiện Padding và trả về kết quả băm.

```
int SHA1Result( SHA1Context *context,
                uint8_t Message_Digest[SHA1HashSize]) {
    int i;

    if (!context || !Message_Digest)
        return shaNull;

    if (context->Corrupted)
        return context->Corrupted;

    if (!context->Computed) {
        SHA1PadMessage(context);
        for(i=0; i<64; ++i)
            context->Message_Block[i] = 0;
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
        }

    for(i = 0; i < SHA1HashSize; ++i)
        Message_Digest[i] = context->Intermediate_Hash[i>>2]
                            >> 8 * ( 3 - ( i & 0x03 ) );

    return shaSuccess;
}
```

- Hàm SHA1ProcessMessageBlock: Hàm nén (Compression Function), thực hiện 80 vòng lặp xử lý chính.

```
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const uint32_t K[] = {0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6};
    int           t;                 /* Loop counter                */
    uint32_t      temp;              /* Temporary word value        */
    uint32_t      W[80];             /* Word sequence               */
    uint32_t      A, B, C, D, E;     /* Word buffers                */

    if(context->Print_Block_Input)
    {
        printf("Thuc hien SHA1 khoi thu %d:\n", context->Process_Count+1);
        context->Process_Count++;
    }

    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
        if(context->Print_Block_Input)
            toBinary(W[t]);
    }
    if(context->Print_Block_Input)
        printf("\n");

    for(t = 16; t < 80; t++)
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for(t = 0; t < 20; t++) {
        temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++) {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}
```
## 2. CƠ SỞ LÝ THUYẾT: CHUYỂN ĐỔI TỪ SHA-1 SANG SHA-512

_Việc chuyển đổi từ SHA-1 sang SHA-512 yêu cầu thay đổi hầu hết các tham số định lượng theo chuẩn SHA-2._


### 2.1. Khác biệt về Kích thước và Trạng thái

| Đặc trưng | SHA-1 | SHA-512 |
|---------------|---------------|---------------|
| Kích thước Word | 32-bit (uint32_t) | 64-bit (uint64_t) |
| Kích thước Khối (Block) | 512 bit (64 bytes) | 1024 bit (128 bytes) |
| Mesage Digest Size | 160 bit | 512 bit |
| Số vòng lặp  | 80 | 80 |

### 2.2. Định nghĩa lại Cấu trúc Dữ liệu SHA-512
_Để duy trì giao diện hàm (API) nhưng mở rộng khả năng xử lý, cần định nghĩa lại cấu trúc SHA512Context:_


```
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
```

### 2.3. Khác biệt về Hàm Nén (Compression Function)
_Sự khác biệt về hàm nén là nơi thay đổi cốt lõi của thuật toán._

- SHA-512 sử dụng 80 hằng số $K_t$ (64-bit), trong khi SHA-1 chỉ dùng 4 hằng số 32-bit làm hằng số vòng lặp để sử dụng trong hàm nén.

```
const uint32_t K[] = {0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6} ## SHA-1 const
const uint64_t K[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,...., 0x6c44198c4a475817ULL
};    ## SHA-512 const 
```


- Word Expansion: SHA-1 mở rộng 16 word đầu (32-bit) thành 80 word. SHA-512 mở rộng 16 word đầu (64-bit) thành 80 word (64-bit) bằng công thức tương tự nhưng sử dụng phép quay (rotation) thay vì dịch chuyển (shift) và các phép toán 64-bit.

- Các hàm logic cơ bản của SHA-1 được thay thế bằng các hàm phức tạp hơn trong SHA-512 bao gồm hàm Right Rotation, RotShift và các hàm Sigma dùng để mở rộng message.

## 3. QUÁ TRÌNH LẬP TRÌNH VÀ TRIỂN KHAI

_Quá trình triển khai SHA-512 được thực hiện trong thư mục sha512 và giữ nguyên tên giao diện hàm (SHA512Reset, SHA512Input, SHA512Result)._
### 3.1. Định nghĩa các Phép toán Cơ bản 

_Các phép toán quay (Rotation), dịch chuyển (Shift) và Sigma đóng vai trò quan trọng trong SHA-512._

```
#define ROTR(x,n) (((x) >> (n)) | ((x) << (64 - (n)))) // Phép quay bit                                                         tuần hoàn 64 bit    
#define SHR(x,n)  ((x) >> (n))        //Phép dịch phải bit logic 64-bit.

#define SIG0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define SIG1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
// Kết hợp 3 phép quay bit khác nhau, dùng để tạo ra các State mới. 

#define sig0(x) (ROTR(x,1)  ^ ROTR(x,8)  ^ SHR(x,7))
#define sig1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))
// Kết hợp 2 phép quay và 1 phép dịch bit, sử dụng trong quá trình Mở rộng Thông điệp (Message Expansion).

```

### 3.2. Triển khai Hàm Xử lý Khối (SHA512ProcessMessageBlock)
Hàm SHA512ProcessMessageBlock là nơi xử lý các khối trong từng vòng:


- Khởi tạo mảng chứa 80 từ của thông điệp và 8 trạng thái băm trong suốt 80 vòng lặp. Khối thông điệp đầu vào (context->Message_Block, 128 bytes) được chuyển thành 16 từ 64-bit đầu tiên của mảng $W$ ($W_0$ đến $W_{15}$).
```
uint64_t      W[80];             /* Word sequence               */
uint64_t      A, B, C, D, E, F,G,H;     /* Word buffers                */
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
```
- Word Expansion: Với các từ $W_{0}$ đến $W_{15}$ được tạo ở trên, các từ $W_{16}$ đến $W_{79}$ được tính toán dựa trên 4 từ đã được tính trước đó, sử dụng các hàm Sigma nhỏ ($\sigma_0, \sigma_1$) đã được định nghĩa.

$$W_t = \sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16}$$

```
for(t = 16; t < 80; t++)
       W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
```

- Tám giá trị băm trung gian hiện tại (context->Intermediate_Hash[0] đến [7]) được sao chép vào các biến cục bộ $A$ đến $H$. Điều này là cần thiết để cộng dồn kết quả băm mới vào cuối hàm.

```
    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];
    F = context->Intermediate_Hash[5];
    G = context->Intermediate_Hash[6];
    H = context->Intermediate_Hash[7];
```

- Vòng lặp chính: Hàm nén thực hiện 80 vòng lặp, cập nhật 8 biến trạng thái trong mỗi vòng. Chi tiết:

 _    - Tính toán giá trị temp1:_
```
uint64_t temp1 = H + SIG1(E) + ((E & F) ^ ((~E) & G)) + K[t] + W[t]; /*Conditional Function*/
```


trong đó: SIG1(E) chính là hàm Rotate(E)

Ch(E, F, G): hàm Conditional(E, F, G) = ((E & F) ^ ((~E) & G)) 
   
 _   - Tính toán giá trị T2: _

```
uint64_t temp2 = SIG0(A) + ((A & B) ^ (A & C) ^ (B & C)); /*Majority Function*/
```
với SIG0(A) là hàm Rotate(A)

Maj(A, B, C): hàm Majority(A,B,C) = ((A & B) ^ (A & C) ^ (B & C))

_
    - Cập nhật Trạng thái theo quy tắc sau: _

```
        H = G;
        G = F;
        F = E;
        E= D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1+ temp2;

```


- Sau 80 vòng lặp, các giá trị cuối cùng của $A$ đến $H$ được cộng dồn với trạng thái băm trung gian ban đầu (context->Intermediate_Hash[]).

```
    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Intermediate_Hash[5] += F;
    context->Intermediate_Hash[6] += G;
    context->Intermediate_Hash[7] += H;
    context->Message_Block_Index = 0;
```
### 3.3. Xử lý Đệm (Padding) và Kết quả

_Do kích thước khối đã tăng lên 1024 bit (128 bytes) và độ dài thông điệp được lưu trữ bằng 128 bit (hai uint64_t), logic đệm thông điệp cần được điều chỉnh trong hàm SHA512PadMessage:_

- Thông điệp được đệm bằng một bit 1, theo sau là các bit 0 cho đến khi khối còn thiếu 128 bit để hoàn thành 1024 bit.

  ```
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
  ```

- Sử dụng 16 bytes ở cuối khối đệm để để ghi độ dài thông điệp gốc (tính bằng bit). Độ dài này được lưu trữ trong hai trường 64-bit: Length_High và Length_Low.

```

   for (int i = 0; i < 8; ++i)
        context->Message_Block[112 + i] = (uint8_t)(context->Length_High >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i)
        context->Message_Block[120 + i] = (uint8_t)(context->Length_Low >> (56 - 8 * i));
```
## 4. KẾT QUẢ ĐẠT ĐƯỢC VÀ HƯỚNG DẪN SỬ DỤNG 


- Triển khai thành công hàm băm SHA-512 (SHA-2) tuân thủ chuẩn FIPS PUB 180-4.
- Đảm bảo duy trì các giao diện hàm chính (Reset, Input, Result) theo cấu trúc đã có của SHA-1, giúp việc thay thế (plug-in) thuật toán trở nên dễ dàng.
- Mã nguồn được kiểm tra với các chuỗi thử nghiệm chuẩn (Test Vectors) và cho ra kết quả băm SHA-512 chính xác.

```
PS C:\Users\speci\OneDrive\Documents\CODE\C\SHA\sha512> ./main2.exe 'hello world'
Input van ban: 'hello world'
Output: 30 9e cc 48 9c 12 d6 eb 4c c4 0f 50 c9 02 f2 b4 d0 ed 77 ee 51 1a 7c 7a 9b cd 3c a8 6d 4c d8 6f 98 9d d3 5b c5 ff 49 96 70 da 34 25 5b 45 b0 cf d8 30 e8 1f 60 5d cf 7d c5 54 2e 93 ae 9c d7 6f
```




