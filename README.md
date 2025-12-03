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

Đặc trưng	--------SHA-1--------	SHA-512 -------(SHA-2)	--------Tỷ lệ Mở rộng
Kích thước Word	----32-bit (uint32_t)----	64-bit (uint64_t)	x2
Kích thước Khối (Block)	512 bit (64 bytes)	1024 bit (128 bytes)	x2
Kích thước Trạng thái (State)	5 word (160 bit)	8 word (512 bit: A-H)	x3.2
Độ dài Hash Output	160 bit	512 bit	x3.2
Số vòng lặp	80 vòng	80 vòng	Giữ nguyên


### 2.2. Định nghĩa lại Cấu trúc Dữ liệu SHA-512

### 2.3. Khác biệt về Hàm Nén (Compression Function)



## 3. QUÁ TRÌNH LẬP TRÌNH VÀ TRIỂN KHAI

### 3.1. Định nghĩa các Phép toán Cơ bản 


### 3.2. Triển khai Hàm Xử lý Khối (SHA512ProcessMessageBlock)


### 3.3. Xử lý Đệm (Padding) và Kết quả



## 4. KẾT QUẢ ĐẠT ĐƯỢC VÀ HƯỚNG DẪN SỬ DỤNG 

## 4.1. Kết quả 


## 4.2. HƯỚNG DẪN SỬ DỤNG


