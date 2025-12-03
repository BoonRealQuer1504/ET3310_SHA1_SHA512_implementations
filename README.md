# Lập trình hàm băm SHA-512 dựa trên cấu trúc SHA-1.
**Course: Theory of Cryptography - ET3310**

**Lecturers: Do Trong Tuan, Ma Viet Duc**

**School: Hanoi University of Science and Technology - HUST**

**Group: 4**

**Students: Nguyen Ho Trieu Duong - C41 , Nguyen Tien Dat - C42, Vu Tien Dat - C43**

**Created: Wed 03 Dec 2025 12:25:05 Hanoi, Vietnam**


_Báo cáo này trình bày quá trình phân tích mã nguồn SHA-1 ban đầu, sau đó nâng cấp thuật toán lên SHA-512 theo chuẩn FIPS PUB 180-4 (SHA-2).
Mục tiêu là giữ nguyên cấu trúc có sẵn (SHAContext, Reset, Input, Result) nhưng mở rộng kích thước khối, phép quay bit, hàm nén và số vòng lặp theo yêu cầu của SHA-512._


## 1. Phân tích cấu trúc SHA-1 đã cho.

### 1.1 Cấu trúc SHA-1 
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
