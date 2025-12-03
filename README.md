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
Thuật toán SHA-1 được xây dựng theo mô hình Merkle–Damgård với các hàm chính:

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


